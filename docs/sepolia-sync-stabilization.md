# Sepolia Sync Stabilization Report

Date: 2026-02-19
Scope: `snap sync`/`full sync` 불안정(피어 churn, pause 반복, timeout 후 정체) 정상화 과정 정리

## 1) 관측된 주요 문제

- snap 동기화 중 `paused before account completion/timeout` 반복
- full 동기화에서 헤더 timeout을 완료로 오판해 조기 종료
- 피어 연결/해제 churn이 심해 진행률이 흔들림
- 재시작/재연결 시 진행 상황 복원 불충분
- 로그에서 handshake 실패 원인 파악이 어려움

## 2) 적용된 패치 요약

### A. Full sync 신뢰성 강화

파일: `ethclient/networking/sync/full_sync.py`

- 헤더 timeout을 `[]`(정상 빈 응답)가 아닌 `None`(실패)로 구분
- 헤더 실패 누적 시 재시도 backoff + peer failover 도입
- 동기화 중 연결된 피어들의 head를 반영해 `target_block` 갱신
- 고정 단일 피어 의존 구조를 완화

효과:
- timeout 상황에서 "완료"로 빠지는 문제 감소
- 장시간 연결 불안정에서도 full sync 진행 지속성 개선

### B. Snap sync 품질 제어 및 복원력 강화

파일: `ethclient/networking/sync/snap_sync.py`

- peer health 모델 추가
- timeout/proof-failure 누적 시 cooldown/ban 적용
- RTT 기반 adaptive timeout 적용
- 요청마다 live peer pool에서 round-robin 선택
- stale snap peer 필터링(목표 블록 대비 과도하게 뒤처진 피어 제외)
- `AccountRange` empty 응답에 대해 즉시 완료 처리하지 않고 bounded retry
- storage/bytecode/trie phase 병렬화(실패 batch 재큐잉)
- 진행 상태 persist/resume 강화(target/cursor/counter/queue 길이 저장)

효과:
- churn 환경에서 snap pause 빈도 감소
- 저품질 피어 영향 격리
- 중단 후 재개 시 진행률 보존 개선

### C. P2P 다이얼 churn 억제

파일: `ethclient/networking/server.py`, `ethclient/main.py`

- 다이얼 후보 필터 강화
- bootnode 우선, 최근 pong 확인 노드 우선
- 틱당 최대 다이얼 수 제한
- disconnect된 peer에 dial cooldown 적용(즉시 재다이얼 방지)
- `--bootnode-only` 옵션을 CLI로 노출

효과:
- 무분별한 다이얼 폭주 완화
- handshake 실패/재접속 스파이크 감소

### D. Handshake 디버깅 가시성 강화

파일: `ethclient/networking/rlpx/connection.py`, `ethclient/networking/server.py`

- `last_handshake_error` 저장
- RLPx 실패 로그에 예외 타입/원인 직접 출력

효과:
- `TimeoutError`, `IncompleteReadError`, `ConnectionResetError` 등 원인 분리 가능

### E. 런북 업데이트

파일: `AGENTS.md`

- Sepolia 실행 커맨드/모니터링 가이드 보강
- snap/full 권장 실행 예시 정리

## 3) 실험 중 도입 후 제거한 로직

- "동일 paused cursor 반복 시 full 강제 전환" 로직은 제거함
- 제거 이유: 단기 우회에는 유효했지만 snap 진행 중 정상 회복 경로를 과도하게 끊음
- 원인 완화는 강제 모드 전환보다 peer 품질 제어/다이얼 안정화가 더 근본적

## 4) 회귀 검증

- `pytest tests/test_p2p.py tests/test_snap_sync.py -q`
- 결과: 통과(최근 실행 기준 93 passed)

추가 보강 테스트:

- full sync: timeout/failover 시나리오
- snap sync: peer refresh, health/ban, stale peer filtering, progress restore

## 5) 운영 관측 결과

- snap account cursor가 지속 증가하며 상태 동기화가 실제로 전진
- `peerCount`는 시점별 변동이 있으나 `eth_syncing=true` 상태에서 진행 계속
- 로컬 `0x9c0` 블록 헤더는 Sepolia 퍼블릭 RPC와 핵심 필드(hash/root 등) 일치 확인

## 6) 남은 리스크

- 일부 peer가 여전히 잦은 disconnect/timeout을 유발
- `Account range proof unverifiable` 로그가 빈번(현재 relaxed checks 허용)

운영 권장:

- 장시간 모니터링 시 `account cursor` 증가 추세를 1차 정상성 지표로 사용
- 필요 시 strict proof 정책은 별도 검증 환경에서 단계적 활성화
