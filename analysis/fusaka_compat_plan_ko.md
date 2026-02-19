# Fusaka 하드포크 호환 작업 계획서 (py-ethclient)

## 1. 목적

`py-ethclient`를 Fusaka 하드포크 규격에 맞게 동작시키고, 메인넷/테스트넷에서 상호운용 가능한 수준으로 검증한다.

## 2. 현재 상태 요약

- 포크 시각 관련 필드(`osaka_time`, `extra_fork_times`)는 일부 존재
- 그러나 Fusaka 핵심 EIP 다수 미반영
- 특히 `eth/69`, ReceiptsV2, 신규 EVM/프리컴파일, 가스/블록 제한 규칙이 부재

## 3. 범위 (Fusaka 대응 대상)

- 네트워킹
  - EIP-7642: `eth/69` 지원
  - EIP-7910: `GetReceiptsV2`, `ReceiptsV2`
- 실행 계층(EVM/트랜잭션/프리컴파일)
  - EIP-7939: `CLZ` opcode
  - EIP-7951: `P256VERIFY` precompile
  - EIP-7823: SetCode tx 타입 업데이트 반영
- 검증/규칙
  - EIP-7934: `MAX_RLP_BLOCK_SIZE`
  - EIP-7825: `MAX_TX_GAS`
  - EIP-7883: MODEXP 입력 상한
  - EIP-7892, EIP-7918: blob fee/스케줄 파라미터 반영
- 설정/포크 활성화
  - ChainConfig 및 포크 전환 타이밍/파라미터 정합성 확보

## 4. 구현 단계

### Phase 1. 스펙 고정 및 설계

- [ ] Fusaka 대상 EIP별 필수 요구사항 표 정리 (입력/출력/예외/활성화 조건)
- [ ] 기존 모듈 매핑 문서화 (`networking`, `vm`, `blockchain`, `common/config`)
- [ ] 하위호환 정책 정의 (`eth/68` fallback 여부, 네트워크별 활성화 시점)

산출물:
- `analysis/fusaka_spec_matrix_ko.md` (EIP별 구현 체크 매트릭스)

### Phase 2. 네트워킹 레이어

- [ ] `ETH_VERSION`을 `69` 기반으로 확장
- [ ] `Status` 인코딩/디코딩을 `eth/69` 규격에 맞게 분기 처리
- [ ] `GetReceiptsV2`, `ReceiptsV2` 메시지 타입 추가
- [ ] 프로토콜 협상(`protocol_registry`) 테스트 보강
- [ ] `eth/68` 피어와의 상호운용 fallback 동작 점검

대상 파일(예상):
- `ethclient/networking/eth/protocol.py`
- `ethclient/networking/eth/messages.py`
- `ethclient/networking/server.py`
- `ethclient/networking/protocol_registry.py`
- `tests/test_p2p.py`
- `tests/test_protocol_registry.py`

### Phase 3. EVM/트랜잭션/프리컴파일

- [ ] `CLZ` opcode 추가 (디코드 테이블, 실행, 가스)
- [ ] `P256VERIFY` precompile 구현 및 등록
- [ ] SetCode tx(EIP-7823) 필드/서명/검증 규칙 업데이트
- [ ] MODEXP 입력 상한(EIP-7883) 반영

대상 파일(예상):
- `ethclient/vm/opcodes.py`
- `ethclient/vm/evm.py`
- `ethclient/vm/precompiles.py`
- `ethclient/common/types.py`
- `ethclient/blockchain/chain.py`
- `tests/test_evm.py`
- `tests/test_blockchain.py`

### Phase 4. 블록/가스/Blob 규칙

- [ ] `MAX_RLP_BLOCK_SIZE` 검증 로직 추가
- [ ] `MAX_TX_GAS` 검증 로직 추가
- [ ] blob schedule(EIP-7892) 및 base fee fraction(EIP-7918) 반영
- [ ] 헤더/블록 검증 파이프라인에 포크 활성 시점 분기 적용

대상 파일(예상):
- `ethclient/blockchain/chain.py`
- `ethclient/common/config.py`
- `ethclient/common/types.py`
- `tests/test_blockchain.py`
- `tests/test_rpc.py`

### Phase 5. 검증 및 회귀 테스트

- [ ] 단위 테스트: 변경 모듈 전부 커버
- [ ] 통합 테스트: sync + RPC 경로 회귀
- [ ] 라이브 네트워크 검증: `test_full_sync.py` 시나리오 갱신
- [ ] 성능/안정성 점검: 메시지 파싱 및 precompile 경계 입력

필수 실행:
- [ ] `python3 -m pytest`
- [ ] `python3 test_full_sync.py`

## 5. 완료 기준 (Definition of Done)

- [ ] Fusaka 대상 EIP 항목이 코드/테스트에서 모두 매핑됨
- [ ] `eth/69` 피어와 핸드셰이크 및 주요 메시지 송수신 성공
- [ ] 신규 opcode/precompile 공식 벡터 또는 동등 수준 벡터 통과
- [ ] 블록/트랜잭션 제한 규칙 위반 케이스가 정확히 거절됨
- [ ] 전체 테스트 통과 + 라이브 검증 로그 확보

## 6. 리스크 및 대응

- 네트워크 상호운용성 리스크 (`eth/68`/`eth/69` 혼재)
  - 대응: capability negotiation 기반 분기 + 통합 테스트 2세트 운영
- 암호학 프리컴파일 구현 리스크 (P-256 검증 정확도)
  - 대응: 표준 테스트 벡터 + 실패 케이스 강화
- 포크 시점/파라미터 리스크
  - 대응: `ChainConfig` 단일 소스화 + 포크별 스냅샷 테스트

## 7. 우선순위 권장

1. 네트워킹(`eth/69`, ReceiptsV2)
2. 검증 규칙(`MAX_RLP_BLOCK_SIZE`, `MAX_TX_GAS`)
3. EVM/프리컴파일(`CLZ`, `P256VERIFY`)
4. Blob 파라미터(EIP-7892, EIP-7918)

## 8. 작업 일정 예시

- Day 1-2: Phase 1-2
- Day 3-4: Phase 3
- Day 5: Phase 4
- Day 6: Phase 5 및 문서/로그 정리

