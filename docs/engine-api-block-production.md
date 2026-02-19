# Engine API V3 블록 생산 설계서 (py-ethclient)

## 1. 목적

`/Users/theo/workspace_tokamak/tokamak-thanos-geth`의 실제 구현을 기준으로,
`py-ethclient`의 Engine API V3(`engine_forkchoiceUpdatedV3`, `engine_getPayloadV3`, `engine_newPayloadV3`)를
OP Stack 연동 가능 수준으로 구현하기 위한 설계를 정의한다.

핵심 목표:
- 더미 payload 반환 제거
- `forkchoice -> getPayload -> newPayload -> forkchoice` 루프를 geth와 동등한 계약으로 동작
- 오류 코드/상태(`VALID/INVALID/SYNCING/ACCEPTED`)를 표준에 맞춰 반환

---

## 2. 기준 구현(Thanos Geth) 요약

기준 소스:
- `tokamak-thanos-geth/eth/catalyst/api.go`
- `tokamak-thanos-geth/beacon/engine/types.go`
- `tokamak-thanos-geth/beacon/engine/errors.go`
- `tokamak-thanos-geth/miner/payload_building.go`
- `tokamak-thanos-geth/eth/catalyst/queue.go`

### 2.1 RPC 표면

지원 메서드(핵심):
- `engine_forkchoiceUpdatedV1/V2/V3`
- `engine_getPayloadV1/V2/V3`
- `engine_newPayloadV1/V2/V3`
- `engine_getPayloadBodiesByHashV1`
- `engine_getPayloadBodiesByRangeV1`
- `engine_getClientVersionV1`

### 2.2 V3 제약(입력 검증)

`ForkchoiceUpdatedV3`:
- `payloadAttributes != nil`일 때
- `withdrawals` 필수
- `parentBeaconBlockRoot`(`BeaconRoot`) 필수
- timestamp 기준 포크가 Cancun이 아니면 `UnsupportedFork(-38005)`

`NewPayloadV3`:
- `withdrawals`, `blobGasUsed`, `excessBlobGas` 필수
- `expectedBlobVersionedHashes` 필수(빈 배열 허용, nil 불가)
- `parentBeaconBlockRoot` 필수
- Cancun payload가 아니면 `UnsupportedFork(-38005)`

### 2.3 Forkchoice 공통 동작

`forkchoiceUpdated(...)` 공통 로직:
1. `headBlockHash == 0x00..00`이면 `INVALID`
2. head가 로컬에 없으면
- 과거 `newPayload`로 받은 `remoteBlocks` 헤더 확인
- 있으면 beacon sync 트리거 후 `SYNCING`
- 없으면 `SYNCING`
3. head가 로컬에 있으면 canonical 전환/검증
4. safe/finalized hash가 canonical이 아니면 `InvalidForkChoiceState(-38002)`
5. payloadAttributes가 있으면 payload 빌드 시작 후 `payloadId` 반환

### 2.4 Payload ID 생성

`miner.BuildPayloadArgs.Id()`:
- `sha256(parent, timestamp, prevRandao, feeRecipient, withdrawals, beaconRoot, op-fields)`
- 결과 8바이트를 payload id로 사용
- 첫 바이트는 payload version(V1/V2/V3)

OP 확장 필드도 ID에 반영:
- `noTxPool`
- `transactions`(tx hash 목록)
- `gasLimit`

### 2.5 Payload 큐

`payloadQueue`:
- 최근 payload 최대 10개 추적
- 동일 payload id 중복 빌드 방지
- `getPayload` 시 id 조회 후 envelope 반환

`headerQueue(remoteBlocks)`:
- `newPayload`는 받았으나 아직 import 못 한 헤더 최대 96개 추적

### 2.6 NewPayload 공통 처리

`newPayload(...)` 핵심:
1. `ExecutableDataToBlock`로 구문/일관성 검증
- `extraData <= 32`
- `logsBloom == 256 bytes`
- `baseFeePerGas` 범위
- tx의 blob hashes와 `versionedHashes` 일치
2. 중복 block hash면 `VALID` 반환
3. 부모 없으면 즉시 reject하지 않고 `delayPayloadImport -> SYNCING`
4. snap sync 중이면 import 지연(`SYNCING`)
5. 상태 준비되면 block import 후 `VALID`

### 2.7 표준 오류 코드

- `-38001`: Unknown payload
- `-38002`: Invalid forkchoice state
- `-38003`: Invalid payload attributes
- `-38004`: Too large request
- `-38005`: Unsupported fork
- `-32602`: Invalid params

---

## 3. py-ethclient 현재 갭

대상 파일: `ethclient/rpc/engine_api.py`

현재 상태:
- `engine_getPayloadV3`: 더미 payload 반환 (`stateRoot/receiptsRoot/blockHash=0x00..00`)
- `engine_newPayloadV3`: 기본 실행 경로는 있으나 V3 필수 필드/포크 제약 검증 불충분
- `engine_forkchoiceUpdatedV3`: geth 수준의 forkchoice 상태 검증/동기화 전이 로직 미흡
- payload id 생성이 비결정적(`python hash`)이며 프로세스/재시작 간 안정성 없음

---

## 4. 구현 설계

## 4.1 설계 원칙

- geth 계약 우선: 메서드별 성공/실패/상태 전이를 geth와 동일하게 맞춘다.
- 타입 안전: hex/bytes/int 변환 및 필수 필드 검증을 명시적으로 분리한다.
- 단계적 적용: 먼저 V3 동작 일치, 이후 최적화(백그라운드 빌드/큐 eviction) 적용.

## 4.2 모듈 구조

신규 모듈 권장:
- `ethclient/rpc/engine_types.py`
- Engine API request/response dataclass + strict parser

신규/확장 컴포넌트:
- `PayloadBuilder` (엔진 API 전용 block assemble)
- `PayloadQueue` (max 10)
- `RemoteHeaderQueue` (max 96)
- `InvalidAncestorCache` (invalid 블록 재참조 처리)

기존 모듈 활용:
- `ethclient/blockchain/chain.py::validate_and_execute_block`
- `ethclient/storage/store.py`
- `ethclient/blockchain/fork_choice.py`

## 4.3 메서드별 상세 설계

### A. `engine_forkchoiceUpdatedV3`

1. 입력 검증
- `headBlockHash` zero hash 금지
- `payloadAttributes`가 있으면
  - `withdrawals` 필수
  - `parentBeaconBlockRoot` 필수
  - timestamp가 Cancun이 아니면 `-38005`

2. head 처리
- 로컬에 head 존재:
  - canonical head 설정
  - safe/finalized가 canonical chain 상에 있는지 검증
  - 실패 시 `-38002`
- 로컬에 head 부재:
  - `remote_headers` 조회
  - 있으면 sync 확장 시도 후 `SYNCING`
  - 없으면 `SYNCING`

3. payloadAttributes 존재 시 payload 생성 시작
- deterministic payload id 생성(geth 규칙)
- 동일 id가 queue에 있으면 재사용
- 없으면 payload 빌드 등록
- `payloadId` 반환

응답:
- 성공: `payloadStatus.status=VALID`
- 동기화 필요: `SYNCING`
- 실패: 엔진 오류 코드

### B. `engine_getPayloadV3`

1. payload id 조회
- 없으면 `UnknownPayload(-38001)`

2. payload envelope 반환
- `executionPayload`: 실제 계산된 값
  - `stateRoot`, `receiptsRoot`, `logsBloom`, `gasUsed`, `blockHash`가 더미가 아니어야 함
- `blockValue`: `0x0`(초기 구현)
- `blobsBundle`: L2 정책에 따라 빈 배열(필드는 유지)
- `shouldOverrideBuilder`: `false`

3. V3 필드 포함
- `withdrawals`, `blobGasUsed`, `excessBlobGas`, `parentBeaconBlockRoot`

### C. `engine_newPayloadV3`

1. 사전 검증(geth 동등)
- payload 내부: `withdrawals`, `blobGasUsed`, `excessBlobGas` 필수
- 파라미터: `expectedBlobVersionedHashes` nil 금지
- 파라미터: `parentBeaconBlockRoot` nil 금지
- Cancun payload 여부 검증

2. 블록 디코드/검증
- tx 디코드
- blob hash와 expected hash 일치 검증
- `validate_and_execute_block` 호출

3. 상태 반환
- 이미 알고 있는 block hash면 `VALID`
- 부모/상태 부족 시 지연 수용(`SYNCING` 또는 `ACCEPTED` 정책 선택)
- 실행 실패 시 `INVALID` + `validationError`
- 성공 import 시 `VALID + latestValidHash`

### D. payload id 알고리즘(필수)

`python hash` 제거, 아래로 교체:
- `sha256` 기반 8바이트
- 포함 필드 순서:
  - parentHash
  - timestamp
  - prevRandao
  - feeRecipient
  - withdrawals(정규화 직렬화)
  - parentBeaconBlockRoot(optional)
  - `noTxPool`, tx hashes, `gasLimit`(있을 때)
- 첫 바이트에 version 삽입

## 4.4 빌더 동작(초기 구현)

초기 구현은 동기식 빌드 허용:
- `forkchoiceUpdatedV3`에서 payload 생성 즉시 block assemble + execute
- 결과를 queue에 저장

2단계 개선:
- geth처럼 백그라운드 업데이트(수익 최적화) 추가
- `waitFull`류 동기화 프리미티브 도입

## 4.5 데이터 구조 제안

```text
pending_payloads: dict[payload_id, PayloadEnvelope]
remote_headers: deque[(hash, header)]          # max 96
payload_queue: deque[(payload_id, envelope)]   # max 10
invalid_ancestors: dict[head_hash, bad_header] # hit-based eviction
```

---

## 5. 구현 순서 (권장)

1. 타입/검증 계층 도입 (`engine_types.py`)
2. deterministic payload id + payload queue 구현
3. `forkchoiceUpdatedV3` 상태 전이/검증 구현
4. `getPayloadV3` 실제 payload 반환 구현
5. `newPayloadV3` 필수 필드/포크/blob hash 검증 구현
6. remote header 지연 import + invalid ancestor 캐시 적용
7. V1/V2와 공통 경로 정리(중복 제거)

---

## 6. 테스트 계획

단위 테스트:
- `tests/test_rpc.py`
- `tests/test_blockchain.py`

필수 케이스:
1. `forkchoiceUpdatedV3`:
- missing withdrawals -> `-32602`
- missing parentBeaconBlockRoot -> `-32602`
- non-Cancun timestamp -> `-38005`
2. `getPayloadV3`:
- unknown payload id -> `-38001`
- 정상 payload의 `blockHash/stateRoot/receiptsRoot` non-zero
3. `newPayloadV3`:
- missing blob fields -> `-32602`
- expected blob hashes 불일치 -> `INVALID`
- known block 재전송 -> `VALID`
- parent unknown -> `SYNCING`
4. 통합:
- `forkchoiceUpdatedV3 -> getPayloadV3 -> newPayloadV3 -> forkchoiceUpdatedV3` 성공 루프

운영 검증:
- op-node 연동 시 payload invalid 재시도 루프가 사라지는지 확인
- `eth_blockNumber`가 슬롯 진행에 따라 단조 증가하는지 확인

---

## 7. 비범위(이번 설계 1차)

- OP deposit tx(type `0x7E`) 실행 semantics 확장
- L1 fee vault 정산 로직
- builder 수익 최적화/다중 후보 payload 경쟁

위 항목은 V3 계약 동작이 안정화된 뒤 후속 설계서로 분리한다.

---

## 8. 참고

- `tokamak-thanos-geth/eth/catalyst/api.go`
- `tokamak-thanos-geth/beacon/engine/types.go`
- `tokamak-thanos-geth/beacon/engine/errors.go`
- `tokamak-thanos-geth/miner/payload_building.go`
- `tokamak-thanos-geth/eth/catalyst/queue.go`
- Engine API spec: <https://github.com/ethereum/execution-apis/tree/main/src/engine>
