---
description: "P2P 네트워킹 디버깅 — RLPx, devp2p, 동기화 문제 진단"
allowed-tools: ["Read", "Glob", "Grep", "Edit", "Write", "Bash", "Task"]
argument-hint: "P2P 에러 메시지나 증상"
user-invocable: true
---

# P2P 네트워킹 디버깅 스킬

RLPx 연결, devp2p 핸드셰이크, 동기화 문제를 진단하고 해결하는 전문 스킬.

## 핵심 파일 참조

| 파일 | 역할 |
|------|------|
| `ethclient/networking/rlpx/transport.py` | RLPx 연결, ECIES 핸드셰이크 |
| `ethclient/networking/rlpx/ecies.py` | ECIES 암호화/복호화 |
| `ethclient/networking/rlpx/protocol.py` | devp2p 프로토콜 메시지 |
| `ethclient/networking/eth/protocol.py` | eth/68 메시지 인코딩/디코딩 |
| `ethclient/networking/snap/protocol.py` | snap/1 메시지 |
| `ethclient/networking/discv4/` | Discovery v4 (Kademlia) |
| `ethclient/networking/sync/full_sync.py` | Full sync 전략 |
| `ethclient/networking/sync/snap_sync.py` | Snap sync 전략 |

## 디버깅 체크리스트

### 연결 실패

- [ ] **TCP 연결**: 포트 30303 접근 가능한지 확인 (방화벽, NAT)
- [ ] **ECIES 핸드셰이크**: auth-msg → auth-ack → frame cipher 초기화
- [ ] **Hello 메시지**: devp2p 버전, 클라이언트 ID, 캡 목록 교환
- [ ] **Snappy 압축**: Geth v1.17.0+ 연결 시 `conn.use_snappy = True` 필수
- [ ] **프로토콜 캡**: `["eth/68", "snap/1"]` 매칭 확인

### TOO_MANY_PEERS (0x04)

가장 빈번한 연결 거부 사유:

```python
from ethclient.networking.rlpx.protocol import DisconnectReason
# DisconnectReason.TOO_MANY_PEERS == 0x04
```

**대응 전략:**
1. **Discovery v4 사용**: 부트노드 직접 연결 대신 discv4로 여러 노드 탐색
2. **Sepolia 사용**: Mainnet 부트노드보다 Sepolia가 연결 성공률 높음
3. **재시도 로직**: 5-10초 간격 재시도, 최대 10회
4. **다수 부트노드**: 여러 부트노드에 동시 시도

```python
# Sepolia 부트노드 (EF DevOps, 연결 성공률 높음)
SEPOLIA_BOOTNODES = [
    ("138.197.51.181", 30303),
    ("146.190.1.103", 30303),
]
```

### 핸드셰이크 실패

**ECIES 핸드셰이크 플로우:**
```
Initiator                    Responder
    |                            |
    |--- auth-msg (ECIES) ------>|  (pubkey + nonce + signature)
    |                            |
    |<--- auth-ack (ECIES) ------|  (pubkey + nonce)
    |                            |
    |--- [frame cipher init] --->|  (AES-CTR + MAC secrets derived)
    |                            |
    |--- Hello (p2p) ----------->|  (version, client, caps, port, id)
    |<--- Hello (p2p) ----------|
    |                            |
    |--- Status (eth/68) ------->|  (network, genesis, head, forkid)
    |<--- Status (eth/68) ------|
```

**일반적 실패 원인:**
- `MAC mismatch`: ECIES 키 파생 오류. 로컬 키 확인
- `Unexpected message`: Hello 전에 다른 메시지 수신. 프레임 파싱 확인
- `Protocol version mismatch`: devp2p v5 필수
- `Network ID mismatch`: Mainnet=1, Sepolia=11155111
- `Genesis hash mismatch`: 네트워크에 맞는 genesis 사용

### Snappy 압축 문제

```python
# Geth v1.17.0+에서 필수
conn.use_snappy = True

# 증상: 메시지 디코딩 실패, RLP 파싱 에러
# 원인: snappy 압축/해제 누락
# 해결: python-snappy 패키지 설치 확인
#   pip install python-snappy
```

## RLPx 연결 상세

### ECIES (Elliptic Curve Integrated Encryption Scheme)

```python
from ethclient.networking.rlpx.ecies import ecies_encrypt, ecies_decrypt

# auth-msg 생성
# 1. 임시 키쌍 생성
# 2. 정적 키로 서명
# 3. ECIES로 암호화 (상대 공개키 사용)
# 4. 전송

# auth-ack 처리
# 1. ECIES로 복호화 (내 비밀키 사용)
# 2. 공유 비밀 파생 (ECDH)
# 3. frame cipher 키 생성 (KDF)
```

### 프레임 구조

```
[header (16B, AES-CTR encrypted)]
[header-mac (16B)]
[frame (variable, AES-CTR encrypted, padded to 16B)]
[frame-mac (16B)]

header: [frame-size (3B big-endian)] [header-data (13B)]
```

### devp2p Hello 메시지

```python
# p2p 메시지 코드
HELLO = 0x00
DISCONNECT = 0x01
PING = 0x02
PONG = 0x03

# Hello 필드:
# version: 5
# client_id: "py-ethclient/1.0"
# caps: [["eth", 68], ["snap", 1]]
# listen_port: 30303
# node_id: 64-byte public key
```

## Disconnect 사유

```python
class DisconnectReason(IntEnum):
    REQUESTED = 0x00           # 정상 종료
    TCP_ERROR = 0x01           # TCP 에러
    BREACH_OF_PROTOCOL = 0x02  # 프로토콜 위반
    USELESS_PEER = 0x03        # 쓸모없는 피어
    TOO_MANY_PEERS = 0x04      # 피어 수 초과 ★
    ALREADY_CONNECTED = 0x05   # 이미 연결됨
    INCOMPATIBLE_VERSION = 0x06 # 호환 불가 버전
    INVALID_IDENTITY = 0x07    # 잘못된 ID
    CLIENT_QUITTING = 0x08     # 클라이언트 종료
    UNEXPECTED_IDENTITY = 0x09 # 예상치 못한 ID
    CONNECTED_TO_SELF = 0x0a   # 자기 자신 연결
    TIMEOUT = 0x0b             # 타임아웃
    SUBPROTOCOL_ERROR = 0x10   # 서브프로토콜 에러
```

## eth/68 Status 디버깅

```python
# Status 메시지 교환 후 검증 항목:
# 1. networkId 일치 (1=mainnet, 11155111=sepolia)
# 2. genesisHash 일치
# 3. forkID 호환성 (fork_hash + fork_next)

# ForkID 계산:
# fork_hash = CRC32(genesis_hash + fork_block_numbers)
# fork_next = 다음 예정된 하드포크 블록

# 불일치 시: DISCONNECT(SUBPROTOCOL_ERROR)
```

## Discovery v4 디버깅

### 패킷 구조
```
[hash (32B)] [signature (65B)] [type (1B)] [data (RLP)]
hash = keccak256(signature || type || data)
```

### 일반적 문제

1. **UDP 미수신**: 포트 30303/UDP 방화벽 확인
2. **Ping 미응답**: NAT 뒤에서는 외부 IP 올바르게 설정
3. **라우팅 테이블 비어있음**: 부트노드에 먼저 Ping 전송 필요
4. **시간 만료**: expiration 필드가 미래 시점이어야 함 (현재 + 20초 권장)

### 부트노드 연결

```python
from ethclient.networking.discv4.routing import Node, RoutingTable

# 부트노드를 테이블에 추가
boot = Node(id=boot_pubkey, ip="138.197.51.181", udp_port=30303, tcp_port=30303)
table.add_node(boot)

# FindNode로 주변 노드 탐색
closest = table.closest_nodes(target_id=my_node_id, count=16)
```

## Sync 디버깅

### Full Sync 문제

| 증상 | 원인 | 해결 |
|------|------|------|
| 헤더 다운로드 멈춤 | 피어 응답 없음 | 다른 피어 시도, 타임아웃 조정 |
| 바디 누락 | 피어가 데이터 없음 | 여러 피어에 분산 요청 |
| EVM 실행 실패 | 상태 불일치 | 이전 블록부터 재실행 |
| 느린 동기화 | 블록별 순차 처리 | snap sync 사용 |

### Snap Sync 문제

| 증상 | 원인 | 해결 |
|------|------|------|
| AccountRange 빈 응답 | 피봇 블록 너무 오래됨 | 최신 피봇으로 재시작 |
| proof 검증 실패 | 상태 변경됨 | 피봇 블록 갱신 |
| 바이트코드 누락 | 해시 불일치 | 다른 피어에 재요청 |
| 타임아웃 | 피어 느림 | adaptive timeout 사용 |

```python
# Snap sync 타임아웃 상수
SNAP_TIMEOUT = 15  # 초 (기본)
PEER_WAIT_TIMEOUT = 30  # 피어 대기
# adaptive_timeout: 느린 피어에 대해 자동 증가
```

## 로깅 설정

```python
import logging

# P2P 디버깅 로그
logging.getLogger("ethclient.networking.rlpx").setLevel(logging.DEBUG)
logging.getLogger("ethclient.networking.eth").setLevel(logging.DEBUG)
logging.getLogger("ethclient.networking.discv4").setLevel(logging.DEBUG)
logging.getLogger("ethclient.networking.sync").setLevel(logging.DEBUG)
```

## 네트워크별 설정

| 항목 | Mainnet | Sepolia |
|------|---------|---------|
| Network ID | 1 | 11155111 |
| Chain ID | 1 | 11155111 |
| 부트노드 성공률 | 낮음 (TOO_MANY_PEERS) | 높음 |
| eth 프로토콜 | eth/68, eth/69 | eth/68, eth/69 |
| snap 프로토콜 | snap/1 | snap/1 |
| Snappy | 필수 | 필수 |

## 주의사항

1. **Snappy 필수**: 2024년 이후 모든 Geth 노드에서 snappy 압축 필수
2. **Mainnet 연결 어려움**: TOO_MANY_PEERS가 대부분. discv4로 우회
3. **ECIES 키 관리**: 노드 키는 secp256k1. 64바이트 비압축 공개키 (0x04 접두사 제외)
4. **프레임 크기**: 최대 16MB. 큰 응답은 분할 필요
5. **ping/pong 주기**: 15초 간격 권장. 미응답 시 연결 종료
6. **ForkID 검증**: 호환 불가 포크면 즉시 disconnect
