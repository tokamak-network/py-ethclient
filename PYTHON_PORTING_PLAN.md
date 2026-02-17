# Python Single Sequencer L1 Porting Plan

## 개요

이 문서는 Rust로 작성된 ethrex 이더리움 노드를 분석하여, **싱글 시퀀서 환경**의 초경량 이더리움 L1을 Python으로 구현하기 위한 포팅 계획입니다.

### 싱글 시퀀서 환경이란?

싱글 시퀀서는 단일 운영자가 블록 생성 권한을 독점하는 환경입니다:

- **No Consensus**: 컨센서스 클라이언트 불필요
- **No P2P**: 외부 피어와 통신하지 않음
- **No Reorgs**: 체인 리오그 없음 (일직선 체인)
- **Centralized Block Production**: 지정된 시퀀서만 블록 생성

이로 인해 다음 컴포넌트들이 **제외**됩니다:

| 제외 컴포넌트 | 이유 |
|-------------|------|
| Engine API | 컨센서스 클라이언트 없음 |
| Fork Choice | 리오그 없음, 일직선 체인 |
| P2P (DiscV4, RLPx, eth/68) | 외부 피어 불필요 |
| Block Sync | 외부에서 블록 수신 불필요 |
| Tx Broadcasting | 트랜잭션 전파 불필요 |
| Mempool (선택적) | 자체 생성 tx만 처리 |

---

## 1. Python 라이브러리 분석 및 선정

이미 검증된 Python 라이브러리를 적극 활용하여 개발 시간을 단축하고 안정성을 확보합니다.

### 1.1 EVM (Ethereum Virtual Machine)

> **⚠️ 핵심 원칙: 라이브러리를 직접 사용하라**
> 
> "멍청하고 작은 코드"가 나중에 개선하기 더 좋습니다. EVM은 직접 구현하지 말고 `py-evm`을 그대로 사용하세요.

| 라이브러리 | 상태 | 장점 | 단점 | 추천 |
|-----------|------|------|------|------|
| **py-evm** | Archived (2025.05) | Ethereum 재단 공식, 완전한 EVM, Prague까지 지원 | 더 이상 활성 개발 안함 | ⭐ **직접 사용** |
| **execution-specs (EELS)** | Active | 공식 스펙 참조 구현, 최신 포크 지원 | 학습용 참조, 프로덕션 미최적화 | 참조용 |

**선택: `py-evm` 직접 사용 (참조가 아님!)**

```python
# py-evm을 직접 import하여 사용
pip install py-evm  # 0.12.1b1 (마지막 버전)

from eth.vm.forks.shanghai import ShanghaiVM
from eth.vm.forks.cancun import CancunVM
from eth.vm.message import Message
from eth.vm.computation import BaseComputation
from eth import constants

# 우리는 VM 어댑터만 작성하면 됨 (~300 LOC)
class SequencerVM:
    def __init__(self, chain_config):
        self.vm_class = CancunVM  # 포크에 따라 선택
    
    def execute_transaction(self, tx, state):
        # py-evm의 VM을 사용하여 트랜잭션 실행
        message = Message(...)  # tx에서 변환
        computation = self.vm_class.execute(message, state)
        return computation
```

**절감 효과: ~3,000 LOC → ~300 LOC**

**활용 방안:**
- EVM 실행: py-evm VM 직접 호출
- State 관리: py-evm의 State 클래스 활용
- 필요시에만 포크별 차이 처리

### 1.2 RLP (Recursive Length Prefix)

| 라이브러리 | 다운로드/월 | 특징 | 추천 |
|-----------|------------|------|------|
| **ethereum-rlp** | 13,000+ | Ethereum 재단 공식, EELS 연동, 데이터클래스 지원 | ⭐ **강력 추천** |
| **rlp** | 높음 | eth-rlp 의존성, 오래된 API | 대안 |
| **eth-rlp** | 높음 | rlp + Ethereum 객체 정의 | ethereum-rlp와 함께 사용 |
| simple-rlp | 낮음 | 심플, 빠름 | 소규모 프로젝트용 |

**선택: `ethereum-rlp` (공식 라이브러리)**

```python
# ethereum-rlp: EELS와 호환되는 최신 RLP 라이브러리
pip install ethereum-rlp

# 사용 예시
from ethereum_rlp import encode, decode_to
from dataclasses import dataclass
from ethereum_types.numeric import Uint

@dataclass
class Transaction:
    nonce: Uint
    gas_price: Uint
    gas: Uint
    to: bytes
    value: Uint
    data: bytes
    
encoded = encode(transaction)
decoded = decode_to(Transaction, encoded)
```

### 1.3 Cryptography (Keccak-256, ECDSA)

| 라이브러리 | 특징 | 성능 | 추천 |
|-----------|------|------|------|
| **coincurve** | libsecp256k1 바인딩, 10x+ 빠름 | ⚡ 최고 | ⭐ **강력 추천** |
| **py-ecc** | Ethereum 재단, 순수 Python | 느림 | 대안 (검증용) |
| python-secp256k1 | libsecp256k1 바인딩 | 빠름 | coincurve와 유사 |
| ecdsa | 순수 Python, 느림 | 느림 | 학습용만 |
| pycryptodome | SHA3/Keccak 지원 | 빠름 | 해시용으로 함께 사용 |

**선택: `coincurve` + `pycryptodome`**

```python
# ECDSA 서명/검증 (coincurve)
pip install coincurve

from coincurve import PrivateKey, PublicKey

# 키 생성
private_key = PrivateKey()
public_key = private_key.public_key

# 서명
signature = private_key.sign(message_hash)

# 검증
public_key.verify(signature, message_hash)

# 주소 파생
address = keccak256(public_key.format(compressed=False)[1:])[12:]

# Keccak-256 (pycryptodome)
pip install pycryptodome

from Crypto.Hash import keccak
def keccak256(data: bytes) -> bytes:
    k = keccak.new(digest_bits=256)
    k.update(data)
    return k.digest()
```

### 1.4 Merkle Patricia Trie

> **⚠️ 핵심 원칙: 확장하지 말고 그대로 써라**
> 
> "필요시 확장"은 나중에 실제로 필요할 때 하세요. 처음부터 확장하지 마세요.

| 라이브러리 | 특징 | 상태 | 추천 |
|-----------|------|------|------|
| **trie (py-trie)** | Ethereum 재단 공식, py-evm 연동 | Active | ⭐ **직접 사용** |

**선택: `trie` 직접 사용**

```python
# trie: Ethereum 재단 공식 MPT 구현 - 그대로 사용
pip install trie

from trie import HexaryTrie

# StateDB는 단순한 래퍼만 작성
class StateDB:
    """py-evm과 함께 작동하는 최소한의 래퍼"""
    
    def __init__(self, db: dict = None):
        self._trie = HexaryTrie(db or {})
    
    def get_account(self, address: bytes) -> Account:
        key = keccak256(address)
        data = self._trie.get(key)
        return Account.from_rlp(data) if data else Account.empty()
    
    def set_account(self, address: bytes, account: Account):
        key = keccak256(address)
        self._trie[key] = account.to_rlp()
    
    def root_hash(self) -> bytes:
        return self._trie.root_hash

# 끝. 확장은 나중에 실제로 필요할 때.
```

**절감 효과: ~300 LOC → ~50 LOC**

### 1.5 Types & Utilities

> **⚠️ 핵심 원칙: 타입은 라이브러리에서 가져오고 최소한만 정의**
> 
> ethereum-types와 eth-utils에서 이미 다 제공합니다.

| 라이브러리 | 목적 | 추천 |
|-----------|------|------|
| **ethereum-types** | EELS용 타입, U256, Address 등 | ⭐ **직접 사용** |
| **eth-utils** | 유틸리티 함수 (변환, 주소 검증 등) | 함께 사용 |

**선택: `ethereum-types` 직접 사용**

```python
# ethereum-types: 이미 다 정의되어 있음
pip install ethereum-types eth-utils

from ethereum_types.numeric import U256, Uint
from ethereum_types.bytes import Bytes20, Bytes32
from eth_utils import to_checksum_address, keccak

# 우리는 최소한의 래퍼만 정의
@dataclass
class Account:
    nonce: Uint
    balance: U256
    storage_root: Bytes32
    code_hash: Bytes32
    
    @classmethod
    def empty(cls) -> 'Account':
        return cls(nonce=Uint(0), balance=U256(0), 
                   storage_root=EMPTY_ROOT, code_hash=EMPTY_CODE_HASH)
    
    def to_rlp(self) -> bytes:
        return encode([self.nonce, self.balance, self.storage_root, self.code_hash])
    
    @classmethod
    def from_rlp(cls, data: bytes) -> 'Account':
        nonce, balance, storage_root, code_hash = decode(data)
        return cls(nonce, balance, storage_root, code_hash)
```

**절감 효과: ~500 LOC → ~150 LOC**

### 1.6 종합 라이브러리 의존성

> **⚠️ 핵심 원칙: 의존성을 최소화하라**
> 
> 불필요한 의존성은 복잡성을 증가시킵니다.

```toml
[project]
name = "sequencer"
version = "0.1.0"
dependencies = [
    # 핵심 EVM (직접 사용!)
    "py-evm>=0.12.0b1",              # EVM 실행 엔진
    
    # RLP Encoding (공식)
    "ethereum-rlp>=0.1.4",           # RLP 인코딩/디코딩
    
    # Cryptography (성능 중요)
    "coincurve>=21.0.0",             # secp256k1 (빠른 ECDSA)
    "pycryptodome>=3.20.0",          # Keccak256
    
    # Trie (공식 MPT)
    "trie>=3.1.0",                   # Merkle Patricia Trie
    
    # Types
    "ethereum-types>=0.1.0",         # 타입 정의
    "eth-utils>=5.0.0",              # 유틸리티
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0.0",
    "pytest-asyncio>=0.23.0",
    "hypothesis>=6.0.0",             # Property-based testing
    "mypy>=1.8.0",
    "ruff>=0.2.0",
]

# 나중에 필요할 때만 추가
production = [
    "aiosqlite>=0.19.0",             # Async SQLite (필요시)
]

# EELS 참조용 (선택적)
eels = [
    "ethereum>=5.0.0",               # Execution specs
]
```

### 1.7 라이브러리 활용 전략

> **⚠️ "직접 구현"에서 "직접 사용"으로 전환**

| 컴포넌트 | 기존 전략 | **새 전략** | 비고 |
|----------|----------|------------|------|
| **EVM** | py-evm 코드 참조 | **py-evm 직접 사용** | VM 어댑터만 작성 |
| **RLP** | ethereum-rlp 직접 사용 | ethereum-rlp 직접 사용 | 완전 활용 |
| **Crypto** | coincurve + pycryptodome 직접 사용 | coincurve + pycryptodome 직접 사용 | 완전 활용 |
| **Trie** | trie 라이브러리 기반, 필요시 확장 | **trie 직접 사용** | 확장하지 마세요 |
| **Types** | ethereum-types + 직접 정의 혼합 | **ethereum-types 직접 사용** | 최소 래퍼만 |
| **State** | 직접 구현 | **py-evm State 활용** | 어댑터만 작성 |
| **Storage** | 직접 구현 (SQLite) | **dict로 시작, 나중에 SQLite** | Phase 1은 dict

### 1.8 코드 재사용 vs 직접 구현

> **⚠️ 새로운 원칙: "직접 구현" 최소화**

```
재사용 (라이브러리 그대로 사용):
├── RLP Encoding          → ethereum-rlp (직접 사용)
├── Cryptography          → coincurve, pycryptodome (직접 사용)
├── Merkle Patricia Trie  → trie (직접 사용, 확장 금지)
├── Type Definitions      → ethereum-types (직접 사용)
├── Utilities             → eth-utils (직접 사용)
└── EVM Execution         → py-evm (직접 사용!) ⭐ NEW

직접 구현 (정말 필요한 것만):
├── Sequencer Logic       → 블록 생성, 체인 관리 (~500 LOC)
├── Block Adapter         → py-evm 타입 변환 (~200 LOC)
├── State Adapter         → py-evm State 연동 (~150 LOC)
├── Storage (Phase 1)     → dict 기반 (~100 LOC)
└── RPC (Phase 2)         → stdlib http.server (~150 LOC)

나중에 필요하면 추가:
├── Storage (Phase 2)     → SQLite로 교체
├── RPC (production)      → aiohttp로 교체
└── Performance hotpaths  → Cython (필요시)
```

---

## 2. 간소화된 아키텍처

### 1.1 컴포넌트 의존성 그래프

```
┌─────────────────────────────────────────────────────────────────┐
│                     Single Sequencer Node                        │
│                                                                   │
│  ┌─────────────┐     ┌──────────────────────────────────────┐   │
│  │    RPC      │     │          Sequencer Core              │   │
│  │  (Query)    │     │  ┌─────────────┐  ┌──────────────┐   │   │
│  │             │     │  │   Payload   │  │   Block      │   │   │
│  │ eth_*       │◄────┤  │   Builder   │  │  Executor    │   │   │
│  │ (read-only) │     │  └─────────────┘  └──────────────┘   │   │
│  └─────────────┘     │         │                │           │   │
│                      │         ▼                ▼           │   │
│                      │  ┌─────────────────────────────────┐  │   │
│                      │  │             EVM                  │  │   │
│                      │  └─────────────────────────────────┘  │   │
│                      └───────────────────┬───────────────────┘   │
│                                          │                       │
│                                          ▼                       │
│                      ┌───────────────────────────────────────┐   │
│                      │              Storage                  │   │
│                      │  ┌─────────────┐  ┌────────────────┐  │   │
│                      │  │   Blocks    │  │   State Trie   │  │   │
│                      │  │   Receipts  │  │   (MPT)        │  │   │
│                      │  └─────────────┘  └────────────────┘  │   │
│                      └───────────────────────────────────────┘   │
│                                          │                       │
│                                          ▼                       │
│                      ┌───────────────────────────────────────┐   │
│                      │           Core Types                  │   │
│                      │  Block, Tx, Account, RLP, Crypto      │   │
│                      └───────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 Rust → Python 매핑

> **⚠️ 핵심 변경: "직접 포팅"에서 "라이브러리 활용"으로 전환**

| Rust Crate | 기존 전략 | **새 전략** | 비고 |
|------------|----------|------------|------|
| `common/types` | ✅ 전체 포팅 | **ethereum-types 사용** | 래퍼만 작성 |
| `common/rlp` | ✅ 전체 포팅 | **ethereum-rlp 사용** | 0 LOC |
| `common/crypto` | ✅ 전체 포팅 | **coincurve/pycryptodome 사용** | ~50 LOC |
| `common/trie` | ✅ 전체 포팅 | **trie 사용** | 0 LOC |
| `vm/levm` | ✅ 전체 포팅 | **py-evm 직접 사용** | ~300 LOC 어댑터 |
| `storage` | ✅ 전체 포팅 | **dict로 시작** | ~100 LOC |
| `blockchain/execution` | ✅ 전체 포팅 | py-evm 활용 | ~200 LOC |
| `blockchain/validation` | ✅ 간소화 | 최소 검증만 | ~100 LOC |
| `blockchain/payload` | ✅ 전체 포팅 | 직접 구현 | ~300 LOC |
| `blockchain/mempool` | ❌ 제외 | - | 불필요 |
| `blockchain/fork_choice` | ❌ 제외 | - | 리오그 없음 |
| `networking/p2p` | ❌ 제외 | - | 불필요 |
| `networking/rpc` | ✅ 일부 | stdlib으로 시작 | ~150 LOC |
| `networking/rpc/engine` | ❌ 제외 | - | 불필요 |

---

## 3. 핵심 기능 목록

### 3.1 필수 구현 (Phase 1) - 경량화 버전

> **⚠️ "직접 구현"에서 "어댑터 작성"으로 전환**

| 기능 | 기존 전략 | **새 전략** | LOC 추정 |
|------|----------|------------|----------|
| **Core Types** | 직접 구현 | ethereum-types 래퍼 | ~150 LOC |
| **RLP Encoding** | 직접 구현 | ethereum-rlp 사용 | **0 LOC** |
| **Cryptography** | 직접 구현 | coincurve/pycryptodome 사용 | ~50 LOC |
| **Merkle Patricia Trie** | 직접 구현 | trie 사용 | **0 LOC** |
| **EVM** | 직접 구현 | py-evm 사용 | ~300 LOC |
| **Block Execution** | 직접 구현 | py-evm 활용 | ~200 LOC |
| **Storage** | SQLite 구현 | dict로 시작 | ~100 LOC |
| **Chain Config** | 직접 구현 | 최소 설정만 | ~50 LOC |

**총 LOC: ~850 LOC (기존 ~6,150 LOC에서 86% 감소)**

### 3.2 시퀀서 전용 기능 (Phase 2)

| 기능 | 설명 | 우선순위 |
|------|------|----------|
| **Payload Builder** | 새 블록 생성 | P1 |
| **Transaction Pool** | (선택적) 들어오는 tx 관리 | P2 |
| **Basic RPC** | 상태 조회용 API | P1 |
| **Block Production** | 주기적 블록 생성 | P1 |

### 3.3 제외 기능

| 기능 | 제외 이유 |
|------|----------|
| Fork Choice | 리오그 없음, 시퀀서가 독점 |
| Engine API | 컨센서스 클라이언트 없음 |
| P2P Discovery | 외부 피어 없음 |
| Block Sync | 외부 소스 없음 |
| Transaction Broadcasting | 자체 생성만 처리 |

---

## 4. Python 프로젝트 구조 - 경량화 버전

> **⚠️ 핵심 변경: 불필요한 디렉토리 삭제**

```
py-sequencer/
├── pyproject.toml
├── src/
│   └── sequencer/
│       ├── __init__.py
│       │
│       ├── core/                    # Phase 1: 어댑터만
│       │   ├── __init__.py
│       │   ├── types.py             # Account, Receipt 래퍼 (~150 LOC)
│       │   ├── crypto.py            # keccak256, sign, recover (~50 LOC)
│       │   ├── constants.py         # 체인 상수 (~20 LOC)
│       │   └── chainspec.py         # Fork 스케줄 (~30 LOC)
│       │
│       ├── evm/                     # Phase 1: py-evm 어댑터
│       │   ├── __init__.py
│       │   ├── adapter.py           # py-evm 래퍼 (~200 LOC)
│       │   └── state.py             # StateDB 어댑터 (~100 LOC)
│       │
│       ├── storage/                 # Phase 1: dict 기반
│       │   ├── __init__.py
│       │   └── store.py             # 인메모리 저장소 (~100 LOC)
│       │
│       ├── sequencer/               # Phase 2: 시퀀서 로직
│       │   ├── __init__.py
│       │   ├── executor.py          # 블록 실행 (~200 LOC)
│       │   ├── builder.py           # 블록 생성 (~300 LOC)
│       │   └── chain.py             # 체인 관리 (~100 LOC)
│       │
│       ├── rpc/                     # Phase 2: RPC (stdlib)
│       │   ├── __init__.py
│       │   ├── server.py            # HTTP 서버 (~100 LOC)
│       │   └── methods.py           # eth_* 메서드 (~150 LOC)
│       │
│       └── cli.py                   # CLI 진입점 (~50 LOC)
│
├── tests/
│   ├── test_executor.py
│   ├── test_builder.py
│   └── test_chain.py
│
└── README.md
```

### 핵심 변경 사항:

1. **`core/types/` → `core/types.py`**: ethereum-types 래퍼만 작성
2. **`core/rlp/` 삭제**: ethereum-rlp 직접 사용
3. **`core/crypto/` → `core/crypto.py`**: coincurve/pycryptodome 래퍼만
4. **`trie/` 삭제**: trie 라이브러리 직접 사용
5. **`evm/opcodes/`, `evm/precompiles/` 삭제**: py-evm 직접 사용
6. **`storage/backends/` 삭제**: dict로 시작

---

## 5. 핵심 컴포넌트 설계 - 경량화 버전

> **⚠️ "직접 구현"에서 "라이브러리 활용"으로 전환**

### 5.1 Core Types (최소 래퍼)

```python
# src/sequencer/core/types.py
"""최소한의 타입 래퍼 - ethereum-types 활용"""
from dataclasses import dataclass
from typing import Optional, List
from ethereum_types.numeric import U256, Uint
from ethereum_types.bytes import Bytes20, Bytes32
from ethereum_rlp import encode, decode

EMPTY_ROOT = bytes.fromhex(
    "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
)
EMPTY_CODE_HASH = bytes.fromhex(
    "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
)

@dataclass
class Account:
    """Account wrapper using ethereum-types"""
    nonce: Uint
    balance: U256
    storage_root: Bytes32
    code_hash: Bytes32
    
    @classmethod
    def empty(cls) -> 'Account':
        return cls(nonce=Uint(0), balance=U256(0), 
                   storage_root=EMPTY_ROOT, code_hash=EMPTY_CODE_HASH)
    
    def to_rlp(self) -> bytes:
        return encode([self.nonce, self.balance, self.storage_root, self.code_hash])
    
    @classmethod
    def from_rlp(cls, data: bytes) -> 'Account':
        nonce, balance, storage_root, code_hash = decode(data)
        return cls(nonce, balance, storage_root, code_hash)


@dataclass
class BlockHeader:
    """블록 헤더 - 싱글 시퀀서에서 필요한 필드만"""
    parent_hash: Bytes32
    ommers_hash: Bytes32  # 항상 빈 리스트 해시
    coinbase: Bytes20     # 시퀀서 주소
    state_root: Bytes32
    transactions_root: Bytes32
    receipts_root: Bytes32
    logs_bloom: bytes     # 256 bytes
    difficulty: int = 0   # 항상 0 (post-merge)
    number: int = 0
    gas_limit: int = 30_000_000
    gas_used: int = 0
    timestamp: int = 0
    extra_data: bytes = b''
    prev_randao: Bytes32 = b'\x00' * 32  # 시퀀서에서는 임의값
    nonce: bytes = b'\x00' * 8
    base_fee_per_gas: Optional[int] = None  # EIP-1559
    
    def hash(self) -> bytes:
        from .crypto import keccak256
        return keccak256(encode(self))


@dataclass  
class Block:
    """블록 - 최소한의 구조"""
    header: BlockHeader
    transactions: List['Transaction']
    
    # 싱글 시퀀서에서는 항상 빈 값
    ommers: List = None  # 항상 []
    withdrawals: List = None  # Shanghai+


# Transaction은 py-evm 타입을 그대로 사용
# 별도의 Transaction 클래스 정의 불필요
```

### 5.2 Crypto (라이브러리 래퍼)

```python
# src/sequencer/core/crypto.py
"""암호화 래퍼 - coincurve, pycryptodome 활용"""
from coincurve import PrivateKey, PublicKey
from Crypto.Hash import keccak

def keccak256(data: bytes) -> bytes:
    """Keccak-256 해시"""
    k = keccak.new(digest_bits=256)
    k.update(data)
    return k.digest()

def sign(private_key: bytes, message_hash: bytes) -> tuple[int, int, int]:
    """ECDSA 서명 → (v, r, s)"""
    pk = PrivateKey(private_key)
    signature = pk.sign(message_hash, hasher=None)
    # signature에서 r, s, v 추출
    r = int.from_bytes(signature[:32], 'big')
    s = int.from_bytes(signature[32:64], 'big')
    v = signature[64] + 27  # Ethereum 형식
    return v, r, s

def recover_address(message_hash: bytes, v: int, r: int, s: int) -> bytes:
    """서명에서 주소 복구"""
    from eth_keys import keys
    signature = keys.Signature(vrs=(v, r, s))
    public_key = signature.recover_public_key_from_msg_hash(message_hash)
    return keccak256(public_key.to_bytes()[1:])[12:]
```

### 5.3 EVM Adapter (py-evm 직접 사용)

```python
# src/sequencer/evm/adapter.py
"""py-evm 어댑터 - 직접 사용!"""
from eth.vm.forks.cancun import CancunVM
from eth.vm.message import Message
from eth.vm.computation import BaseComputation
from eth.chains.base import MiningChain
from eth.consensus.pow import PowConsensus
from eth.db.atomic import AtomicDB
from eth.db.backends.memory import MemoryDB

class EVMAdapter:
    """py-evm을 직접 사용하는 어댑터"""
    
    def __init__(self, chain_config):
        # py-evm의 MiningChain 사용
        self.chain = MiningChain.from_genesis(
            AtomicDB(MemoryDB()),
            genesis_params={
                'difficulty': 0,
                'gas_limit': chain_config.gas_limit,
                'timestamp': chain_config.timestamp,
            },
            genesis_state=chain_config.initial_state,
        )
    
    def execute_transaction(self, tx) -> 'ExecutionResult':
        """트랜잭션 실행 - py-evm에 위임"""
        # py-evm 트랜잭션 형식으로 변환
        vm_execution = self.chain.get_vm()
        computation = vm_execution.execute_transaction(tx)
        
        return ExecutionResult(
            success=computation.is_success,
            output=computation.output,
            gas_used=computation.get_gas_used(),
            logs=computation.get_log_entries(),
        )
    
    def get_state_root(self) -> bytes:
        """State Root 반환"""
        return self.chain.get_block().header.state_root


class ExecutionResult:
    success: bool
    output: bytes
    gas_used: int
    logs: list
```

### 5.4 State Adapter (trie 라이브러리 직접 사용)

```python
# src/sequencer/evm/state.py
"""State DB 어댑터 - trie 직접 사용"""
from trie import HexaryTrie
from ..core.types import Account

class StateDB:
    """간단한 State DB - trie 라이브러리 직접 사용"""
    
    def __init__(self, db: dict = None):
        self._trie = HexaryTrie(db or {})
        self._code: dict[bytes, bytes] = {}  # code_hash → code
    
    def get_account(self, address: bytes) -> Account:
        from ..core.crypto import keccak256
        key = keccak256(address)
        data = self._trie.get(key)
        return Account.from_rlp(data) if data else Account.empty()
    
    def set_account(self, address: bytes, account: Account):
        from ..core.crypto import keccak256
        key = keccak256(address)
        self._trie[key] = account.to_rlp()
    
    def get_code(self, address: bytes) -> bytes:
        account = self.get_account(address)
        return self._code.get(account.code_hash, b'')
    
    def set_code(self, address: bytes, code: bytes):
        from ..core.crypto import keccak256
        code_hash = keccak256(code)
        self._code[code_hash] = code
        
        account = self.get_account(address)
        account.code_hash = code_hash
        self.set_account(address, account)
    
    def get_storage(self, address: bytes, slot: int) -> int:
        # Storage trie는 Account.storage_root를 사용
        # 이 부분은 필요시 구현
        ...
    
    def root_hash(self) -> bytes:
        return self._trie.root_hash
```

### 5.5 Storage (dict로 시작)

```python
# src/sequencer/storage/store.py
"""인메모리 저장소 - 나중에 SQLite로 교체 가능"""
from typing import Optional
from ..core.types import Block, BlockHeader

class InMemoryStore:
    """가장 간단한 저장소 - dict 기반"""
    
    def __init__(self):
        # 블록 저장
        self._blocks: dict[int, Block] = {}
        self._block_by_hash: dict[bytes, Block] = {}
        
        # Trie 노드 저장 (trie 라이브러리가 사용)
        self._trie_nodes: dict[bytes, bytes] = {}
        
        # 컨트랙트 코드
        self._codes: dict[bytes, bytes] = {}
        
        # 영수증
        self._receipts: dict[bytes, Receipt] = {}
        
        # 메타데이터
        self._latest_number: int = -1
        self._chain_id: int = 1
    
    def get_block(self, number: int) -> Optional[Block]:
        return self._blocks.get(number)
    
    def get_block_by_hash(self, hash: bytes) -> Optional[Block]:
        return self._block_by_hash.get(hash)
    
    def get_latest_block(self) -> Optional[Block]:
        return self._blocks.get(self._latest_number)
    
    def save_block(self, block: Block):
        self._blocks[block.header.number] = block
        self._block_by_hash[block.header.hash()] = block
        self._latest_number = max(self._latest_number, block.header.number)
    
    def get_trie_db(self) -> dict:
        """trie 라이브러리에 전달할 DB"""
        return self._trie_nodes
```

### 5.6 Block Executor (시퀀서 전용)

```python
# src/sequencer/sequencer/executor.py
"""블록 실행기 - py-evm 활용"""
from typing import List, Tuple
from ..core.types import Block, Transaction, Receipt
from ..evm.adapter import EVMAdapter
from ..storage.store import InMemoryStore

class BlockExecutor:
    """블록 실행기 - 싱글 시퀀서용 간소화 버전"""
    
    def __init__(self, store: InMemoryStore, chain_config):
        self.store = store
        self.evm = EVMAdapter(chain_config)
    
    def execute_block(self, block: Block) -> Tuple[List[Receipt], bytes]:
        """블록 실행 - 검증은 최소한만"""
        # 1. 부모 블록 확인 (리오그 없으므로 간단)
        parent = self.store.get_block(block.header.number - 1)
        if parent is None and block.header.number != 0:
            raise ValueError(f"Parent not found: {block.header.number - 1}")
        
        # 2. 트랜잭션 실행 - py-evm에 위임
        receipts = []
        for tx in block.transactions:
            result = self.evm.execute_transaction(tx)
            receipts.append(Receipt(
                status=1 if result.success else 0,
                cumulative_gas_used=result.gas_used,
                logs=result.logs,
            ))
        
        # 3. State Root 검증
        actual_root = self.evm.get_state_root()
        if actual_root != block.header.state_root:
            raise ValueError(f"State root mismatch")
        
        return receipts, actual_root
```

### 5.7 Block Builder (시퀀서 전용)

```python
# src/sequencer/sequencer/builder.py
"""블록 생성기 - 싱글 시퀀서의 핵심"""
import time
import secrets
from typing import List, Optional
from ..core.types import Block, BlockHeader
from ..core.crypto import keccak256
from .executor import BlockExecutor

class BlockBuilder:
    """블록 생성기"""
    
    def __init__(self, store, executor: BlockExecutor, sequencer_address: bytes):
        self.store = store
        self.executor = executor
        self.sequencer_address = sequencer_address
    
    def build_block(self, transactions: List[Transaction], 
                    timestamp: Optional[int] = None) -> Block:
        """새 블록 생성"""
        parent = self.store.get_latest_block()
        parent_hash = parent.header.hash() if parent else b'\x00' * 32
        number = (parent.header.number + 1) if parent else 0
        
        # Base fee 계산 (EIP-1559)
        base_fee = self._calculate_base_fee(parent)
        
        # 임시 블록으로 실행
        header = BlockHeader(
            parent_hash=parent_hash,
            ommers_hash=self._empty_ommers_hash(),
            coinbase=self.sequencer_address,
            state_root=b'\x00' * 32,  # 실행 후 업데이트
            transactions_root=b'\x00' * 32,
            receipts_root=b'\x00' * 32,
            logs_bloom=b'\x00' * 256,
            number=number,
            timestamp=timestamp or int(time.time()),
            base_fee_per_gas=base_fee,
            prev_randao=secrets.token_bytes(32),
        )
        
        block = Block(header=header, transactions=transactions)
        receipts, state_root = self.executor.execute_block(block)
        
        # 실제 roots로 업데이트
        header.state_root = state_root
        header.transactions_root = self._compute_tx_root(transactions)
        header.receipts_root = self._compute_receipt_root(receipts)
        header.gas_used = sum(r.cumulative_gas_used for r in receipts)
        
        return block
    
    def _calculate_base_fee(self, parent: Optional[BlockHeader]) -> int:
        if parent is None or parent.base_fee_per_gas is None:
            return 1_000_000_000  # 1 Gwei 초기값
        # EIP-1559 공식 (간소화)
        return parent.base_fee_per_gas  # 실제로는 gas_used에 따라 조정
    
    def _empty_ommers_hash(self) -> bytes:
        return keccak256(b'\xc0')  # RLP([])
    
    def _compute_tx_root(self, transactions: List[Transaction]) -> bytes:
        # trie 라이브러리로 트랜잭션 루트 계산
        from trie import HexaryTrie
        trie = HexaryTrie({})
        for i, tx in enumerate(transactions):
            trie[encode(i)] = encode(tx)
        return trie.root_hash
```

---

## 6. Storage 설계 - 경량화 버전

> **⚠️ "dict로 시작, 나중에 SQLite로 교체"**

### Phase 1: 인메모리 저장소

```python
# 위 5.5절 InMemoryStore 참조
# 약 100 LOC
```

### Phase 2: SQLite 백엔드 (필요시에만)

```sql
-- 나중에 필요할 때만 추가
CREATE TABLE blocks (
    number INTEGER PRIMARY KEY,
    hash BLOB UNIQUE NOT NULL,
    header_rlp BLOB NOT NULL,
    body_rlp BLOB NOT NULL
);

CREATE TABLE trie_nodes (
    hash BLOB PRIMARY KEY,
    node_rlp BLOB NOT NULL
);

CREATE TABLE codes (
    code_hash BLOB PRIMARY KEY,
    code BLOB NOT NULL
);

CREATE TABLE receipts (
    tx_hash BLOB PRIMARY KEY,
    receipt_rlp BLOB NOT NULL,
    block_number INTEGER NOT NULL
);

CREATE TABLE metadata (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
```

---

## 7. 구현 로드맵 - 경량화 버전

### Phase 1: Core Foundation (1-2주) ⬅️ 대폭 단축

**목표**: 블록 실행 가능 (py-evm 활용)

| 작업 | 산출물 | LOC |
|------|--------|-----|
| Types 래퍼 | Account, BlockHeader, Block | ~150 |
| Crypto 래퍼 | keccak256, sign, recover | ~50 |
| EVM 어댑터 | py-evm 연동 | ~200 |
| State 어댑터 | trie 연동 | ~100 |
| Storage | dict 기반 | ~100 |
| **합계** | | **~600 LOC** |

**검증**:
- 단일 트랜잭션 실행 가능
- State Root 계산 가능

### Phase 2: Sequencer (1주)

**목표**: 블록 생성 가능

| 작업 | 산출물 | LOC |
|------|--------|-----|
| Block Executor | 실행 + 검증 | ~200 |
| Block Builder | 블록 생성 | ~300 |
| Chain | append-only 관리 | ~100 |
| **합계** | | **~600 LOC** |

**검증**:
- Genesis에서 연속 블록 생성
- 상태 일관성 유지

### Phase 3: RPC (0.5주)

**목표**: 기본 조회 가능

| 작업 | 산출물 | LOC |
|------|--------|-----|
| HTTP Server | stdlib http.server | ~100 |
| eth_* methods | 기본 조회만 | ~150 |
| **합계** | | **~250 LOC** |

### 총 LOC: ~1,450 LOC (기존 ~6,150 LOC에서 76% 감소)

---

## 8. 테스트 전략 - 경량화 버전

> **⚠️ "EF Tests보다 빠른 피드백 우선"**

### 8.1 단위 테스트

```python
# tests/test_types.py
def test_account_rlp():
    account = Account(nonce=Uint(1), balance=U256(100), ...)
    encoded = account.to_rlp()
    decoded = Account.from_rlp(encoded)
    assert decoded == account

# tests/test_evm.py
def test_evm_adapter():
    adapter = EVMAdapter(test_config)
    result = adapter.execute_transaction(test_tx)
    assert result.success

# tests/test_builder.py
def test_build_block():
    builder = BlockBuilder(...)
    block = builder.build_block([test_tx])
    assert block.header.number == 1
```

### 8.2 통합 테스트

```python
# tests/test_chain.py
def test_sequential_blocks():
    chain = Chain.from_genesis(test_genesis)
    for i in range(10):
        tx = create_test_tx(nonce=i)
        block = chain.produce_block([tx])
        assert block.header.number == i + 1
```

### 8.3 EF Tests (선택적)

```python
# py-evm이 이미 EF Tests를 통과했으므로
# 우리는 어댑터만 테스트하면 됨
# tests/test_adapter.py
def test_py_evm_compatibility():
    # py-evm의 테스트 벡터 사용
    ...
```

---

## 9. 의존성 - 경량화 버전

```toml
[project]
name = "sequencer"
version = "0.1.0"
dependencies = [
    # 핵심 - 직접 사용!
    "py-evm>=0.12.0b1",              # EVM 실행 엔진
    "ethereum-rlp>=0.1.4",           # RLP 인코딩/디코딩
    "trie>=3.1.0",                   # Merkle Patricia Trie
    "ethereum-types>=0.1.0",         # 타입 정의
    
    # 암호화
    "coincurve>=21.0.0",             # secp256k1
    "pycryptodome>=3.20.0",          # Keccak256
    
    # 유틸리티
    "eth-utils>=5.0.0",              # 유틸리티
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0.0",
    "pytest-asyncio>=0.23.0",
]

# Phase 2에서만 추가
production = [
    "aiosqlite>=0.19.0",             # SQLite (필요시)
]
```

---

## 10. 요약

### 경량화 비교

| 항목 | 기존 계획 | **새 계획** | 절감 |
|------|----------|------------|------|
| 코드 규모 | ~6,150 LOC | **~1,450 LOC** | **76%** |
| Phase 1 기간 | 3-4주 | **1-2주** | **50%** |
| Phase 2 기간 | 2주 | **1주** | **50%** |
| Phase 3 기간 | 1-2주 | **0.5주** | **66%** |
| 의존성 수 | 10+ | **6** | **40%** |

### 핵심 원칙 재강조

1. **라이브러리를 직접 사용하라**: py-evm, trie, ethereum-rlp, ethereum-types
2. **확장하지 마라**: "필요시 확장"은 나중에 실제로 필요할 때
3. **dict로 시작하라**: SQLite는 나중에
4. **stdlib 우선**: aiohttp 대신 http.server
5. **멍청한 코드가 좋다**: 나중에 개선하기 더 쉽다

### 라이브러리 활용 요약

| 기능 | 선택한 라이브러리 | 방식 |
|------|------------------|------|
| **EVM** | py-evm | **직접 사용** ⭐ |
| **RLP** | ethereum-rlp | 직접 사용 |
| **Crypto** | coincurve + pycryptodome | 래퍼만 |
| **Trie** | trie | **직접 사용** ⭐ |
| **Types** | ethereum-types | **직접 사용** ⭐ |
| **Storage** | dict → SQLite (나중에) | 직접 구현 |