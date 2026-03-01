---
description: "L1 Ethereum Node — EVM, eth/68, snap/1, Engine API, P2P"
allowed-tools: ["Read", "Glob", "Grep", "Edit", "Write", "Bash", "Task"]
argument-hint: "node-related task or question"
user-invocable: true
---

# L1 Ethereum Node Operation Skill

Guides EVM execution, eth/68 protocol, snap/1 synchronization, Engine API, and P2P networking for the Python-based Ethereum L1 client.

## Key File References

| Directory/File | Role |
|----------------|------|
| `ethclient/vm/` | EVM execution engine |
| `ethclient/vm/opcodes.py` | 140+ opcode implementations |
| `ethclient/vm/precompiles.py` | 11 precompiles (ecrecover ~ kzg_point_eval) |
| `ethclient/vm/evm.py` | EVM interpreter, CallFrame, ExecutionEnvironment |
| `ethclient/networking/rlpx/` | RLPx protocol, ECIES handshake |
| `ethclient/networking/eth/` | eth/68 protocol messages |
| `ethclient/networking/snap/` | snap/1 state synchronization |
| `ethclient/networking/discv4/` | Discovery v4 node discovery |
| `ethclient/networking/sync/` | Full sync, Snap sync strategies |
| `ethclient/blockchain/` | Block, Header, Transaction management |
| `ethclient/rpc/server.py` | JSON-RPC 2.0 server (FastAPI) |
| `ethclient/rpc/engine_api.py` | Engine API V1/V2/V3 (PoS) |

## EVM Execution Engine

### Supported Opcodes (140+)

**Arithmetic**: ADD, MUL, SUB, DIV, SDIV, MOD, SMOD, ADDMOD, MULMOD, EXP, SIGNEXTEND
**Comparison/Bitwise**: LT, GT, SLT, SGT, EQ, ISZERO, AND, OR, XOR, NOT, BYTE, SHL, SHR, SAR
**Hash**: KECCAK256
**Environment**: ADDRESS, BALANCE, ORIGIN, CALLER, CALLVALUE, CALLDATALOAD, CALLDATASIZE, CALLDATACOPY, CODESIZE, CODECOPY, GASPRICE, EXTCODESIZE, EXTCODECOPY, RETURNDATASIZE, RETURNDATACOPY, EXTCODEHASH, BLOCKHASH, COINBASE, TIMESTAMP, NUMBER, PREVRANDAO, GASLIMIT, CHAINID, SELFBALANCE, BASEFEE, BLOBHASH, BLOBBASEFEE
**Memory/Storage**: MLOAD, MSTORE, MSTORE8, SLOAD, SSTORE, MSIZE, MCOPY, TLOAD, TSTORE
**Stack**: POP, PUSH0~PUSH32, DUP1~DUP16, SWAP1~SWAP16
**Flow**: JUMP, JUMPI, PC, GAS, JUMPDEST, STOP, RETURN, REVERT, INVALID, SELFDESTRUCT
**Log**: LOG0~LOG4
**Call**: CALL, CALLCODE, DELEGATECALL, STATICCALL, CREATE, CREATE2

### Precompiles (11)

| Address | Name | Function |
|---------|------|----------|
| 0x01 | ecrecover | ECDSA signature recovery |
| 0x02 | sha256 | SHA-256 hash |
| 0x03 | ripemd160 | RIPEMD-160 hash |
| 0x04 | identity | Data copy |
| 0x05 | modexp | Modular exponentiation |
| 0x06 | ecadd | BN128 G1 point addition |
| 0x07 | ecmul | BN128 G1 scalar multiplication |
| 0x08 | ecpairing | BN128 pairing check |
| 0x09 | blake2f | BLAKE2b compression function |
| 0x0a | kzg_point_eval | KZG point evaluation (EIP-4844) |
| 0x100 | p256verify | P-256 signature verification (RIP-7212) |

### EVM Execution

```python
from ethclient.vm.evm import run_bytecode, ExecutionEnvironment, CallFrame

env = ExecutionEnvironment(
    caller=b"\x01" * 20,
    address=b"\x02" * 20,
    value=0,
    data=b"",
    gas=30_000_000,
)

result = run_bytecode(bytecode=b"\x60\x01\x60\x02\x01", env=env)
# PUSH1 1, PUSH1 2, ADD → stack top = 3
```

## eth/68 Protocol

### Message Types

| Code | Message | Direction | Description |
|------|---------|-----------|-------------|
| 0x00 | Status | Bidirectional | Handshake (network_id, genesis, head, forkid) |
| 0x01 | NewBlockHashes | → | New block hash announcement |
| 0x02 | Transactions | → | Transaction propagation |
| 0x03 | GetBlockHeaders | → | Block header request |
| 0x04 | BlockHeaders | ← | Block header response |
| 0x05 | GetBlockBodies | → | Block body request |
| 0x06 | BlockBodies | ← | Block body response |
| 0x07 | NewBlock | → | New block propagation |
| 0x08 | NewPooledTransactionHashes | → | Pool TX hash announcement (eth/68) |
| 0x09 | GetPooledTransactions | → | Pool TX request |
| 0x0a | PooledTransactions | ← | Pool TX response |
| 0x0d | GetReceipts | → | Receipt request |
| 0x0e | Receipts | ← | Receipt response |

### eth/68 Status Handshake
```python
# Status message fields:
# version: 68
# network_id: 1 (mainnet) or 11155111 (sepolia)
# td: total difficulty
# head: best block hash
# genesis: genesis hash
# forkid: [fork_hash(4B), fork_next(8B)]
```

## snap/1 Synchronization

### Messages

| Code | Message | Description |
|------|---------|-------------|
| 0x00 | GetAccountRange | Account range request (root, origin, limit, bytes) |
| 0x01 | AccountRange | Account range response + proof |
| 0x02 | GetStorageRanges | Storage range request |
| 0x03 | StorageRanges | Storage range response |
| 0x04 | GetByteCodes | Bytecode request by code hash |
| 0x05 | ByteCodes | Bytecode response |
| 0x06 | GetTrieNodes | Trie node path request |
| 0x07 | TrieNodes | Trie node response |

### Snap Sync Strategy
1. Determine pivot block (head - 64)
2. Download account trie via GetAccountRange
3. Download storage via GetStorageRanges
4. Download contract code via GetByteCodes
5. Fill missing nodes via GetTrieNodes
6. Full sync for blocks after pivot

## Discovery v4

### Protocol

| Packet | Type | Description |
|--------|------|-------------|
| Ping | 0x01 | Liveness check (version, from, to, expiration, enr_seq) |
| Pong | 0x02 | Ping response (to, ping_hash, expiration, enr_seq) |
| FindNode | 0x03 | Find nodes close to target |
| Neighbours | 0x04 | FindNode response |

### Kademlia Routing Table
```python
BUCKET_SIZE = 16      # k-bucket capacity
NUM_BUCKETS = 256     # 256-bit node ID
ALPHA = 3             # Concurrent lookups
MAX_REPLACEMENTS = 10 # Replacement list size
```

- Distance = keccak256(pubkey_A) XOR keccak256(pubkey_B)
- log_distance: 0 (same) ~ 256

## Engine API (PoS)

### V1 Methods
- `engine_newPayloadV1(payload)` — Validate new execution payload
- `engine_forkchoiceUpdatedV1(state, attrs)` — Fork choice update
- `engine_getPayloadV1(id)` — Return block build result

### V2 Methods (Shanghai/Capella)
- `engine_newPayloadV2` — Includes withdrawals
- `engine_forkchoiceUpdatedV2`
- `engine_getPayloadV2`

### V3 Methods (Cancun/Deneb)
- `engine_newPayloadV3` — Includes blob versioned hashes
- `engine_forkchoiceUpdatedV3`
- `engine_getPayloadV3`

### JWT Authentication
```python
rpc = RPCServer()
rpc.set_engine_jwt_secret(secret_bytes)
# engine_* methods require Bearer JWT
# JWT: HS256, iat-based, 120s skew tolerance
```

## RPC Server

```python
from ethclient.rpc.server import RPCServer

rpc = RPCServer()  # FastAPI-based

# Register methods
rpc.register("eth_blockNumber", lambda: hex(chain.height))

@rpc.method("eth_getBalance")
def get_balance(address: str, block: str = "latest"):
    return hex(state.get_balance(address))

# Run
import uvicorn
uvicorn.run(rpc.app, host="0.0.0.0", port=8545)
```

## Bootnode Information

### Sepolia (EF DevOps)
```
138.197.51.181:30303
146.190.1.103:30303
```

### Mainnet
- TOO_MANY_PEERS is frequent → use discv4 discovery instead
- Geth v1.17.0+: eth/68 + eth/69 + snap/1

## Sync Strategies

### Full Sync
```python
from ethclient.networking.sync.full_sync import FullSync

syncer = FullSync(chain, peer_pool)
# GetBlockHeaders → GetBlockBodies → EVM execution → state update
```

### Snap Sync
```python
from ethclient.networking.sync.snap_sync import SnapSync

syncer = SnapSync(chain, peer_pool)
# Pivot block → account download → storage → bytecode → full sync
```

## Caveats

1. **Snappy compression required**: Must set `conn.use_snappy = True` when communicating with Geth v1.17.0+
2. **eth/68 vs eth/69**: Latest Geth supports both. py-ethclient implements eth/68
3. **EVM gas calculation**: Reflects Berlin/London/Shanghai price tables
4. **EIP-2929**: Access list support — warm/cold storage slots
5. **EIP-4844**: Blob tx, kzg_point_eval precompile support
6. **Transient Storage**: TLOAD/TSTORE (EIP-1153) support
7. **MCOPY**: EIP-5656 memory copy opcode support
