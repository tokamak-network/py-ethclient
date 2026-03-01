---
description: "L1↔L2 Bridge — CrossDomainMessenger, force inclusion, escape hatch"
allowed-tools: ["Read", "Glob", "Grep", "Edit", "Write", "Bash", "Task"]
argument-hint: "bridge use case or direction (L1→L2 or L2→L1)"
user-invocable: true
---

# L1↔L2 Bridge Construction Skill

Guides bidirectional L1↔L2 message passing based on CrossDomainMessenger, 5 relay handler types, and force inclusion/escape hatch safety mechanisms.

## Key File References

| File | Role |
|------|------|
| `ethclient/bridge/messenger.py` | CrossDomainMessenger — message send/receive |
| `ethclient/bridge/relay_handlers.py` | 5 RelayHandler implementations |
| `ethclient/bridge/types.py` | CrossDomainMessage, Domain, RelayResult, StateUpdate |
| `ethclient/bridge/watcher.py` | BridgeWatcher — automatic relay |
| `ethclient/bridge/environment.py` | BridgeEnvironment — integration test harness |
| `ethclient/l2/l1_backend.py` | InMemoryL1Backend |
| `ethclient/l2/eth_l1_backend.py` | EthL1Backend (real Ethereum) |

## Quick Start: EVM Bridge

```python
from ethclient.bridge.environment import BridgeEnvironment

# 1. Create bridge environment with EVM relay
env = BridgeEnvironment.with_evm(l1_chain_id=1, l2_chain_id=42170)

ALICE = b"\x01" * 20
L2_CONTRACT = b"\xca\xfe" + b"\x00" * 18

# 2. L1 → L2 deposit (ETH transfer)
msg = env.send_l1(
    sender=ALICE,
    target=L2_CONTRACT,
    data=b"",           # calldata
    value=1_000_000,    # wei
)

# 3. Execute relay (Watcher drains L1 outbox → L2 relay)
result = env.relay()
assert result.all_success

# 4. Check L2 balance
assert env.l2_balance(L2_CONTRACT) == 1_000_000
```

## Message Structure

```python
@dataclass
class CrossDomainMessage:
    nonce: int              # Auto-incremented per domain, prevents replay
    sender: bytes           # 20-byte sender
    target: bytes           # 20-byte recipient
    data: bytes             # Arbitrary calldata (ABI encoded)
    value: int = 0          # ETH transfer amount (minted on receiving domain)
    gas_limit: int = 1_000_000
    source_domain: Domain   # Domain.L1 or Domain.L2
    block_number: int = 0   # Send block (set by messenger)
    message_hash: bytes     # keccak256(RLP([nonce, sender, target, ...]))
```

## 5 Relay Handler Types

### 1. EVMRelayHandler (default)
```python
env = BridgeEnvironment.with_evm()
```
- Executes EVM bytecode, smart contract calls
- If `msg.value > 0`, mints balance to target
- Commits state changes on success, full rollback on failure
- 30M gas limit, uses MESSENGER_ADDRESS (`0x4200...42`) as caller

### 2. MerkleProofHandler
```python
env = BridgeEnvironment.with_merkle_proof()
```
- Verifies Merkle proof against L1 state root, then applies state
- Must register trusted root via `add_trusted_root(root)`
- Data format: `RLP([state_root, address, account_rlp, [proof_nodes], [storage_proofs]])`

### 3. ZKProofHandler
```python
from ethclient.zk.types import VerificationKey
env = BridgeEnvironment.with_zk_proof(vk=my_verification_key)
```
- Verifies Groth16 proof, then applies state updates
- Data format: `RLP([proof_a(64B), proof_b(128B), proof_c(64B), [public_inputs], [state_updates]])`

### 4. DirectStateHandler
```python
env = BridgeEnvironment.with_direct_state()
```
- Applies state directly without verification (assumes trusted relayer)
- For testing/prototyping only

### 5. TinyDBHandler
```python
from ethclient.bridge.relay_handlers import TinyDBHandler
handler = TinyDBHandler()
```
- Stores state in JSON document DB (non-EVM runtime)
- `get_account(address)` → dict lookup

## Deposit/Withdrawal Flows

### L1 → L2 Deposit
```
User → l1_messenger.send_message(target=L2_contract, value=ETH)
  → Message queued in L1 outbox
  → Watcher calls drain_outbox() then l2_messenger.relay_message(msg)
  → EVMRelayHandler: mint value to target + execute calldata
  → Mark as relayed (replay prevention)
```

### L2 → L1 Withdrawal
```
L2_contract → l2_messenger.send_message(target=User, value=ETH)
  → Message queued in L2 outbox
  → Watcher calls l1_messenger.relay_message(msg)
  → Mint value + execute on L1
```

## Force Inclusion (Censorship Resistance)

When the L2 operator refuses to relay a message, users can force include directly:

```python
# FORCE_INCLUSION_WINDOW = 50 blocks (hardcoded)

# 1. Register force inclusion on L1
entry = env.force_include(msg)

# 2. Wait 50 blocks
env.advance_l1_block(50)

# 3. Anyone can execute forced relay
result = env.force_relay(msg)
assert result.success
```

## Escape Hatch (Last Resort)

When L2 is completely down and relay is impossible, recover deposits on L1:

```python
# Conditions: force_include done + 50 blocks elapsed + msg.value > 0
result = env.escape_hatch(msg)
assert result.success
# → msg.sender's L1 balance refunded with msg.value
```

**Error cases:**
- "message not in force queue"
- "force inclusion window not elapsed"
- "already resolved (relayed or escaped)"
- "no value to recover" (value=0 message)

## BridgeWatcher Direct Usage

```python
from ethclient.bridge.watcher import BridgeWatcher

watcher = BridgeWatcher(l1_messenger, l2_messenger)

# One cycle: L1→L2 + L2→L1 + force queue processing
result = watcher.tick()
# BatchRelayResult { l1_to_l2, l2_to_l1, forced, all_success, total_relayed }
```

## StateUpdate Structure

Used by MerkleProof, ZKProof, and DirectState handlers:

```python
@dataclass
class StateUpdate:
    address: bytes              # 20 bytes
    balance: int | None = None  # Balance to set
    nonce: int | None = None    # Nonce to set
    storage: dict[int, int] = {}  # slot → value

# Encoding/decoding
from ethclient.bridge.types import encode_state_updates, decode_state_updates
data = encode_state_updates([StateUpdate(address=ALICE, balance=1000)])
```

## State Queries

```python
env.l1_balance(ALICE)           # L1 balance
env.l2_balance(ALICE)           # L2 balance
env.l1_storage(contract, slot)  # L1 storage
env.l2_storage(contract, slot)  # L2 storage
env.l1_state_root()             # L1 state root
env.l2_state_root()             # L2 state root
```

## Security Considerations

### Security Mechanisms (WHITEPAPER 7.4)

| Mechanism | Description | Implementation |
|-----------|-------------|----------------|
| **Replay protection** | Domain-scoped nonce prevents message replay | `message_hash` checked in `relayed_messages` set |
| **Force inclusion** | Users bypass censoring operator after 50-block window | `force_include()` → `force_relay()` on L1 |
| **Escape hatch** | L1 fund recovery when L2 is fully down | Refunds `msg.value` to sender on L1 |
| **Proof-based relay** | MerkleProof/ZKProof handlers verify before state application | Cryptographic verification before state mutation |

### Known Security Limitations (WHITEPAPER 10.1.6)

- **No dispute mechanism**: Once a batch is submitted and verified, there is no challenge period or fraud proof mechanism to contest invalid state transitions
- **L1 finality unawareness**: The bridge does not track L1 finality status — messages relayed before L1 finality may be invalidated by L1 reorgs
- **Blob DA expiry**: If batch data is posted as EIP-4844 blobs, it expires after ~18 days. Historical state reconstruction requires archival storage
- **Single operator trust**: Value bridging uses mint/burn (not escrow), assuming a single trusted operator

### STF-side Bridge Security (WHITEPAPER 10.1.8)

When the STF processes bridge-related transactions (deposits/withdrawals):
- **Token bridging**: Ensure mint/burn amounts match cross-domain messages exactly
- **Message ordering**: Process deposits in nonce order to prevent reordering attacks
- **Deposit validation**: Verify deposit messages originate from the trusted L1 messenger contract

## Caveats

1. **Value is minted**: Not escrowed — minted on destination domain. Single operator trust model
2. **Outbox drain is destructive**: Messages are removed from outbox after `drain_outbox()`. Production needs persistent queue
3. **Block number is manual**: Must call `advance_l1_block(n)`. No auto-sync with JSON-RPC block height
4. **Nonces are domain-independent**: L1 and L2 each start from 0
5. **EVM relay atomicity**: All-or-nothing. No partial state updates
6. **Trusted root has no expiry**: Roots registered via `add_trusted_root()` remain valid indefinitely
7. **Gas limit**: EVM relay uses msg.gas_limit, non-EVM handlers report gas_used=0
8. **L1 reorg risk**: Messages relayed before L1 finality (~13 min for PoS) may be invalidated by chain reorganizations
9. **No dispute mechanism**: Submitted batches cannot be challenged — there is no fraud proof or challenge period
