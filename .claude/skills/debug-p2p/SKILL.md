---
description: "P2P Networking Debug — RLPx, devp2p, sync issue diagnosis"
allowed-tools: ["Read", "Glob", "Grep", "Edit", "Write", "Bash", "Task"]
argument-hint: "P2P error message or symptom"
user-invocable: true
---

# P2P Networking Debug Skill

Specialized skill for diagnosing and resolving RLPx connections, devp2p handshakes, and synchronization issues.

## Key File References

| File | Role |
|------|------|
| `ethclient/networking/rlpx/transport.py` | RLPx connection, ECIES handshake |
| `ethclient/networking/rlpx/ecies.py` | ECIES encryption/decryption |
| `ethclient/networking/rlpx/protocol.py` | devp2p protocol messages |
| `ethclient/networking/eth/protocol.py` | eth/68 message encoding/decoding |
| `ethclient/networking/snap/protocol.py` | snap/1 messages |
| `ethclient/networking/discv4/` | Discovery v4 (Kademlia) |
| `ethclient/networking/sync/full_sync.py` | Full sync strategy |
| `ethclient/networking/sync/snap_sync.py` | Snap sync strategy |

## Debug Checklist

### Connection Failures

- [ ] **TCP connection**: Verify port 30303 is accessible (firewall, NAT)
- [ ] **ECIES handshake**: auth-msg → auth-ack → frame cipher initialization
- [ ] **Hello message**: devp2p version, client ID, capability list exchange
- [ ] **Snappy compression**: Must set `conn.use_snappy = True` for Geth v1.17.0+
- [ ] **Protocol capabilities**: Verify `["eth/68", "snap/1"]` matching

### TOO_MANY_PEERS (0x04)

Most common connection refusal reason:

```python
from ethclient.networking.rlpx.protocol import DisconnectReason
# DisconnectReason.TOO_MANY_PEERS == 0x04
```

**Mitigation strategies:**
1. **Use Discovery v4**: Instead of connecting directly to bootnodes, discover multiple peers via discv4
2. **Use Sepolia**: Higher connection success rate than Mainnet bootnodes
3. **Retry logic**: Retry at 5-10 second intervals, maximum 10 attempts
4. **Multiple bootnodes**: Attempt connections to several bootnodes simultaneously

```python
# Sepolia bootnodes (EF DevOps, high connection success rate)
SEPOLIA_BOOTNODES = [
    ("138.197.51.181", 30303),
    ("146.190.1.103", 30303),
]
```

### Handshake Failures

**ECIES Handshake Flow:**
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

**Common failure causes:**
- `MAC mismatch`: ECIES key derivation error. Check local key
- `Unexpected message`: Non-Hello message received before Hello. Check frame parsing
- `Protocol version mismatch`: devp2p v5 required
- `Network ID mismatch`: Mainnet=1, Sepolia=11155111
- `Genesis hash mismatch`: Use correct genesis for the network

### Snappy Compression Issues

```python
# Required for Geth v1.17.0+
conn.use_snappy = True

# Symptoms: message decoding failure, RLP parsing errors
# Cause: missing snappy compress/decompress
# Fix: verify python-snappy package is installed
#   pip install python-snappy
```

## RLPx Connection Details

### ECIES (Elliptic Curve Integrated Encryption Scheme)

```python
from ethclient.networking.rlpx.ecies import ecies_encrypt, ecies_decrypt

# auth-msg creation
# 1. Generate ephemeral keypair
# 2. Sign with static key
# 3. Encrypt with ECIES (using remote public key)
# 4. Send

# auth-ack processing
# 1. Decrypt with ECIES (using local private key)
# 2. Derive shared secret (ECDH)
# 3. Generate frame cipher keys (KDF)
```

### Frame Structure

```
[header (16B, AES-CTR encrypted)]
[header-mac (16B)]
[frame (variable, AES-CTR encrypted, padded to 16B)]
[frame-mac (16B)]

header: [frame-size (3B big-endian)] [header-data (13B)]
```

### devp2p Hello Message

```python
# p2p message codes
HELLO = 0x00
DISCONNECT = 0x01
PING = 0x02
PONG = 0x03

# Hello fields:
# version: 5
# client_id: "py-ethclient/1.0"
# caps: [["eth", 68], ["snap", 1]]
# listen_port: 30303
# node_id: 64-byte public key
```

## Disconnect Reasons

```python
class DisconnectReason(IntEnum):
    REQUESTED = 0x00           # Normal shutdown
    TCP_ERROR = 0x01           # TCP error
    BREACH_OF_PROTOCOL = 0x02  # Protocol violation
    USELESS_PEER = 0x03        # Useless peer
    TOO_MANY_PEERS = 0x04      # Peer limit exceeded ★
    ALREADY_CONNECTED = 0x05   # Already connected
    INCOMPATIBLE_VERSION = 0x06 # Incompatible version
    INVALID_IDENTITY = 0x07    # Invalid identity
    CLIENT_QUITTING = 0x08     # Client quitting
    UNEXPECTED_IDENTITY = 0x09 # Unexpected identity
    CONNECTED_TO_SELF = 0x0a   # Connected to self
    TIMEOUT = 0x0b             # Timeout
    SUBPROTOCOL_ERROR = 0x10   # Subprotocol error
```

## eth/68 Status Debugging

```python
# Post-Status exchange validation items:
# 1. networkId match (1=mainnet, 11155111=sepolia)
# 2. genesisHash match
# 3. forkID compatibility (fork_hash + fork_next)

# ForkID calculation:
# fork_hash = CRC32(genesis_hash + fork_block_numbers)
# fork_next = next scheduled hard fork block

# On mismatch: DISCONNECT(SUBPROTOCOL_ERROR)
```

## Discovery v4 Debugging

### Packet Structure
```
[hash (32B)] [signature (65B)] [type (1B)] [data (RLP)]
hash = keccak256(signature || type || data)
```

### Common Issues

1. **UDP not received**: Check port 30303/UDP firewall
2. **No Ping response**: Set external IP correctly behind NAT
3. **Empty routing table**: Must send Ping to bootnodes first
4. **Expiration timeout**: Expiration field must be a future timestamp (current + 20s recommended)

### Bootnode Connection

```python
from ethclient.networking.discv4.routing import Node, RoutingTable

# Add bootnode to table
boot = Node(id=boot_pubkey, ip="138.197.51.181", udp_port=30303, tcp_port=30303)
table.add_node(boot)

# Discover nearby nodes via FindNode
closest = table.closest_nodes(target_id=my_node_id, count=16)
```

## Sync Debugging

### Full Sync Issues

| Symptom | Cause | Resolution |
|---------|-------|------------|
| Header download stalls | No peer response | Try different peer, adjust timeout |
| Missing bodies | Peer lacks data | Distribute requests across peers |
| EVM execution failure | State mismatch | Re-execute from earlier block |
| Slow synchronization | Sequential block processing | Use snap sync |

### Snap Sync Issues

| Symptom | Cause | Resolution |
|---------|-------|------------|
| Empty AccountRange response | Pivot block too old | Restart with fresh pivot |
| Proof verification failure | State changed | Update pivot block |
| Missing bytecodes | Hash mismatch | Re-request from different peer |
| Timeouts | Slow peer | Use adaptive timeout |

```python
# Snap sync timeout constants
SNAP_TIMEOUT = 15  # seconds (default)
PEER_WAIT_TIMEOUT = 30  # peer wait
# adaptive_timeout: automatically increases for slow peers
```

## Logging Configuration

```python
import logging

# P2P debug logging
logging.getLogger("ethclient.networking.rlpx").setLevel(logging.DEBUG)
logging.getLogger("ethclient.networking.eth").setLevel(logging.DEBUG)
logging.getLogger("ethclient.networking.discv4").setLevel(logging.DEBUG)
logging.getLogger("ethclient.networking.sync").setLevel(logging.DEBUG)
```

## Network-Specific Settings

| Item | Mainnet | Sepolia |
|------|---------|---------|
| Network ID | 1 | 11155111 |
| Chain ID | 1 | 11155111 |
| Bootnode success rate | Low (TOO_MANY_PEERS) | High |
| eth protocol | eth/68, eth/69 | eth/68, eth/69 |
| snap protocol | snap/1 | snap/1 |
| Snappy | Required | Required |

## Caveats

1. **Snappy required**: All Geth nodes since 2024 require snappy compression
2. **Mainnet connection difficulty**: TOO_MANY_PEERS is predominant. Use discv4 to work around
3. **ECIES key management**: Node key is secp256k1. 64-byte uncompressed public key (excluding 0x04 prefix)
4. **Frame size**: Maximum 16MB. Large responses need to be chunked
5. **Ping/pong interval**: 15 seconds recommended. Connection closed on non-response
6. **ForkID validation**: Incompatible forks cause immediate disconnect
