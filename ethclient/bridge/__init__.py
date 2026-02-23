"""General State Bridge — L1/L2 cross-domain messaging with pluggable relay."""

from ethclient.bridge.types import (
    BatchRelayResult,
    CrossDomainMessage,
    Domain,
    ForceInclusionEntry,
    FORCE_INCLUSION_WINDOW,
    RelayResult,
)
from ethclient.bridge.messenger import CrossDomainMessenger, MESSENGER_ADDRESS
from ethclient.bridge.watcher import BridgeWatcher
from ethclient.bridge.environment import BridgeEnvironment
from ethclient.bridge.relay_handlers import (
    DirectStateHandler,
    EVMRelayHandler,
    MerkleProofHandler,
    RelayHandler,
    StateUpdate,
    TinyDBHandler,
    ZKProofHandler,
    encode_state_updates,
    decode_state_updates,
)

__all__ = [
    "BatchRelayResult",
    "BridgeEnvironment",
    "BridgeWatcher",
    "CrossDomainMessage",
    "CrossDomainMessenger",
    "DirectStateHandler",
    "Domain",
    "EVMRelayHandler",
    "FORCE_INCLUSION_WINDOW",
    "ForceInclusionEntry",
    "MESSENGER_ADDRESS",
    "MerkleProofHandler",
    "RelayHandler",
    "RelayResult",
    "StateUpdate",
    "TinyDBHandler",
    "ZKProofHandler",
    "decode_state_updates",
    "encode_state_updates",
]
