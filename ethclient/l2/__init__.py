"""Application-specific ZK rollup framework.

Usage::

    from ethclient.l2 import Rollup, L2Tx, STFResult

    def my_stf(state, tx):
        state["count"] = state.get("count", 0) + 1
        return STFResult(success=True)

    rollup = Rollup(stf=my_stf)
    rollup.setup()

    rollup.submit_tx(L2Tx(sender=b"\\x01"*20, nonce=0, data={"op": "inc"}))
    batch = rollup.produce_batch()
    receipt = rollup.prove_and_submit(batch)
    assert receipt.verified
"""

from ethclient.l2.types import (
    L2Tx,
    L2TxType,
    L2State,
    STFResult,
    Batch,
    BatchReceipt,
)
from ethclient.l2.interfaces import (
    StateTransitionFunction,
    DAProvider,
    L1Backend,
    ProofBackend,
)
from ethclient.l2.config import L2Config
from ethclient.l2.state import L2StateStore
from ethclient.l2.runtime import PythonRuntime
from ethclient.l2.sequencer import Sequencer
from ethclient.l2.prover import Groth16ProofBackend
from ethclient.l2.da import LocalDAProvider
from ethclient.l2.da_s3 import S3DAProvider
from ethclient.l2.da_calldata import CalldataDAProvider
from ethclient.l2.da_blob import BlobDAProvider
from ethclient.l2.eth_rpc import EthRPCClient, EthRPCError
from ethclient.l2.l1_backend import InMemoryL1Backend
from ethclient.l2.submitter import BatchSubmitter
from ethclient.l2.persistent_state import L2PersistentStateStore, L2PersistentState, WALEntry
from ethclient.l2.eth_l1_backend import EthL1Backend
from ethclient.l2.native_prover import NativeProverBackend
from ethclient.l2.rollup import Rollup

__all__ = [
    "L2Tx",
    "L2TxType",
    "L2State",
    "STFResult",
    "Batch",
    "BatchReceipt",
    "StateTransitionFunction",
    "DAProvider",
    "L1Backend",
    "ProofBackend",
    "L2Config",
    "L2StateStore",
    "PythonRuntime",
    "Sequencer",
    "Groth16ProofBackend",
    "LocalDAProvider",
    "S3DAProvider",
    "CalldataDAProvider",
    "BlobDAProvider",
    "EthRPCClient",
    "EthRPCError",
    "InMemoryL1Backend",
    "BatchSubmitter",
    "EthL1Backend",
    "NativeProverBackend",
    "L2PersistentStateStore",
    "L2PersistentState",
    "WALEntry",
    "Rollup",
]
