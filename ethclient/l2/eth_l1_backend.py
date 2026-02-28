"""EthL1Backend — real Ethereum L1 backend via JSON-RPC.

Deploys the on-chain Groth16 verifier, submits batch proofs as L1 transactions,
and verifies them on-chain. Reuses existing infrastructure:
- EthRPCClient for JSON-RPC transport
- EVMVerifier for bytecode generation + calldata encoding
- Transaction for EIP-1559 tx construction
- ecdsa_sign for signing
"""

from __future__ import annotations

import logging
import time
from typing import Optional

from ethclient.common.crypto import ecdsa_sign, private_key_to_address
from ethclient.common.types import Transaction, TxType
from ethclient.l2.eth_rpc import EthRPCClient, EthRPCError
from ethclient.l2.interfaces import L1Backend
from ethclient.l2.prover import _to_field
from ethclient.zk.evm_verifier import EVMVerifier
from ethclient.zk.types import Proof, VerificationKey

logger = logging.getLogger(__name__)


class EthL1Backend(L1Backend):
    """L1 backend that submits batches to a real Ethereum network.

    Uses EIP-1559 transactions for deployment and batch submission.
    Verifies proofs on-chain via the deployed Groth16 verifier contract.
    """

    def __init__(
        self,
        rpc_url: str,
        private_key: bytes,
        chain_id: int = 1,
        gas_multiplier: float = 1.2,
        receipt_timeout: int = 120,
        confirmations: int = 0,
    ) -> None:
        self._rpc = EthRPCClient(rpc_url)
        self._private_key = private_key
        self._chain_id = chain_id
        self._gas_multiplier = gas_multiplier
        self._receipt_timeout = receipt_timeout
        self._sender = private_key_to_address(private_key)
        self._confirmations = confirmations

        self._verifier_address: Optional[bytes] = None
        self._evm_verifier: Optional[EVMVerifier] = None
        self._verified_batches: dict[int, bytes] = {}
        self._latest_root: Optional[bytes] = None

    def deploy_verifier(self, vk: VerificationKey) -> bytes:
        """Deploy the Groth16 verifier contract to L1."""
        self._evm_verifier = EVMVerifier(vk)
        bytecode = self._evm_verifier.bytecode

        tx = self._build_tx(to=None, data=bytecode)
        raw_tx = self._sign_tx(tx)
        tx_hash = self._rpc.send_raw_transaction(raw_tx)

        receipt = self._rpc.wait_for_receipt(tx_hash, timeout=self._receipt_timeout)
        status = int(receipt.get("status", "0x0"), 16)
        if status != 1:
            raise EthRPCError("Verifier deployment failed: tx reverted")

        contract_addr_hex = receipt.get("contractAddress", "")
        if not contract_addr_hex:
            raise EthRPCError("Verifier deployment failed: no contract address in receipt")

        self._verifier_address = bytes.fromhex(contract_addr_hex.replace("0x", ""))
        logger.info("Deployed verifier at 0x%s", self._verifier_address.hex())
        return self._verifier_address

    def submit_batch(
        self,
        batch_number: int,
        old_root: bytes,
        new_root: bytes,
        proof: Proof,
        tx_commitment: bytes,
        da_commitment: bytes = b"",
    ) -> bytes:
        """Submit a proven batch to L1 via the verifier contract."""
        if self._verifier_address is None or self._evm_verifier is None:
            raise RuntimeError("Verifier not deployed. Call deploy_verifier() first.")

        old_root_int = _to_field(old_root)
        new_root_int = _to_field(new_root)
        tx_commit_int = _to_field(tx_commitment)
        public_inputs = [old_root_int, new_root_int, tx_commit_int]

        calldata = self._evm_verifier.encode_calldata(proof, public_inputs)
        tx = self._build_tx(to=self._verifier_address, data=calldata)
        raw_tx = self._sign_tx(tx)
        tx_hash = self._rpc.send_raw_transaction(raw_tx)

        receipt = self._rpc.wait_for_receipt(tx_hash, timeout=self._receipt_timeout)
        status = int(receipt.get("status", "0x0"), 16)

        if status == 1:
            self._verified_batches[batch_number] = new_root
            self._latest_root = new_root
            logger.info("Batch #%d verified on L1 (tx: 0x%s)", batch_number, tx_hash.hex())
            if self._confirmations > 0:
                self._wait_for_confirmations(tx_hash, self._confirmations)
        else:
            logger.warning("Batch #%d verification FAILED on L1 (tx: 0x%s)", batch_number, tx_hash.hex())

        return tx_hash

    def _wait_for_confirmations(self, tx_hash: bytes, confirmations: int, timeout: int = 600) -> None:
        """Wait for N block confirmations after tx receipt."""
        receipt = self._rpc.get_receipt(tx_hash)
        if receipt is None:
            return
        tx_block = int(receipt.get("blockNumber", "0x0"), 16)
        deadline = time.time() + timeout
        while time.time() < deadline:
            current = self._rpc.get_block_number()
            if current - tx_block >= confirmations:
                return
            time.sleep(12)  # ~1 slot
        logger.warning("Confirmation timeout for tx 0x%s", tx_hash.hex())

    def is_batch_verified(self, batch_number: int) -> bool:
        return batch_number in self._verified_batches

    def get_verified_state_root(self) -> Optional[bytes]:
        return self._latest_root

    def _build_tx(self, to: Optional[bytes], data: bytes) -> Transaction:
        """Build an EIP-1559 transaction."""
        sender_hex = "0x" + self._sender.hex()
        nonce = self._rpc.get_nonce(sender_hex)
        base_fee = self._rpc.get_base_fee()
        priority_fee = self._rpc.get_max_priority_fee()

        max_fee = int((base_fee + priority_fee) * self._gas_multiplier)
        gas_limit = 5_000_000 if to is None else 500_000  # deployment vs call

        return Transaction(
            tx_type=TxType.FEE_MARKET,
            chain_id=self._chain_id,
            nonce=nonce,
            max_priority_fee_per_gas=priority_fee,
            max_fee_per_gas=max_fee,
            gas_limit=gas_limit,
            to=to,
            value=0,
            data=data,
        )

    def _sign_tx(self, tx: Transaction) -> bytes:
        """Sign an EIP-1559 transaction and return the raw encoded bytes."""
        msg_hash = tx.signing_hash()
        v, r, s = ecdsa_sign(msg_hash, self._private_key)
        tx.v = v
        tx.r = r
        tx.s = s
        return tx.encode_rlp()
