from typing import Any, Callable, Dict, List, Optional
from sequencer.core.crypto import keccak256


class MempoolError(Exception):
    pass


class NonceTooLow(MempoolError):
    pass


class UnderpricedReplacement(MempoolError):
    pass


class InsufficientFunds(MempoolError):
    """Raised when sender does not have enough balance for transaction."""
    pass


class Mempool:
    def __init__(self, max_size: int = 4096):
        self.max_size = max_size
        self.txs: Dict[bytes, Any] = {}
        self.by_sender: Dict[bytes, Dict[int, bytes]] = {}

    def add(self, tx: Any, current_nonce: int) -> bool:
        sender = tx.sender
        tx_hash = keccak256(tx.encode())
        tx_nonce = tx.nonce
        
        if tx_nonce < current_nonce:
            raise NonceTooLow(f"nonce too low: current={current_nonce}, tx={tx_nonce}")
        
        if sender in self.by_sender and self.by_sender[sender]:
            existing_nonces = self.by_sender[sender]
            
            if tx_nonce in existing_nonces:
                old_hash = existing_nonces[tx_nonce]
                old_tx = self.txs[old_hash]
                
                old_fee = self._get_fee(old_tx)
                new_fee = self._get_fee(tx)
                
                if new_fee >= old_fee * 11 // 10:
                    self._remove_tx(old_hash, sender, tx_nonce)
                else:
                    raise UnderpricedReplacement(f"replacement transaction underpriced: need >= {old_fee * 11 // 10}, got {new_fee}")
            
            if len(self.txs) >= self.max_size:
                self._evict_lowest_fee()
        else:
            if len(self.txs) >= self.max_size:
                self._evict_lowest_fee()
            self.by_sender[sender] = {}
        
        self.txs[tx_hash] = tx
        if sender not in self.by_sender:
            self.by_sender[sender] = {}
        self.by_sender[sender][tx_nonce] = tx_hash
        return True

    def get_pending(self, max_txs: int, current_nonces: Optional[Dict[bytes, int]] = None) -> List[Any]:
        result = []
        sender_txs: Dict[bytes, List[Any]] = {}
        
        for sender, nonces in self.by_sender.items():
            current_nonce = current_nonces.get(sender, 0) if current_nonces else 0
            txs = []
            sorted_nonces = sorted(nonces.keys())
            
            expected_nonce = current_nonce
            for nonce in sorted_nonces:
                if nonce == expected_nonce:
                    tx_hash = nonces[nonce]
                    if tx_hash in self.txs:
                        txs.append(self.txs[tx_hash])
                    expected_nonce += 1
                elif nonce > expected_nonce:
                    break
            
            if txs:
                sender_txs[sender] = txs
        
        while sender_txs and len(result) < max_txs:
            best_sender = None
            best_fee = -1
            
            for sender, txs in sender_txs.items():
                if txs:
                    fee = self._get_fee(txs[0])
                    if fee > best_fee:
                        best_fee = fee
                        best_sender = sender
            
            if best_sender and sender_txs[best_sender]:
                result.append(sender_txs[best_sender].pop(0))
                if not sender_txs[best_sender]:
                    del sender_txs[best_sender]
            else:
                break
        
        return result

    def remove(self, tx_hash: bytes) -> None:
        if tx_hash not in self.txs:
            return
        
        tx = self.txs[tx_hash]
        sender = tx.sender
        nonce = tx.nonce
        
        self._remove_tx(tx_hash, sender, nonce)

    def _remove_tx(self, tx_hash: bytes, sender: bytes, nonce: int) -> None:
        if tx_hash in self.txs:
            del self.txs[tx_hash]
        if sender in self.by_sender and nonce in self.by_sender[sender]:
            del self.by_sender[sender][nonce]
            if not self.by_sender[sender]:
                del self.by_sender[sender]

    def _get_fee(self, tx: Any) -> int:
        if hasattr(tx, 'max_priority_fee_per_gas'):
            return tx.max_priority_fee_per_gas
        elif hasattr(tx, 'gas_price'):
            return tx.gas_price
        return 0

    def _evict_lowest_fee(self) -> None:
        if not self.txs:
            return
        
        lowest_hash = min(self.txs.keys(), key=lambda h: self._get_fee(self.txs[h]))
        tx = self.txs[lowest_hash]
        self._remove_tx(lowest_hash, tx.sender, tx.nonce)

    def __len__(self) -> int:
        return len(self.txs)

    def clear(self) -> None:
        self.txs.clear()
        self.by_sender.clear()