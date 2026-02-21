"""Tests for snap sync state machine and response handlers."""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from ethclient.common import rlp
from ethclient.common.crypto import keccak256
from ethclient.networking.snap.protocol import SnapMsg
from ethclient.networking.snap.messages import (
    AccountRangeMessage,
    StorageRangesMessage,
    ByteCodesMessage,
    TrieNodesMessage,
)
from ethclient.networking.sync.snap_sync import (
    SnapSync,
    SnapSyncState,
    SyncPhase,
    ZERO_HASH,
    MAX_HASH,
    EMPTY_CODE_HASH,
    EMPTY_TRIE_ROOT,
    SNAP_TIMEOUT,
    PEER_FAIL_BAN_SECONDS,
    MAX_STALE_SNAP_PEER_LAG_BLOCKS,
)
from ethclient.storage.memory_backend import MemoryBackend


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_slim_account(nonce=0, balance=0, storage_root=None, code_hash=None):
    """Create RLP-encoded slim account."""
    sr = storage_root or EMPTY_TRIE_ROOT
    ch = code_hash or EMPTY_CODE_HASH
    return rlp.encode([nonce, balance, sr, ch])


def _make_mock_peer(connected=True, snap_supported=True):
    """Create a mock PeerConnection."""
    peer = MagicMock()
    peer.connected = connected
    peer.snap_supported = snap_supported
    peer.send_snap_message = AsyncMock()
    peer.remote_id = b"\x01" * 64
    return peer


# ---------------------------------------------------------------------------
# State machine tests
# ---------------------------------------------------------------------------

class TestSnapSyncState:
    def test_initial_state(self):
        state = SnapSyncState()
        assert state.phase == SyncPhase.IDLE
        assert state.accounts_downloaded == 0
        assert state.storage_downloaded == 0
        assert state.codes_downloaded == 0
        assert state.nodes_healed == 0

    def test_request_id_increment(self):
        state = SnapSyncState()
        assert state.next_request_id() == 1
        assert state.next_request_id() == 2
        assert state.next_request_id() == 3

    def test_storage_queue(self):
        state = SnapSyncState()
        state.storage_queue.append((b"\x01" * 32, b"\x02" * 32))
        assert len(state.storage_queue) == 1

    def test_code_queue(self):
        state = SnapSyncState()
        state.code_queue.append(keccak256(b"code"))
        assert len(state.code_queue) == 1


class TestSyncPhases:
    def test_phase_transitions(self):
        """Verify all valid phase values."""
        assert SyncPhase.IDLE.name == "IDLE"
        assert SyncPhase.ACCOUNT_DOWNLOAD.name == "ACCOUNT_DOWNLOAD"
        assert SyncPhase.STORAGE_DOWNLOAD.name == "STORAGE_DOWNLOAD"
        assert SyncPhase.BYTECODE_DOWNLOAD.name == "BYTECODE_DOWNLOAD"
        assert SyncPhase.TRIE_HEALING.name == "TRIE_HEALING"
        assert SyncPhase.COMPLETE.name == "COMPLETE"


# ---------------------------------------------------------------------------
# Response handler tests
# ---------------------------------------------------------------------------

class TestResponseHandlers:
    def test_handle_account_range(self):
        syncer = SnapSync()

        accounts = [
            (b"\x01" * 32, _make_slim_account(nonce=1, balance=100)),
            (b"\x02" * 32, _make_slim_account(nonce=2, balance=200)),
        ]
        msg = AccountRangeMessage(request_id=5, accounts=accounts, proof=[])

        # Set up an event that the handler should trigger
        event = asyncio.Event()
        syncer._response_events[5] = event

        syncer.handle_account_range(msg.encode())

        assert event.is_set()
        assert 5 in syncer._account_responses
        response = syncer._account_responses[5]
        assert len(response.accounts) == 2
        assert response.request_id == 5

    def test_handle_storage_ranges(self):
        syncer = SnapSync()

        slots = [[(b"\xa1" * 32, b"\x01")]]
        msg = StorageRangesMessage(request_id=10, slots=slots, proof=[])

        event = asyncio.Event()
        syncer._response_events[10] = event

        syncer.handle_storage_ranges(msg.encode())

        assert event.is_set()
        assert 10 in syncer._storage_responses

    def test_handle_byte_codes(self):
        syncer = SnapSync()

        codes = [b"\x60\x00\x60\x00\xf3"]
        msg = ByteCodesMessage(request_id=20, codes=codes)

        event = asyncio.Event()
        syncer._response_events[20] = event

        syncer.handle_byte_codes(msg.encode())

        assert event.is_set()
        assert 20 in syncer._bytecode_responses
        response = syncer._bytecode_responses[20]
        assert len(response.codes) == 1

    def test_handle_trie_nodes(self):
        syncer = SnapSync()

        nodes = [b"\xc0" * 32, b"\xc1" * 32]
        msg = TrieNodesMessage(request_id=30, nodes=nodes)

        event = asyncio.Event()
        syncer._response_events[30] = event

        syncer.handle_trie_nodes(msg.encode())

        assert event.is_set()
        assert 30 in syncer._trie_node_responses

    def test_handler_without_event(self):
        """Stale responses without pending events should be dropped."""
        syncer = SnapSync()
        msg = AccountRangeMessage(request_id=99, accounts=[], proof=[])
        syncer.handle_account_range(msg.encode())  # should not raise
        assert 99 not in syncer._account_responses


# ---------------------------------------------------------------------------
# Properties tests
# ---------------------------------------------------------------------------

class TestSnapSyncProperties:
    def test_is_syncing_idle(self):
        syncer = SnapSync()
        assert not syncer.is_syncing

    def test_is_syncing_active(self):
        syncer = SnapSync()
        syncer.state.phase = SyncPhase.ACCOUNT_DOWNLOAD
        assert syncer.is_syncing

    def test_is_syncing_complete(self):
        syncer = SnapSync()
        syncer.state.phase = SyncPhase.COMPLETE
        assert not syncer.is_syncing

    def test_progress(self):
        syncer = SnapSync()
        syncer.state.accounts_downloaded = 100
        syncer.state.storage_downloaded = 50
        syncer.state.codes_downloaded = 10
        syncer.state.nodes_healed = 5

        progress = syncer.progress
        assert progress["accounts"] == 100
        assert progress["storage"] == 50
        assert progress["codes"] == 10
        assert progress["healed"] == 5


# ---------------------------------------------------------------------------
# Store integration
# ---------------------------------------------------------------------------

class TestSnapSyncStore:
    def test_store_snap_account(self):
        store = MemoryBackend()
        syncer = SnapSync(store=store)

        acct_hash = b"\x01" * 32
        acct_rlp = _make_slim_account(nonce=5, balance=1000)
        store.put_snap_account(acct_hash, acct_rlp)

        assert store._snap_accounts[acct_hash] == acct_rlp

    def test_store_snap_storage(self):
        store = MemoryBackend()
        acct_hash = b"\x01" * 32
        slot_hash = b"\x02" * 32
        value = b"\x42"

        store.put_snap_storage(acct_hash, slot_hash, value)
        assert store._snap_storage[(acct_hash, slot_hash)] == value

    def test_store_snap_code(self):
        store = MemoryBackend()
        code = b"\x60\x00\x60\x00\xf3"
        code_hash = keccak256(code)

        store.put_snap_code(code_hash, code)
        assert store.get_code(code_hash) == code

    def test_store_progress(self):
        store = MemoryBackend()
        assert store.get_snap_progress() is None

        progress = {"phase": "ACCOUNT_DOWNLOAD", "accounts_downloaded": 42}
        store.put_snap_progress(progress)
        assert store.get_snap_progress() == progress


# ---------------------------------------------------------------------------
# Account parsing
# ---------------------------------------------------------------------------

class TestAccountParsing:
    def test_account_with_storage_enqueues(self):
        """Accounts with non-empty storage should be enqueued for storage download."""
        syncer = SnapSync()
        state = syncer.state
        state.phase = SyncPhase.ACCOUNT_DOWNLOAD

        storage_root = keccak256(b"some storage root")
        acct_rlp = _make_slim_account(storage_root=storage_root)

        # Simulate what _download_accounts does with an account
        acct_fields = rlp.decode_list(acct_rlp)
        sr = acct_fields[2]
        ch = acct_fields[3]

        if sr and sr != EMPTY_TRIE_ROOT:
            state.storage_queue.append((b"\x01" * 32, sr))
        if ch and ch != EMPTY_CODE_HASH:
            state.code_queue.append(ch)

        assert len(state.storage_queue) == 1
        assert len(state.code_queue) == 0  # default code_hash is empty

    def test_account_with_code_enqueues(self):
        """Accounts with non-empty code should be enqueued for bytecode download."""
        syncer = SnapSync()
        state = syncer.state

        code_hash = keccak256(b"contract code")
        acct_rlp = _make_slim_account(code_hash=code_hash)

        acct_fields = rlp.decode_list(acct_rlp)
        ch = acct_fields[3]

        if ch and ch != EMPTY_CODE_HASH:
            state.code_queue.append(ch)

        assert len(state.code_queue) == 1
        assert state.code_queue[0] == code_hash

    def test_empty_account_no_enqueue(self):
        """Empty accounts should not enqueue anything."""
        syncer = SnapSync()
        state = syncer.state

        acct_rlp = _make_slim_account()

        acct_fields = rlp.decode_list(acct_rlp)
        sr = acct_fields[2]
        ch = acct_fields[3]

        if sr and sr != EMPTY_TRIE_ROOT:
            state.storage_queue.append((b"\x01" * 32, sr))
        if ch and ch != EMPTY_CODE_HASH:
            state.code_queue.append(ch)

        assert len(state.storage_queue) == 0
        assert len(state.code_queue) == 0


class TestPeerRefresh:
    @pytest.mark.asyncio
    async def test_wait_for_connected_peers_uses_provider(self, monkeypatch):
        syncer = SnapSync()
        disconnected_peer = _make_mock_peer(connected=False, snap_supported=True)
        connected_peer = _make_mock_peer(connected=True, snap_supported=True)

        calls = {"count": 0}

        def provider():
            calls["count"] += 1
            if calls["count"] < 3:
                return [disconnected_peer]
            return [connected_peer]

        syncer._peer_provider = provider
        monkeypatch.setattr(
            "ethclient.networking.sync.snap_sync.PEER_WAIT_TIMEOUT",
            0.2,
        )
        monkeypatch.setattr(
            "ethclient.networking.sync.snap_sync.PEER_WAIT_POLL_INTERVAL",
            0.01,
        )

        assert await syncer._wait_for_connected_peers([disconnected_peer], "account")

    @pytest.mark.asyncio
    async def test_wait_for_connected_peers_timeout(self, monkeypatch):
        syncer = SnapSync()
        disconnected_peer = _make_mock_peer(connected=False, snap_supported=True)
        syncer._peer_provider = lambda: [disconnected_peer]

        monkeypatch.setattr(
            "ethclient.networking.sync.snap_sync.PEER_WAIT_TIMEOUT",
            0.05,
        )
        monkeypatch.setattr(
            "ethclient.networking.sync.snap_sync.PEER_WAIT_POLL_INTERVAL",
            0.01,
        )

        assert not await syncer._wait_for_connected_peers([disconnected_peer], "account")


class TestPeerHealth:
    def test_snap_sync_default_no_proof_pool(self):
        syncer = SnapSync()
        assert syncer._proof_pool is None

    def test_adaptive_timeout_uses_rtt(self):
        syncer = SnapSync()
        peer = _make_mock_peer()
        health = syncer._get_peer_health(peer)
        assert syncer._adaptive_timeout(peer) == SNAP_TIMEOUT
        health.avg_rtt = 5.0
        assert syncer._adaptive_timeout(peer) >= SNAP_TIMEOUT

    def test_peer_ban_on_repeated_timeout(self):
        syncer = SnapSync()
        peer = _make_mock_peer()
        syncer._record_timeout(peer)
        syncer._record_timeout(peer)
        syncer._record_timeout(peer)
        health = syncer._get_peer_health(peer)
        assert health.banned_until > 0
        assert health.banned_until - health.cooldown_until <= PEER_FAIL_BAN_SECONDS

    def test_connected_peers_filters_stale_head(self):
        syncer = SnapSync()
        syncer.state.target_block = 1_000

        stale_peer = _make_mock_peer(connected=True, snap_supported=True)
        stale_peer.best_block_number = 800

        fresh_peer = _make_mock_peer(connected=True, snap_supported=True)
        fresh_peer.best_block_number = 1_000 - MAX_STALE_SNAP_PEER_LAG_BLOCKS + 1

        zero_peer = _make_mock_peer(connected=True, snap_supported=True)
        zero_peer.best_block_number = 0

        peers = syncer._connected_peers([stale_peer, fresh_peer, zero_peer])

        assert stale_peer not in peers
        assert fresh_peer in peers
        assert zero_peer in peers

    @pytest.mark.asyncio
    async def test_request_snap_aborts_when_peer_disconnected(self, monkeypatch):
        syncer = SnapSync()
        peer = _make_mock_peer()

        async def send_and_disconnect(*_args, **_kwargs):
            peer.connected = False

        peer.send_snap_message = AsyncMock(side_effect=send_and_disconnect)
        monkeypatch.setattr(
            "ethclient.networking.sync.snap_sync.SNAP_TIMEOUT",
            30.0,
        )

        result = await asyncio.wait_for(
            syncer._request_snap(
                peer=peer,
                req_id=1,
                relative_code=SnapMsg.GET_ACCOUNT_RANGE,
                payload=b"\xc0",
                response_buffer=syncer._account_responses,
                request_name="AccountRange",
            ),
            timeout=0.5,
        )

        assert result is None
        assert 1 not in syncer._response_events


class TestProgressRestore:
    def test_restore_progress_when_target_matches(self):
        store = MemoryBackend()
        store.put_snap_progress({
            "target_block": 1234,
            "account_cursor": ("00" * 31) + "ff",
            "accounts_downloaded": 99,
            "storage_downloaded": 7,
            "codes_downloaded": 5,
            "nodes_healed": 3,
        })
        syncer = SnapSync(store=store)
        syncer.state.target_block = 1234

        syncer._restore_progress()

        assert syncer.state.accounts_downloaded == 99
        assert syncer.state.storage_downloaded == 7
        assert syncer.state.codes_downloaded == 5
        assert syncer.state.nodes_healed == 3
        assert syncer.state.account_cursor.hex().endswith("ff")
