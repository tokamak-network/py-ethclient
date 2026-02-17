"""
Merkle Patricia Trie (MPT) implementation.

Implements the Modified Merkle Patricia Trie as specified in the Ethereum Yellow Paper.
Supports get, put, delete operations and computes the state root hash.

Node types:
- Blank: empty node (represented as b"")
- Leaf: [encoded_path, value]
- Extension: [encoded_path, child_hash]
- Branch: [child_0, ..., child_15, value]
"""

from __future__ import annotations

from typing import Optional

from ethclient.common import rlp
from ethclient.common.crypto import keccak256


# ---------------------------------------------------------------------------
# Hex-prefix (HP) encoding for trie paths
# ---------------------------------------------------------------------------

def nibbles_from_bytes(data: bytes) -> list[int]:
    """Convert bytes to a list of nibbles (half-bytes)."""
    nibbles = []
    for byte in data:
        nibbles.append(byte >> 4)
        nibbles.append(byte & 0x0F)
    return nibbles


def bytes_from_nibbles(nibbles: list[int]) -> bytes:
    """Convert a list of nibbles back to bytes. Must have even length."""
    assert len(nibbles) % 2 == 0
    result = bytearray()
    for i in range(0, len(nibbles), 2):
        result.append((nibbles[i] << 4) | nibbles[i + 1])
    return bytes(result)


def hex_prefix_encode(nibbles: list[int], is_leaf: bool) -> bytes:
    """Encode nibbles with hex-prefix encoding.

    The first nibble of the result encodes:
    - bit 0 (0x20): is_leaf flag
    - bit 1 (0x10): odd length flag (padding nibble present)
    """
    flag = 2 if is_leaf else 0

    if len(nibbles) % 2 == 1:
        # Odd: prepend flag + first nibble
        prefix = [flag + 1, nibbles[0]]
        rest = nibbles[1:]
    else:
        # Even: prepend flag, 0
        prefix = [flag, 0]
        rest = nibbles

    return bytes_from_nibbles(prefix + rest)


def hex_prefix_decode(data: bytes) -> tuple[list[int], bool]:
    """Decode hex-prefix encoded data.

    Returns (nibbles, is_leaf).
    """
    nibbles = nibbles_from_bytes(data)
    flag = nibbles[0]
    is_leaf = flag >= 2
    odd = flag % 2 == 1

    if odd:
        return nibbles[1:], is_leaf
    else:
        return nibbles[2:], is_leaf


# ---------------------------------------------------------------------------
# Node types
# ---------------------------------------------------------------------------

EMPTY_NODE: bytes = b""
EMPTY_ROOT = keccak256(rlp.encode(b""))


class TrieNode:
    """In-memory trie node. Nodes are stored by their RLP hash or inline."""
    pass


class BranchNode(TrieNode):
    __slots__ = ("children", "value")

    def __init__(self) -> None:
        self.children: list[object] = [EMPTY_NODE] * 16  # hash or inline node
        self.value: bytes = b""

    def to_rlp_list(self) -> list:
        return list(self.children) + [self.value]


class LeafNode(TrieNode):
    __slots__ = ("path", "value")

    def __init__(self, path: list[int], value: bytes) -> None:
        self.path = path
        self.value = value

    def to_rlp_list(self) -> list:
        return [hex_prefix_encode(self.path, is_leaf=True), self.value]


class ExtensionNode(TrieNode):
    __slots__ = ("path", "child")

    def __init__(self, path: list[int], child: object) -> None:
        self.path = path
        self.child = child  # hash bytes or node

    def to_rlp_list(self) -> list:
        return [hex_prefix_encode(self.path, is_leaf=False), self.child]


# ---------------------------------------------------------------------------
# Merkle Patricia Trie
# ---------------------------------------------------------------------------

class Trie:
    """Merkle Patricia Trie with in-memory node storage.

    Keys and values are bytes. Internally keys are converted to nibble paths.
    """

    def __init__(self) -> None:
        self._db: dict[bytes, bytes] = {}  # hash -> rlp-encoded node
        self._root: object = EMPTY_NODE  # root hash or inline node

    @property
    def root_hash(self) -> bytes:
        """Get the 32-byte root hash."""
        if self._root == EMPTY_NODE:
            return EMPTY_ROOT
        if isinstance(self._root, bytes) and len(self._root) == 32:
            return self._root
        # Inline node - hash it
        encoded = self._encode_node(self._root)
        return keccak256(encoded) if len(encoded) >= 32 else keccak256(encoded)

    def get(self, key: bytes) -> Optional[bytes]:
        """Get value for key, or None if not found."""
        path = nibbles_from_bytes(keccak256(key))
        return self._get(self._root, path)

    def get_raw(self, key: bytes) -> Optional[bytes]:
        """Get value for raw key (no hashing), or None if not found."""
        path = nibbles_from_bytes(key)
        return self._get(self._root, path)

    def put(self, key: bytes, value: bytes) -> None:
        """Insert or update a key-value pair."""
        path = nibbles_from_bytes(keccak256(key))
        self._root = self._put(self._root, path, value)

    def put_raw(self, key: bytes, value: bytes) -> None:
        """Insert with raw key (no hashing)."""
        path = nibbles_from_bytes(key)
        self._root = self._put(self._root, path, value)

    def delete(self, key: bytes) -> None:
        """Delete a key."""
        path = nibbles_from_bytes(keccak256(key))
        self._root = self._delete(self._root, path)

    def delete_raw(self, key: bytes) -> None:
        """Delete with raw key (no hashing)."""
        path = nibbles_from_bytes(key)
        self._root = self._delete(self._root, path)

    # ---------------------------------------------------------------------------
    # Internal: node resolution
    # ---------------------------------------------------------------------------

    def _resolve(self, node_ref: object) -> object:
        """Resolve a node reference (hash or inline) to a TrieNode."""
        if node_ref == EMPTY_NODE:
            return EMPTY_NODE
        if isinstance(node_ref, TrieNode):
            return node_ref
        if isinstance(node_ref, bytes) and len(node_ref) == 32:
            encoded = self._db.get(node_ref)
            if encoded is None:
                return EMPTY_NODE
            return self._decode_node(encoded)
        # Inline encoded (raw bytes that are < 32 bytes)
        if isinstance(node_ref, bytes):
            if len(node_ref) == 0:
                return EMPTY_NODE
            return self._decode_node(node_ref)
        return EMPTY_NODE

    def _store(self, node: TrieNode) -> object:
        """Store a node, returning its hash or inline representation."""
        encoded = self._encode_node(node)
        if len(encoded) < 32:
            return encoded
        h = keccak256(encoded)
        self._db[h] = encoded
        return h

    def _encode_node(self, node: object) -> bytes:
        """RLP-encode a trie node."""
        if node == EMPTY_NODE:
            return rlp.encode(b"")
        if isinstance(node, TrieNode):
            return rlp.encode(node.to_rlp_list())
        if isinstance(node, bytes):
            return node  # already encoded or hash
        raise ValueError(f"Cannot encode node: {type(node)}")

    def _decode_node(self, data: bytes) -> object:
        """Decode RLP data into a TrieNode."""
        items = rlp.decode(data)
        if isinstance(items, bytes):
            return EMPTY_NODE
        if len(items) == 17:
            branch = BranchNode()
            for i in range(16):
                branch.children[i] = items[i]
            branch.value = items[16]
            return branch
        if len(items) == 2:
            path_data = items[0]
            nibbles, is_leaf = hex_prefix_decode(path_data)
            if is_leaf:
                return LeafNode(nibbles, items[1])
            else:
                return ExtensionNode(nibbles, items[1])
        raise rlp.RLPDecodingError(f"Invalid trie node with {len(items)} items")

    # ---------------------------------------------------------------------------
    # Internal: get
    # ---------------------------------------------------------------------------

    def _get(self, node_ref: object, path: list[int]) -> Optional[bytes]:
        node = self._resolve(node_ref)
        if node == EMPTY_NODE:
            return None

        if isinstance(node, LeafNode):
            if node.path == path:
                return node.value
            return None

        if isinstance(node, ExtensionNode):
            prefix_len = len(node.path)
            if path[:prefix_len] != node.path:
                return None
            return self._get(node.child, path[prefix_len:])

        if isinstance(node, BranchNode):
            if len(path) == 0:
                return node.value if node.value else None
            return self._get(node.children[path[0]], path[1:])

        return None

    # ---------------------------------------------------------------------------
    # Internal: put
    # ---------------------------------------------------------------------------

    def _put(self, node_ref: object, path: list[int], value: bytes) -> object:
        node = self._resolve(node_ref)

        if node == EMPTY_NODE:
            return self._store(LeafNode(path, value))

        if isinstance(node, LeafNode):
            return self._put_at_leaf(node, path, value)

        if isinstance(node, ExtensionNode):
            return self._put_at_extension(node, path, value)

        if isinstance(node, BranchNode):
            return self._put_at_branch(node, path, value)

        # Shouldn't get here
        return self._store(LeafNode(path, value))

    def _put_at_leaf(self, node: LeafNode, path: list[int], value: bytes) -> object:
        common = _common_prefix_length(node.path, path)
        old_remaining = node.path[common:]
        new_remaining = path[common:]

        if common == len(node.path) and common == len(path):
            # Same key, update value
            return self._store(LeafNode(path, value))

        branch = BranchNode()

        if len(old_remaining) == 0:
            branch.value = node.value
        else:
            old_leaf = LeafNode(old_remaining[1:], node.value)
            branch.children[old_remaining[0]] = self._store(old_leaf)

        if len(new_remaining) == 0:
            branch.value = value
        else:
            new_leaf = LeafNode(new_remaining[1:], value)
            branch.children[new_remaining[0]] = self._store(new_leaf)

        if common > 0:
            ext = ExtensionNode(path[:common], self._store(branch))
            return self._store(ext)

        return self._store(branch)

    def _put_at_extension(self, node: ExtensionNode, path: list[int], value: bytes) -> object:
        common = _common_prefix_length(node.path, path)
        remaining_ext = node.path[common:]
        remaining_path = path[common:]

        if common == len(node.path):
            # Full match of extension path
            new_child = self._put(node.child, remaining_path, value)
            ext = ExtensionNode(node.path, new_child)
            return self._store(ext)

        branch = BranchNode()

        if len(remaining_ext) == 1:
            branch.children[remaining_ext[0]] = node.child
        else:
            sub_ext = ExtensionNode(remaining_ext[1:], node.child)
            branch.children[remaining_ext[0]] = self._store(sub_ext)

        if len(remaining_path) == 0:
            branch.value = value
        else:
            new_leaf = LeafNode(remaining_path[1:], value)
            branch.children[remaining_path[0]] = self._store(new_leaf)

        if common > 0:
            ext = ExtensionNode(path[:common], self._store(branch))
            return self._store(ext)

        return self._store(branch)

    def _put_at_branch(self, node: BranchNode, path: list[int], value: bytes) -> object:
        new_branch = BranchNode()
        new_branch.children = list(node.children)
        new_branch.value = node.value

        if len(path) == 0:
            new_branch.value = value
        else:
            new_branch.children[path[0]] = self._put(
                node.children[path[0]], path[1:], value
            )

        return self._store(new_branch)

    # ---------------------------------------------------------------------------
    # Internal: delete
    # ---------------------------------------------------------------------------

    def _delete(self, node_ref: object, path: list[int]) -> object:
        node = self._resolve(node_ref)

        if node == EMPTY_NODE:
            return EMPTY_NODE

        if isinstance(node, LeafNode):
            if node.path == path:
                return EMPTY_NODE
            return node_ref

        if isinstance(node, ExtensionNode):
            prefix_len = len(node.path)
            if path[:prefix_len] != node.path:
                return node_ref
            new_child = self._delete(node.child, path[prefix_len:])
            if new_child == EMPTY_NODE:
                return EMPTY_NODE
            child_node = self._resolve(new_child)
            if isinstance(child_node, LeafNode):
                merged = LeafNode(node.path + child_node.path, child_node.value)
                return self._store(merged)
            if isinstance(child_node, ExtensionNode):
                merged = ExtensionNode(
                    node.path + child_node.path, child_node.child
                )
                return self._store(merged)
            ext = ExtensionNode(node.path, new_child)
            return self._store(ext)

        if isinstance(node, BranchNode):
            return self._delete_at_branch(node, path)

        return node_ref

    def _delete_at_branch(self, node: BranchNode, path: list[int]) -> object:
        new_branch = BranchNode()
        new_branch.children = list(node.children)
        new_branch.value = node.value

        if len(path) == 0:
            new_branch.value = b""
        else:
            new_child = self._delete(node.children[path[0]], path[1:])
            new_branch.children[path[0]] = new_child

        # Count remaining children
        remaining = []
        for i in range(16):
            if new_branch.children[i] != EMPTY_NODE:
                remaining.append(i)

        has_value = new_branch.value != b""

        if len(remaining) == 0 and not has_value:
            return EMPTY_NODE

        if len(remaining) == 1 and not has_value:
            idx = remaining[0]
            child = self._resolve(new_branch.children[idx])
            if isinstance(child, LeafNode):
                merged = LeafNode([idx] + child.path, child.value)
                return self._store(merged)
            if isinstance(child, ExtensionNode):
                merged = ExtensionNode([idx] + child.path, child.child)
                return self._store(merged)
            # Child is a branch - wrap in extension
            ext = ExtensionNode([idx], new_branch.children[idx])
            return self._store(ext)

        if len(remaining) == 0 and has_value:
            leaf = LeafNode([], new_branch.value)
            return self._store(leaf)

        return self._store(new_branch)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _common_prefix_length(a: list[int], b: list[int]) -> int:
    """Return the length of the common prefix between two nibble lists."""
    max_len = min(len(a), len(b))
    for i in range(max_len):
        if a[i] != b[i]:
            return i
    return max_len


def compute_trie_root(items: dict[bytes, bytes], use_raw_keys: bool = False) -> bytes:
    """Compute a trie root hash from a dict of key-value pairs.

    If use_raw_keys=True, keys are used directly as nibble paths.
    Otherwise keys are keccak256-hashed (standard state trie behavior).
    """
    trie = Trie()
    for key, value in items.items():
        if use_raw_keys:
            trie.put_raw(key, value)
        else:
            trie.put(key, value)
    return trie.root_hash


def ordered_trie_root(values: list[bytes]) -> bytes:
    """Compute a trie root from an ordered list of values.

    Keys are RLP-encoded indices (0, 1, 2, ...).
    Used for transaction and receipt tries.
    """
    trie = Trie()
    for i, value in enumerate(values):
        key = rlp.encode(i)
        trie.put_raw(key, value)
    return trie.root_hash
