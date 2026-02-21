"""CREATE2 address computation utilities (EIP-1014).

CREATE2 allows deterministic contract address generation before deployment.
The address is computed as:
    address = keccak256(0xff ++ sender_address ++ salt ++ keccak256(init_code))[12:]

Reference: https://eips.ethereum.org/EIPS/eip-1014
"""

from eth_utils import keccak


def compute_create2_address(
    sender: bytes,
    salt: bytes,
    init_code: bytes,
) -> bytes:
    """
    Compute CREATE2 contract address.

    The contract address is the last 20 bytes of:
        keccak256(0xff ++ sender ++ salt ++ keccak256(init_code))

    Args:
        sender: 20-byte deployer address
        salt: 32-byte salt value (can be any 32 bytes)
        init_code: Contract initialization code (constructor bytecode)

    Returns:
        20-byte predicted contract address (before deployment)

    Raises:
        ValueError: If sender is not 20 bytes or salt is not 32 bytes

    Example:
        >>> sender = bytes.fromhex("deadbeef" * 5)
        >>> salt = bytes(32)  # 32 zero bytes
        >>> init_code = bytes.fromhex("602a60005260206000f3")
        >>> addr = compute_create2_address(sender, salt, init_code)
        >>> len(addr)
        20

    Note:
        - The address is deterministic: same sender + salt + init_code always
          produces the same address, regardless of when or where deployed
        - The init_code includes the constructor arguments, so different
          arguments will produce different addresses
        - CREATE2 allows "counterfactual" deployment: contracts can be created
          at addresses that are known in advance
    """
    if len(sender) != 20:
        raise ValueError(f"Sender must be 20 bytes, got {len(sender)}")
    if len(salt) != 32:
        raise ValueError(f"Salt must be 32 bytes, got {len(salt)}")

    init_code_hash = keccak(init_code)
    preimage = b'\xff' + sender + salt + init_code_hash
    return keccak(preimage)[12:]


def compute_create2_address_with_code_hash(
    sender: bytes,
    salt: bytes,
    init_code_hash: bytes,
) -> bytes:
    """
    Compute CREATE2 address with pre-computed init_code hash.

    Useful when you only have the hash of init_code (e.g., from a contract
    that verifies CREATE2 deployments without storing the full init_code).

    Args:
        sender: 20-byte deployer address
        salt: 32-byte salt value
        init_code_hash: 32-byte keccak256 hash of init_code

    Returns:
        20-byte predicted contract address

    Raises:
        ValueError: If lengths are incorrect

    Example:
        >>> from eth_utils import keccak
        >>> sender = bytes.fromhex("deadbeef" * 5)
        >>> salt = bytes(32)
        >>> init_code = bytes.fromhex("602a60005260206000f3")
        >>> init_code_hash = keccak(init_code)
        >>> addr1 = compute_create2_address(sender, salt, init_code)
        >>> addr2 = compute_create2_address_with_code_hash(sender, salt, init_code_hash)
        >>> addr1 == addr2
        True
    """
    if len(sender) != 20:
        raise ValueError(f"Sender must be 20 bytes, got {len(sender)}")
    if len(salt) != 32:
        raise ValueError(f"Salt must be 32 bytes, got {len(salt)}")
    if len(init_code_hash) != 32:
        raise ValueError(f"Init code hash must be 32 bytes, got {len(init_code_hash)}")

    preimage = b'\xff' + sender + salt + init_code_hash
    return keccak(preimage)[12:]


def compute_create_address(sender: bytes, nonce: int) -> bytes:
    """
    Compute CREATE (nonce-based) contract address.

    The contract address is the last 20 bytes of:
        keccak256(rlp([sender, nonce]))

    Args:
        sender: 20-byte deployer address
        nonce: Sender's nonce (integer)

    Returns:
        20-byte contract address

    Raises:
        ValueError: If sender is not 20 bytes

    Example:
        >>> sender = bytes.fromhex("deadbeef" * 5)
        >>> addr = compute_create_address(sender, 0)
        >>> len(addr)
        20
    """
    import rlp

    if len(sender) != 20:
        raise ValueError(f"Sender must be 20 bytes, got {len(sender)}")

    encoded = rlp.encode([sender, nonce])
    return keccak(encoded)[12:]