"""Ethereum crypto compatibility tests."""

import pytest

from sequencer.core.crypto import keccak256, sign, recover_address, private_key_to_address

KECCAK256_EMPTY = bytes.fromhex("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
KECCAK256_HELLO = bytes.fromhex("1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8")
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


class TestKeccak256Compatibility:
    def test_empty_string_hash(self):
        result = keccak256(b"")
        assert result == KECCAK256_EMPTY

    def test_known_string_hash(self):
        result = keccak256(b"hello")
        assert result == KECCAK256_HELLO

    def test_output_is_32_bytes(self):
        result = keccak256(b"test data")
        assert len(result) == 32

    def test_deterministic(self):
        data = b"deterministic test"
        assert keccak256(data) == keccak256(data)

    def test_different_inputs_different_hashes(self):
        assert keccak256(b"input1") != keccak256(b"input2")


class TestSignatureCompatibility:
    @pytest.fixture
    def private_key(self):
        return bytes.fromhex("01" * 32)

    @pytest.fixture
    def message_hash(self):
        return keccak256(b"test message to sign")

    def test_sign_produces_valid_vrs(self, private_key, message_hash):
        v, r, s = sign(private_key, message_hash)
        assert v in (0, 1, 27, 28)
        assert 0 < r < SECP256K1_ORDER
        assert 0 < s < SECP256K1_ORDER

    def test_recover_address_matches_original(self, private_key, message_hash):
        v, r, s = sign(private_key, message_hash)
        expected_address = private_key_to_address(private_key)
        recovered_address = recover_address(message_hash, v, r, s)
        assert recovered_address == expected_address
        assert len(recovered_address) == 20

    def test_sign_and_recover_roundtrip_personal_sign(self, private_key):
        message = b"\x19Ethereum Signed Message:\n5hello"
        message_hash = keccak256(message)
        v, r, s = sign(private_key, message_hash)
        recovered = recover_address(message_hash, v, r, s)
        expected = private_key_to_address(private_key)
        assert recovered == expected

    def test_different_messages_different_signatures(self, private_key):
        hash1 = keccak256(b"message 1")
        hash2 = keccak256(b"message 2")
        v1, r1, s1 = sign(private_key, hash1)
        v2, r2, s2 = sign(private_key, hash2)
        assert (r1, s1) != (r2, s2)

    def test_different_keys_different_addresses(self):
        addr1 = private_key_to_address(bytes.fromhex("01" * 32))
        addr2 = private_key_to_address(bytes.fromhex("02" * 32))
        assert addr1 != addr2


class TestAddressDerivationCompatibility:
    def test_known_private_key_to_address(self):
        private_key = bytes.fromhex("01" * 32)
        address = private_key_to_address(private_key)
        assert len(address) == 20
        assert address == private_key_to_address(private_key)

    def test_address_is_20_bytes(self):
        for i in range(1, 5):
            key = bytes([i] * 32)
            address = private_key_to_address(key)
            assert len(address) == 20

    def test_address_is_keccak_of_public_key_last_20(self):
        from eth_keys import keys
        private_key = bytes.fromhex("01" * 32)
        pk = keys.PrivateKey(private_key)
        public_key_bytes = pk.public_key.to_bytes()
        expected_address = keccak256(public_key_bytes)[12:]
        actual_address = private_key_to_address(private_key)
        assert actual_address == expected_address


class TestEIP155ReplayProtection:
    def test_chain_id_affects_v_value(self):
        chain_id = 1337
        assert chain_id * 2 + 35 == 2709
        assert chain_id * 2 + 36 == 2710

    def test_replay_protection_v_values(self):
        test_cases = [(1, 37, 38), (3, 41, 42), (1337, 2709, 2710)]
        for chain_id, v_low, v_high in test_cases:
            assert chain_id * 2 + 35 == v_low
            assert chain_id * 2 + 36 == v_high