"""
Chain configuration and genesis block handling.

Supports Ethereum mainnet, Sepolia, and Holesky testnets.
Tracks hardfork activation blocks/timestamps.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional

from ethclient.common import rlp
from ethclient.common.crypto import keccak256
from ethclient.common.types import (
    Account,
    Block,
    BlockHeader,
    EMPTY_TRIE_ROOT,
    ZERO_HASH,
    ZERO_ADDRESS,
    BLOOM_BYTE_SIZE,
)


# ---------------------------------------------------------------------------
# Hardfork schedule
# ---------------------------------------------------------------------------

@dataclass
class ChainConfig:
    chain_id: int = 1
    chain_name: str = "mainnet"

    # Block-based forks
    homestead_block: Optional[int] = None
    eip150_block: Optional[int] = None         # Tangerine Whistle
    eip155_block: Optional[int] = None         # Spurious Dragon
    eip158_block: Optional[int] = None         # Spurious Dragon
    byzantium_block: Optional[int] = None
    constantinople_block: Optional[int] = None
    petersburg_block: Optional[int] = None
    istanbul_block: Optional[int] = None
    muir_glacier_block: Optional[int] = None
    berlin_block: Optional[int] = None
    london_block: Optional[int] = None
    arrow_glacier_block: Optional[int] = None
    gray_glacier_block: Optional[int] = None

    # Timestamp-based forks (post-merge)
    merge_netsplit_block: Optional[int] = None
    shanghai_time: Optional[int] = None
    cancun_time: Optional[int] = None
    prague_time: Optional[int] = None

    # Terminal total difficulty for the merge
    terminal_total_difficulty: Optional[int] = None

    def is_homestead(self, block_number: int) -> bool:
        return self.homestead_block is not None and block_number >= self.homestead_block

    def is_eip155(self, block_number: int) -> bool:
        return self.eip155_block is not None and block_number >= self.eip155_block

    def is_eip158(self, block_number: int) -> bool:
        return self.eip158_block is not None and block_number >= self.eip158_block

    def is_byzantium(self, block_number: int) -> bool:
        return self.byzantium_block is not None and block_number >= self.byzantium_block

    def is_constantinople(self, block_number: int) -> bool:
        return self.constantinople_block is not None and block_number >= self.constantinople_block

    def is_istanbul(self, block_number: int) -> bool:
        return self.istanbul_block is not None and block_number >= self.istanbul_block

    def is_berlin(self, block_number: int) -> bool:
        return self.berlin_block is not None and block_number >= self.berlin_block

    def is_london(self, block_number: int) -> bool:
        return self.london_block is not None and block_number >= self.london_block

    def is_shanghai(self, timestamp: int) -> bool:
        return self.shanghai_time is not None and timestamp >= self.shanghai_time

    def is_cancun(self, timestamp: int) -> bool:
        return self.cancun_time is not None and timestamp >= self.cancun_time

    def is_prague(self, timestamp: int) -> bool:
        return self.prague_time is not None and timestamp >= self.prague_time


# ---------------------------------------------------------------------------
# Well-known chain configs
# ---------------------------------------------------------------------------

MAINNET_CONFIG = ChainConfig(
    chain_id=1,
    chain_name="mainnet",
    homestead_block=1_150_000,
    eip150_block=2_463_000,
    eip155_block=2_675_000,
    eip158_block=2_675_000,
    byzantium_block=4_370_000,
    constantinople_block=7_280_000,
    petersburg_block=7_280_000,
    istanbul_block=9_069_000,
    muir_glacier_block=9_200_000,
    berlin_block=12_244_000,
    london_block=12_965_000,
    arrow_glacier_block=13_773_000,
    gray_glacier_block=15_050_000,
    terminal_total_difficulty=58_750_000_000_000_000_000_000,
    shanghai_time=1_681_338_455,
    cancun_time=1_710_338_135,
)

SEPOLIA_CONFIG = ChainConfig(
    chain_id=11155111,
    chain_name="sepolia",
    homestead_block=0,
    eip150_block=0,
    eip155_block=0,
    eip158_block=0,
    byzantium_block=0,
    constantinople_block=0,
    petersburg_block=0,
    istanbul_block=0,
    berlin_block=0,
    london_block=0,
    terminal_total_difficulty=17_000_000_000_000_000,
    shanghai_time=1_677_557_088,
    cancun_time=1_706_655_072,
)

HOLESKY_CONFIG = ChainConfig(
    chain_id=17000,
    chain_name="holesky",
    homestead_block=0,
    eip150_block=0,
    eip155_block=0,
    eip158_block=0,
    byzantium_block=0,
    constantinople_block=0,
    petersburg_block=0,
    istanbul_block=0,
    berlin_block=0,
    london_block=0,
    terminal_total_difficulty=0,
    shanghai_time=1_696_000_704,
    cancun_time=1_707_305_664,
)


CHAIN_CONFIGS: dict[int, ChainConfig] = {
    1: MAINNET_CONFIG,
    11155111: SEPOLIA_CONFIG,
    17000: HOLESKY_CONFIG,
}


# ---------------------------------------------------------------------------
# Genesis
# ---------------------------------------------------------------------------

@dataclass
class GenesisAlloc:
    address: bytes  # 20 bytes
    balance: int = 0
    nonce: int = 0
    code: bytes = b""
    storage: dict[bytes, bytes] = field(default_factory=dict)


@dataclass
class Genesis:
    config: ChainConfig = field(default_factory=ChainConfig)
    nonce: int = 0
    timestamp: int = 0
    extra_data: bytes = b""
    gas_limit: int = 0
    difficulty: int = 0
    mix_hash: bytes = field(default_factory=lambda: ZERO_HASH)
    coinbase: bytes = field(default_factory=lambda: ZERO_ADDRESS)
    alloc: list[GenesisAlloc] = field(default_factory=list)
    base_fee_per_gas: Optional[int] = None
    excess_blob_gas: Optional[int] = None
    blob_gas_used: Optional[int] = None

    def to_block(self) -> Block:
        """Convert genesis to the genesis block (block 0)."""
        header = BlockHeader(
            parent_hash=ZERO_HASH,
            ommers_hash=keccak256(rlp.encode([])),
            coinbase=self.coinbase,
            state_root=ZERO_HASH,  # computed from alloc
            transactions_root=EMPTY_TRIE_ROOT,
            receipts_root=EMPTY_TRIE_ROOT,
            logs_bloom=b"\x00" * BLOOM_BYTE_SIZE,
            difficulty=self.difficulty,
            number=0,
            gas_limit=self.gas_limit,
            gas_used=0,
            timestamp=self.timestamp,
            extra_data=self.extra_data,
            mix_hash=self.mix_hash,
            nonce=self.nonce.to_bytes(8, "big"),
            base_fee_per_gas=self.base_fee_per_gas,
        )
        if self.excess_blob_gas is not None:
            header.blob_gas_used = self.blob_gas_used or 0
            header.excess_blob_gas = self.excess_blob_gas
            header.parent_beacon_block_root = ZERO_HASH
        return Block(header=header)

    @classmethod
    def from_json(cls, data: dict) -> Genesis:
        """Parse a genesis JSON (geth-style genesis.json format)."""
        config_data = data.get("config", {})
        chain_config = ChainConfig(
            chain_id=config_data.get("chainId", 1),
            homestead_block=config_data.get("homesteadBlock"),
            eip150_block=config_data.get("eip150Block"),
            eip155_block=config_data.get("eip155Block"),
            eip158_block=config_data.get("eip158Block"),
            byzantium_block=config_data.get("byzantiumBlock"),
            constantinople_block=config_data.get("constantinopleBlock"),
            petersburg_block=config_data.get("petersburgBlock"),
            istanbul_block=config_data.get("istanbulBlock"),
            muir_glacier_block=config_data.get("muirGlacierBlock"),
            berlin_block=config_data.get("berlinBlock"),
            london_block=config_data.get("londonBlock"),
            arrow_glacier_block=config_data.get("arrowGlacierBlock"),
            gray_glacier_block=config_data.get("grayGlacierBlock"),
            merge_netsplit_block=config_data.get("mergeNetsplitBlock"),
            terminal_total_difficulty=config_data.get("terminalTotalDifficulty"),
            shanghai_time=config_data.get("shanghaiTime"),
            cancun_time=config_data.get("cancunTime"),
            prague_time=config_data.get("pragueTime"),
        )

        alloc = []
        for addr_hex, account_data in data.get("alloc", {}).items():
            addr_hex = addr_hex.lower().removeprefix("0x")
            address = bytes.fromhex(addr_hex.zfill(40))
            balance_str = account_data.get("balance", "0")
            if isinstance(balance_str, str):
                balance = int(balance_str, 0)
            else:
                balance = int(balance_str)
            nonce = int(account_data.get("nonce", "0"), 0) if isinstance(
                account_data.get("nonce", "0"), str
            ) else account_data.get("nonce", 0)
            code_hex = account_data.get("code", "0x")
            code = bytes.fromhex(code_hex.removeprefix("0x")) if code_hex else b""
            storage = {}
            for k, v in account_data.get("storage", {}).items():
                storage_key = bytes.fromhex(k.removeprefix("0x").zfill(64))
                storage_val = bytes.fromhex(v.removeprefix("0x").zfill(64))
                storage[storage_key] = storage_val
            alloc.append(GenesisAlloc(
                address=address,
                balance=balance,
                nonce=nonce,
                code=code,
                storage=storage,
            ))

        def parse_hex_int(val: str | int, default: int = 0) -> int:
            if isinstance(val, int):
                return val
            if isinstance(val, str):
                return int(val, 0) if val else default
            return default

        return cls(
            config=chain_config,
            nonce=parse_hex_int(data.get("nonce", "0x0")),
            timestamp=parse_hex_int(data.get("timestamp", "0x0")),
            extra_data=bytes.fromhex(
                data.get("extraData", "0x").removeprefix("0x")
            ),
            gas_limit=parse_hex_int(data.get("gasLimit", "0x0")),
            difficulty=parse_hex_int(data.get("difficulty", "0x0")),
            mix_hash=bytes.fromhex(
                data.get("mixHash", "0x" + "00" * 32).removeprefix("0x")
            ),
            coinbase=bytes.fromhex(
                data.get("coinbase", "0x" + "00" * 20).removeprefix("0x").zfill(40)
            ),
            alloc=alloc,
            base_fee_per_gas=(
                parse_hex_int(data["baseFeePerGas"])
                if "baseFeePerGas" in data
                else None
            ),
            excess_blob_gas=(
                parse_hex_int(data["excessBlobGas"])
                if "excessBlobGas" in data
                else None
            ),
            blob_gas_used=(
                parse_hex_int(data["blobGasUsed"])
                if "blobGasUsed" in data
                else None
            ),
        )

    @classmethod
    def from_json_file(cls, path: str) -> Genesis:
        with open(path) as f:
            return cls.from_json(json.load(f))
