"""
Chain configuration and genesis block handling.

Supports Ethereum mainnet, Sepolia, and Holesky testnets.
Tracks hardfork activation blocks/timestamps.
"""

from __future__ import annotations

import binascii
from dataclasses import dataclass, field
from typing import Optional

from ethclient.common import rlp
from ethclient.common.crypto import keccak256
from ethclient.common.types import (
    Block,
    BlockHeader,
    EMPTY_TRIE_ROOT,
    ZERO_HASH,
    ZERO_ADDRESS,
    BLOOM_BYTE_SIZE,
)


# ---------------------------------------------------------------------------
# Well-known genesis hashes
# ---------------------------------------------------------------------------

MAINNET_GENESIS_HASH = bytes.fromhex(
    "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
)
SEPOLIA_GENESIS_HASH = bytes.fromhex(
    "25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9"
)
HOLESKY_GENESIS_HASH = bytes.fromhex(
    "b5f7f912443c940f21fd611f12828d75b534364ed9e95ca4e307572a72ff25e7"
)

GENESIS_HASHES: dict[int, bytes] = {
    1: MAINNET_GENESIS_HASH,
    11155111: SEPOLIA_GENESIS_HASH,
    17000: HOLESKY_GENESIS_HASH,
}


# ---------------------------------------------------------------------------
# Hardfork schedule
# ---------------------------------------------------------------------------

@dataclass
class ChainConfig:
    chain_id: int = 1
    chain_name: str = "mainnet"

    # Block-based forks
    homestead_block: Optional[int] = None
    dao_fork_block: Optional[int] = None       # DAO fork
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
    osaka_time: Optional[int] = None

    # Extra fork timestamps (e.g. BPO1, BPO2 on Sepolia testnet)
    extra_fork_times: list[int] = field(default_factory=list)

    # Terminal total difficulty for the merge
    terminal_total_difficulty: Optional[int] = None

    # Blob gas schedule parameters (EIP-4844 / EIP-7892 / EIP-7918)
    target_blob_gas_per_block: int = 393_216
    max_blob_gas_per_block: int = 786_432
    blob_base_fee_update_fraction: int = 3_338_477
    blob_schedule: dict[str, dict[str, int]] = field(default_factory=dict)
    bpo1_time: Optional[int] = None
    bpo2_time: Optional[int] = None

    def is_byzantium(self, block_number: int) -> bool:
        return self.byzantium_block is not None and block_number >= self.byzantium_block

    def is_constantinople(self, block_number: int) -> bool:
        return self.constantinople_block is not None and block_number >= self.constantinople_block

    def is_london(self, block_number: int) -> bool:
        return self.london_block is not None and block_number >= self.london_block

    def is_cancun(self, timestamp: int) -> bool:
        return self.cancun_time is not None and timestamp >= self.cancun_time

    def is_prague(self, timestamp: int) -> bool:
        return self.prague_time is not None and timestamp >= self.prague_time

    def is_osaka(self, timestamp: int) -> bool:
        return self.osaka_time is not None and timestamp >= self.osaka_time

    def get_blob_params_at(self, timestamp: int) -> tuple[int, int, int]:
        """Return (target, max, base_fee_update_fraction) active at timestamp."""
        # Base fallback from static config fields.
        target = self.target_blob_gas_per_block
        max_blobs = self.max_blob_gas_per_block
        fraction = self.blob_base_fee_update_fraction

        # Default fork timeline order.
        timeline: list[tuple[str, Optional[int]]] = [
            ("cancun", self.cancun_time),
            ("prague", self.prague_time),
            ("osaka", self.osaka_time),
            ("bpo1", self.bpo1_time),
            ("bpo2", self.bpo2_time),
        ]

        # Apply overrides in chronological order.
        for name, fork_time in timeline:
            if fork_time is None or timestamp < fork_time:
                continue
            params = self.blob_schedule.get(name)
            if not params:
                continue
            target = params.get("target", target)
            max_blobs = params.get("max", max_blobs)
            fraction = params.get("baseFeeUpdateFraction", fraction)

        return target, max_blobs, fraction


# ---------------------------------------------------------------------------
# Well-known chain configs
# ---------------------------------------------------------------------------

MAINNET_CONFIG = ChainConfig(
    chain_id=1,
    chain_name="mainnet",
    homestead_block=1_150_000,
    dao_fork_block=1_920_000,
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
    prague_time=1_746_612_311,
    osaka_time=1_764_798_551,
    extra_fork_times=[1_765_290_071, 1_767_747_671],  # BPO1, BPO2
    bpo1_time=1_765_290_071,
    bpo2_time=1_767_747_671,
    blob_schedule={
        "cancun": {"target": 393_216, "max": 786_432, "baseFeeUpdateFraction": 3_338_477},
        "osaka": {"target": 786_432, "max": 1_179_648, "baseFeeUpdateFraction": 5_007_716},
        "bpo1": {"target": 1_310_720, "max": 1_966_080, "baseFeeUpdateFraction": 5_007_716},
        "bpo2": {"target": 1_835_008, "max": 2_752_512, "baseFeeUpdateFraction": 5_007_716},
    },
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
    merge_netsplit_block=1_735_371,
    terminal_total_difficulty=17_000_000_000_000_000,
    shanghai_time=1_677_557_088,
    cancun_time=1_706_655_072,
    prague_time=1_741_159_776,
    osaka_time=1_760_427_360,
    extra_fork_times=[1_761_017_184, 1_761_607_008],  # BPO1, BPO2
    bpo1_time=1_761_017_184,
    bpo2_time=1_761_607_008,
    blob_schedule={
        "cancun": {"target": 393_216, "max": 786_432, "baseFeeUpdateFraction": 3_338_477},
        "osaka": {"target": 786_432, "max": 1_179_648, "baseFeeUpdateFraction": 5_007_716},
        "bpo1": {"target": 1_310_720, "max": 1_966_080, "baseFeeUpdateFraction": 5_007_716},
        "bpo2": {"target": 1_835_008, "max": 2_752_512, "baseFeeUpdateFraction": 5_007_716},
    },
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
        # Shanghai: withdrawals_root required when shanghaiTime <= genesis timestamp
        if (self.config and self.config.shanghai_time is not None
                and self.config.shanghai_time <= self.timestamp):
            header.withdrawals_root = EMPTY_TRIE_ROOT
        # Cancun: blob gas fields + parent beacon block root
        if self.excess_blob_gas is not None:
            header.withdrawals_root = EMPTY_TRIE_ROOT  # also ensure set for Cancun
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
            dao_fork_block=config_data.get("daoForkBlock"),
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
            target_blob_gas_per_block=config_data.get("targetBlobGasPerBlock", 393_216),
            max_blob_gas_per_block=config_data.get("maxBlobGasPerBlock", 786_432),
            blob_base_fee_update_fraction=config_data.get("blobBaseFeeUpdateFraction", 3_338_477),
            blob_schedule=data.get("blobSchedule", {}),
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

        chain_config.bpo1_time = parse_hex_int(config_data.get("bpo1Time", 0)) or None
        chain_config.bpo2_time = parse_hex_int(config_data.get("bpo2Time", 0)) or None

        # Normalize blob schedule value types.
        normalized_blob_schedule: dict[str, dict[str, int]] = {}
        for fork_name, values in chain_config.blob_schedule.items():
            if not isinstance(values, dict):
                continue
            target_raw = parse_hex_int(values.get("target", chain_config.target_blob_gas_per_block))
            max_raw = parse_hex_int(values.get("max", chain_config.max_blob_gas_per_block))
            # Some configs use blob counts; convert to blob-gas units.
            if target_raw <= 100:
                target_raw *= 131_072
            if max_raw <= 100:
                max_raw *= 131_072
            normalized_blob_schedule[fork_name] = {
                "target": target_raw,
                "max": max_raw,
                "baseFeeUpdateFraction": parse_hex_int(
                    values.get("baseFeeUpdateFraction", chain_config.blob_base_fee_update_fraction)
                ),
            }
        chain_config.blob_schedule = normalized_blob_schedule

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

# ---------------------------------------------------------------------------
# ForkID (EIP-2124)
# ---------------------------------------------------------------------------

def compute_fork_id(genesis_hash: bytes, config: ChainConfig, head_block: int = 0, head_time: int = 0) -> tuple[bytes, int]:
    """Compute EIP-2124 ForkID = (fork_hash, fork_next).

    fork_hash: CRC32 checksum of genesis hash and all past fork block numbers/timestamps.
    fork_next: next upcoming fork block/timestamp (0 if none known).
    """
    # Gather all fork points (block-based, non-zero, deduplicated)
    block_forks: list[int] = []
    for val in [
        config.homestead_block, config.dao_fork_block,
        config.eip150_block, config.eip155_block,
        config.eip158_block, config.byzantium_block, config.constantinople_block,
        config.petersburg_block, config.istanbul_block, config.muir_glacier_block,
        config.berlin_block, config.london_block, config.arrow_glacier_block,
        config.gray_glacier_block, config.merge_netsplit_block,
    ]:
        if val is not None and val > 0 and val not in block_forks:
            block_forks.append(val)
    block_forks.sort()

    # Gather timestamp-based forks
    time_forks: list[int] = []
    for val in [config.shanghai_time, config.cancun_time, config.prague_time, config.osaka_time]:
        if val is not None and val > 0 and val not in time_forks:
            time_forks.append(val)
    for val in config.extra_fork_times:
        if val > 0 and val not in time_forks:
            time_forks.append(val)
    time_forks.sort()

    # Compute fork_hash
    h = binascii.crc32(genesis_hash) & 0xFFFFFFFF

    # Track which forks are past
    past_forks: list[int] = []

    # Block-based forks: past if head_block >= fork_block
    for f in block_forks:
        if head_block >= f:
            h = binascii.crc32(f.to_bytes(8, "big"), h) & 0xFFFFFFFF
            past_forks.append(f)

    # Time-based forks: past if head_time >= fork_time
    for f in time_forks:
        if head_time >= f:
            h = binascii.crc32(f.to_bytes(8, "big"), h) & 0xFFFFFFFF
            past_forks.append(f)

    fork_hash = (h & 0xFFFFFFFF).to_bytes(4, "big")

    # Determine fork_next: first upcoming fork
    fork_next = 0
    for f in block_forks:
        if head_block < f:
            fork_next = f
            break
    if fork_next == 0:
        for f in time_forks:
            if head_time < f:
                fork_next = f
                break

    return fork_hash, fork_next


