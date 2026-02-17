"""Command-line interface for the sequencer."""

import argparse
import json
from eth_keys import keys
from eth_utils import to_wei

from sequencer.sequencer.chain import Chain
from sequencer.rpc.server import serve


def main():
    parser = argparse.ArgumentParser(description="Python Single Sequencer L1")
    parser.add_argument("--port", type=int, default=8545, help="RPC server port")
    parser.add_argument("--host", default="127.0.0.1", help="RPC server host")
    parser.add_argument("--chain-id", type=int, default=1337, help="Chain ID")
    parser.add_argument(
        "--prefunded-account",
        default="0x01" + "00" * 19,
        help="Address to prefund with 100 ETH",
    )
    parser.add_argument(
        "--prefunded-private-key",
        default="01" * 32,
        help="Private key for prefunded account",
    )
    
    args = parser.parse_args()
    
    pk = keys.PrivateKey(bytes.fromhex(args.prefunded_private_key))
    prefunded_address = pk.public_key.to_canonical_address()
    
    genesis_state = {
        prefunded_address: {
            "balance": to_wei(100, "ether"),
            "nonce": 0,
            "code": b"",
            "storage": {},
        }
    }
    
    print(f"Initializing sequencer with chain ID {args.chain_id}")
    print(f"Prefunded account: {prefunded_address.hex()}")
    print(f"Balance: 100 ETH")
    
    chain = Chain.from_genesis(genesis_state, chain_id=args.chain_id)
    
    print(f"Genesis block created: {chain.get_latest_block().hash.hex()}")
    print(f"Starting RPC server on {args.host}:{args.port}")
    
    serve(chain, args.host, args.port)


if __name__ == "__main__":
    main()