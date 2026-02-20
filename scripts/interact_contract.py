#!/usr/bin/env python3
"""
배포된 컨트랙트와 상호작용하는 스크립트

사용법:
    python scripts/interact_contract.py <deployment_file.json> [options]

예시:
    # view 함수 호출
    python scripts/interact_contract.py deployments/counter.json --call getCount
    
    # 상태 변경 함수 호출
    python scripts/interact_contract.py deployments/counter.json --send increment
    python scripts/interact_contract.py deployments/counter.json --send setCount --args 100
    
    # 여러 작업 순차 실행
    python scripts/interact_contract.py deployments/counter.json --send increment --send increment --call getCount
"""

import argparse
import json
import sys
from pathlib import Path

from eth_keys import keys
from eth_utils import to_wei

sys.path.insert(0, str(Path(__file__).parent.parent))

from sequencer.sequencer.chain import Chain
from sequencer.core.crypto import keccak256


def get_function_selector(function_signature: str) -> bytes:
    return keccak256(function_signature.encode())[:4]


def encode_args(args: list) -> bytes:
    encoded = b""
    for arg in args:
        if isinstance(arg, int):
            encoded += arg.to_bytes(32, 'big')
        elif isinstance(arg, bool):
            encoded += (1 if arg else 0).to_bytes(32, 'big')
        elif isinstance(arg, bytes):
            encoded += arg.ljust(32, b'\x00') if len(arg) < 32 else arg[:32]
        elif isinstance(arg, str):
            if arg.startswith("0x"):
                encoded += bytes.fromhex(arg[2:].zfill(64))
            else:
                encoded += arg.encode().ljust(32, b'\x00')
    return encoded


def parse_args(arg_string: str) -> list:
    if not arg_string:
        return None
    args = []
    for arg in arg_string.split(","):
        arg = arg.strip()
        if arg.startswith("0x"):
            args.append(arg)
        elif arg.isdigit() or (arg.startswith("-") and arg[1:].isdigit()):
            args.append(int(arg))
        elif arg.lower() == "true":
            args.append(True)
        elif arg.lower() == "false":
            args.append(False)
        else:
            args.append(arg)
    return args


def find_function_abi(abi: list, name: str) -> dict:
    for item in abi:
        if item.get("type") == "function" and item.get("name") == name:
            return item
    return None


def main():
    parser = argparse.ArgumentParser(description="컨트랙트 상호작용 스크립트")
    parser.add_argument("deployment", type=str, help="배포 정보 JSON 파일")
    parser.add_argument("--call", action="append", help="view 함수 호출")
    parser.add_argument("--send", action="append", help="상태 변경 함수 호출")
    parser.add_argument("--args", type=str, help="함수 인자")
    parser.add_argument("--private-key", type=str, help="호출자 개인키")
    parser.add_argument("--balance", type=float, default=100, help="계정 잔액 (ETH)")
    
    args = parser.parse_args()
    
    # 배포 정보 로드
    deployment_path = Path(args.deployment)
    if not deployment_path.exists():
        print(f"❌ 배포 파일을 찾을 수 없습니다: {deployment_path}")
        sys.exit(1)
    
    with open(deployment_path) as f:
        deploy_info = json.load(f)
    
    contract_address = bytes.fromhex(deploy_info["contract_address"][2:])
    abi = deploy_info["abi"]
    
    print(f"📄 컨트랙트: {deployment_path.name}")
    print(f"📍 주소: {deploy_info['contract_address']}")
    print()
    
    # 체인 및 계정 설정
    private_key = bytes.fromhex(args.private_key) if args.private_key else bytes.fromhex("01" * 32)
    pk = keys.PrivateKey(private_key)
    address = pk.public_key.to_canonical_address()
    
    genesis_state = {
        address: {
            "balance": to_wei(args.balance, "ether"),
            "nonce": 0,
            "code": b"",
            "storage": {},
        }
    }
    chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
    
    # view 함수들 호출
    if args.call:
        for func_name in args.call:
            func_abi = find_function_abi(abi, func_name)
            if not func_abi:
                print(f"❌ 함수를 찾을 수 없습니다: {func_name}")
                continue
            
            # 함수 서명 생성
            inputs = func_abi.get("inputs", [])
            param_types = [inp["type"] for inp in inputs]
            signature = f"{func_name}({','.join(param_types)})"
            selector = get_function_selector(signature)
            
            print(f"📞 {func_name}() 호출...")
            result = chain.call(
                from_address=address,
                to=contract_address,
                value=0,
                data=selector,
                gas=100_000,
            )
            
            if result:
                value = int.from_bytes(result, 'big')
                print(f"   결과: {value}")
            print()
    
    # 상태 변경 함수들 호출
    if args.send:
        for i, func_name in enumerate(args.send):
            func_abi = find_function_abi(abi, func_name)
            if not func_abi:
                print(f"❌ 함수를 찾을 수 없습니다: {func_name}")
                continue
            
            # 함수 서명 생성
            inputs = func_abi.get("inputs", [])
            param_types = [inp["type"] for inp in inputs]
            param_names = [inp["name"] for inp in inputs]
            signature = f"{func_name}({','.join(param_types)})"
            selector = get_function_selector(signature)
            
            # 인자 파싱
            func_args = None
            if args.args and i == 0:  # 첫 번째 함수에만 args 적용
                func_args = parse_args(args.args)
            
            # 호출 데이터 구성
            call_data = selector
            if func_args:
                call_data += encode_args(func_args)
            
            # 트랜잭션 전송
            nonce = chain.get_nonce(address)
            signed_tx = chain.create_transaction(
                from_private_key=pk.to_bytes(),
                to=contract_address,
                value=0,
                data=call_data,
                gas=100_000,
                gas_price=1_000_000_000,
                nonce=nonce,
            )
            tx_hash = chain.send_transaction(signed_tx)
            block = chain.build_block()
            
            # 영수증 확인
            receipts = chain.store.get_receipts(block.number)
            status = receipts[0].status
            
            args_str = f"({', '.join(map(str, func_args))})" if func_args else "()"
            print(f"✍️ {func_name}{args_str}")
            print(f"   tx: 0x{tx_hash.hex()[:16]}...")
            print(f"   상태: {'✅ 성공' if status == 1 else '❌ 실패'}")
            
            # 실패한 경우 stderr에도 출력
            if status != 1:
                print(f"   ⚠️ 트랜잭션이 실패했습니다. 가스 부족 또는 require 조건 실패일 수 있습니다.")
            print()
    
    # 최종 상태 출력
    if args.send or args.call:
        # getter 함수 자동 찾기
        getter_name = None
        for name in ["getCount", "getValue", "value", "count", "balanceOf"]:
            if find_function_abi(abi, name):
                getter_name = name
                break
        
        if getter_name:
            func_abi = find_function_abi(abi, getter_name)
            inputs = func_abi.get("inputs", [])
            param_types = [inp["type"] for inp in inputs]
            signature = f"{getter_name}({','.join(param_types)})"
            selector = get_function_selector(signature)
            
            result = chain.call(
                from_address=address,
                to=contract_address,
                value=0,
                data=selector,
                gas=100_000,
            )
            
            if result:
                value = int.from_bytes(result, 'big')
                print(f"📊 현재 상태 ({getter_name}()): {value}")


if __name__ == "__main__":
    main()