#!/usr/bin/env python3
"""
Solidity 컨트랙트 컴파일 및 배포 스크립트

사용법:
    python scripts/deploy_contract.py <contract_file.sol> [options]

예시:
    python scripts/deploy_contract.py contracts/SimpleStorage.sol --name SimpleStorage
    python scripts/deploy_contract.py contracts/Counter.sol --constructor-args "100"
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

from eth_keys import keys
from eth_utils import to_wei

# 프로젝트 루트를 Python 경로에 추가
sys.path.insert(0, str(Path(__file__).parent.parent))

from sequencer.sequencer.chain import Chain
from sequencer.core.crypto import keccak256


def compile_contract(sol_file: Path, contract_name: str = None) -> tuple[bytes, dict]:
    """
    Solidity 파일을 컴파일하여 바이트코드와 ABI를 반환합니다.
    
    Args:
        sol_file: Solidity 소스 파일 경로
        contract_name: 컨트랙트 이름 (파일에 하나만 있으면 생략 가능)
    
    Returns:
        (bytecode, abi) 튜플
    """
    if not sol_file.exists():
        raise FileNotFoundError(f"파일을 찾을 수 없습니다: {sol_file}")
    
    # solc로 컴파일
    result = subprocess.run(
        ["solc", "--bin", "--abi", "--optimize", str(sol_file)],
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        raise RuntimeError(f"컴파일 실패:\n{result.stderr}")
    
    output = result.stdout
    
    # 출력에서 바이트코드와 ABI 추출
    lines = output.split("\n")
    bytecode = None
    abi = None
    
    current_contract = None
    in_binary = False
    in_abi = False
    
    for i, line in enumerate(lines):
        # 컨트랙트 이름 감지
        if "=======" in line and str(sol_file) in line:
            # "======= /path/to/Contract.sol:ContractName =======" 형식
            if ":" in line:
                current_contract = line.split(":")[-1].replace("=", "").strip()
            in_binary = False
            in_abi = False
        
        # Binary 섹션
        if "Binary:" in line:
            in_binary = True
            in_abi = False
            continue
        
        # Contract JSON ABI 섹션
        if "Contract JSON ABI" in line:
            in_abi = True
            in_binary = False
            continue
        
        # 바이트코드 읽기
        if in_binary and line.strip() and not line.startswith("="):
            if contract_name is None or current_contract == contract_name:
                bytecode = bytes.fromhex(line.strip())
                in_binary = False
        
        # ABI 읽기
        if in_abi and line.strip().startswith("["):
            if contract_name is None or current_contract == contract_name:
                abi = json.loads(line.strip())
                in_abi = False
    
    if bytecode is None:
        raise RuntimeError("바이트코드를 찾을 수 없습니다")
    if abi is None:
        raise RuntimeError("ABI를 찾을 수 없습니다")
    
    return bytecode, abi


def get_function_selector(function_signature: str) -> bytes:
    """함수 서명에서 선택자(4바이트)를 계산합니다."""
    return keccak256(function_signature.encode())[:4]


def encode_args(args: list, types: list = None) -> bytes:
    """
    인자를 ABI 인코딩합니다.
    
    간단한 타입(uint256, address, bool, bytes)만 지원합니다.
    """
    encoded = b""
    
    for arg in args:
        if isinstance(arg, int):
            # uint256
            encoded += arg.to_bytes(32, 'big')
        elif isinstance(arg, bool):
            encoded += (1 if arg else 0).to_bytes(32, 'big')
        elif isinstance(arg, bytes):
            if len(arg) < 32:
                encoded += arg.ljust(32, b'\x00')
            else:
                encoded += arg[:32]
        elif isinstance(arg, str):
            # 주소 또는 문자열
            if arg.startswith("0x"):
                encoded += bytes.fromhex(arg[2:].zfill(64))
            else:
                encoded += arg.encode().ljust(32, b'\x00')
        else:
            raise ValueError(f"지원하지 않는 타입: {type(arg)}")
    
    return encoded


def create_chain_with_funded_account(private_key: bytes = None, balance: int = None):
    """자금이 있는 계정으로 체인을 생성합니다."""
    if private_key is None:
        private_key = bytes.fromhex("01" * 32)
    
    if balance is None:
        balance = to_wei(100, "ether")
    
    pk = keys.PrivateKey(private_key)
    address = pk.public_key.to_canonical_address()
    
    genesis_state = {
        address: {
            "balance": balance,
            "nonce": 0,
            "code": b"",
            "storage": {},
        }
    }
    
    chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
    return chain, pk, address


def deploy_contract(
    chain: Chain,
    pk: keys.PrivateKey,
    bytecode: bytes,
    constructor_args: list = None,
    gas: int = 1_000_000,
) -> tuple[bytes, int]:
    """
    컨트랙트를 배포합니다.
    
    Args:
        chain: Chain 인스턴스
        pk: 배포자 개인키
        bytecode: 컨트랙트 바이트코드
        constructor_args: 생성자 인자
        gas: 가스 한도
    
    Returns:
        (contract_address, block_number) 튜플
    """
    address = pk.public_key.to_canonical_address()
    nonce = chain.get_nonce(address)
    
    # 생성자 인자가 있으면 바이트코드에 추가
    deploy_data = bytecode
    if constructor_args:
        deploy_data += encode_args(constructor_args)
    
    # 배포 트랜잭션 생성
    signed_tx = chain.create_transaction(
        from_private_key=pk.to_bytes(),
        to=None,  # 컨트랙트 생성
        value=0,
        data=deploy_data,
        gas=gas,
        gas_price=1_000_000_000,
        nonce=nonce,
    )
    
    tx_hash = chain.send_transaction(signed_tx)
    block = chain.build_block()
    
    # 영수증에서 컨트랙트 주소 가져오기
    receipts = chain.store.get_receipts(block.number)
    contract_address = receipts[0].contract_address
    
    return contract_address, block.number, tx_hash


def call_view_method(
    chain: Chain,
    contract_address: bytes,
    function_name: str,
    args: list = None,
    abi: dict = None,
) -> bytes:
    """
    view/pure 함수를 호출합니다 (eth_call).
    """
    # ABI에서 함수 찾기
    if abi:
        for item in abi:
            if item.get("type") == "function" and item.get("name") == function_name:
                # 입력 타입으로 서명 생성
                inputs = item.get("inputs", [])
                param_types = [inp["type"] for inp in inputs]
                signature = f"{function_name}({','.join(param_types)})"
                selector = get_function_selector(signature)
                break
        else:
            raise ValueError(f"함수를 찾을 수 없습니다: {function_name}")
    else:
        # ABI 없이 간단히 함수명만 사용
        selector = get_function_selector(f"{function_name}()")
    
    # 호출 데이터 구성
    call_data = selector
    if args:
        call_data += encode_args(args)
    
    # eth_call 실행
    result = chain.call(
        from_address=b"\x00" * 20,
        to=contract_address,
        value=0,
        data=call_data,
    )
    
    return result


def call_write_method(
    chain: Chain,
    pk: keys.PrivateKey,
    contract_address: bytes,
    function_name: str,
    args: list = None,
    abi: dict = None,
    gas: int = 100_000,
) -> tuple[bytes, int]:
    """
    상태를 변경하는 함수를 호출합니다.
    """
    address = pk.public_key.to_canonical_address()
    nonce = chain.get_nonce(address)
    
    # ABI에서 함수 찾기
    if abi:
        for item in abi:
            if item.get("type") == "function" and item.get("name") == function_name:
                inputs = item.get("inputs", [])
                param_types = [inp["type"] for inp in inputs]
                signature = f"{function_name}({','.join(param_types)})"
                selector = get_function_selector(signature)
                break
        else:
            raise ValueError(f"함수를 찾을 수 없습니다: {function_name}")
    else:
        selector = get_function_selector(f"{function_name}()")
    
    # 호출 데이터 구성
    call_data = selector
    if args:
        call_data += encode_args(args)
    
    # 트랜잭션 생성
    signed_tx = chain.create_transaction(
        from_private_key=pk.to_bytes(),
        to=contract_address,
        value=0,
        data=call_data,
        gas=gas,
        gas_price=1_000_000_000,
        nonce=nonce,
    )
    
    tx_hash = chain.send_transaction(signed_tx)
    block = chain.build_block()
    
    # 영수증 확인
    receipts = chain.store.get_receipts(block.number)
    status = receipts[0].status
    
    return tx_hash, status


def main():
    parser = argparse.ArgumentParser(description="Solidity 컨트랙트 배포 스크립트")
    parser.add_argument("contract_file", type=str, help="Solidity 소스 파일 경로")
    parser.add_argument("--name", "-n", type=str, help="컨트랙트 이름")
    parser.add_argument("--constructor-args", "-c", type=str, help="생성자 인자 (쉼표로 구분)")
    parser.add_argument("--call", type=str, help="배포 후 호출할 view 함수")
    parser.add_argument("--call-args", type=str, help="함수 인자 (쉼표로 구분)")
    parser.add_argument("--send", type=str, help="배포 후 호출할 상태 변경 함수")
    parser.add_argument("--send-args", type=str, help="함수 인자 (쉼표로 구분)")
    parser.add_argument("--private-key", type=str, help="배포자 개인키 (hex)")
    parser.add_argument("--balance", type=float, default=100, help="배포자 초기 잔액 (ETH)")
    parser.add_argument("--output", "-o", type=str, help="배포 정보를 저장할 JSON 파일")
    
    args = parser.parse_args()
    
    # 체인 생성
    private_key = bytes.fromhex(args.private_key) if args.private_key else None
    chain, pk, address = create_chain_with_funded_account(
        private_key=private_key,
        balance=to_wei(args.balance, "ether")
    )
    
    print(f"📦 배포자 주소: 0x{address.hex()}")
    print(f"💰 초기 잔액: {args.balance} ETH")
    print()
    
    # 컨트랙트 컴파일
    sol_file = Path(args.contract_file)
    print(f"🔨 컴파일 중: {sol_file}")
    
    bytecode, abi = compile_contract(sol_file, args.name)
    print(f"✅ 컴파일 완료")
    print(f"   바이트코드 크기: {len(bytecode)} bytes")
    print(f"   함수 수: {sum(1 for item in abi if item.get('type') == 'function')}")
    print()
    
    # 함수 목록 출력
    print("📄 ABI 함수 목록:")
    for item in abi:
        if item.get("type") == "function":
            name = item.get("name")
            inputs = item.get("inputs", [])
            param_names = [inp["name"] for inp in inputs]
            state_mutability = item.get("stateMutability", "nonpayable")
            print(f"   - {name}({', '.join(param_names)}) [{state_mutability}]")
    print()
    
    # 생성자 인자 파싱
    constructor_args = None
    if args.constructor_args:
        constructor_args = []
        for arg in args.constructor_args.split(","):
            arg = arg.strip()
            if arg.startswith("0x"):
                constructor_args.append(arg)
            elif arg.isdigit():
                constructor_args.append(int(arg))
            else:
                constructor_args.append(arg)
    
    # 컨트랙트 배포
    print(f"🚀 컨트랙트 배포 중...")
    contract_address, block_number, tx_hash = deploy_contract(
        chain, pk, bytecode, constructor_args
    )
    
    print(f"✅ 배포 완료!")
    print(f"   컨트랙트 주소: 0x{contract_address.hex()}")
    print(f"   블록 번호: {block_number}")
    print(f"   트랜잭션 해시: 0x{tx_hash.hex()}")
    print()
    
    # view 함수 호출
    if args.call:
        call_args = None
        if args.call_args:
            call_args = []
            for arg in args.call_args.split(","):
                arg = arg.strip()
                if arg.isdigit():
                    call_args.append(int(arg))
                else:
                    call_args.append(arg)
        
        print(f"📞 함수 호출: {args.call}({args.call_args or ''})")
        result = call_view_method(chain, contract_address, args.call, call_args, abi)
        
        # 결과 디코딩 (간단한 uint256만)
        if result:
            value = int.from_bytes(result, 'big')
            print(f"   결과: {value}")
        print()
    
    # 상태 변경 함수 호출
    if args.send:
        send_args = None
        if args.send_args:
            send_args = []
            for arg in args.send_args.split(","):
                arg = arg.strip()
                if arg.isdigit():
                    send_args.append(int(arg))
                else:
                    send_args.append(arg)
        
        print(f"✍️ 상태 변경 함수 호출: {args.send}({args.send_args or ''})")
        tx_hash, status = call_write_method(
            chain, pk, contract_address, args.send, send_args, abi
        )
        print(f"   트랜잭션 해시: 0x{tx_hash.hex()}")
        print(f"   상태: {'성공' if status == 1 else '실패'}")
        print()
        
        # 변경 후 값 확인
        print(f"📊 변경 후 상태 확인...")
        result = call_view_method(chain, contract_address, args.send.replace("set", "get"), None, abi)
        if result:
            value = int.from_bytes(result, 'big')
            print(f"   현재 값: {value}")
        print()
    
    # 배포 정보 저장
    deploy_info = {
        "contract_address": "0x" + contract_address.hex(),
        "deployer": "0x" + address.hex(),
        "block_number": block_number,
        "tx_hash": "0x" + tx_hash.hex(),
        "bytecode_size": len(bytecode),
        "abi": abi,
    }
    
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(deploy_info, f, indent=2)
        print(f"💾 배포 정보 저장: {output_path}")
    
    return deploy_info


if __name__ == "__main__":
    main()