// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title Counter
 * @dev 카운터 컨트랙트
 */
contract Counter {
    uint256 private _count;
    
    event Incremented(uint256 newCount);
    event Decremented(uint256 newCount);
    
    /**
     * @dev 현재 카운트를 반환합니다.
     */
    function getCount() public view returns (uint256) {
        return _count;
    }
    
    /**
     * @dev 카운트를 1 증가시킵니다.
     */
    function increment() public {
        _count += 1;
        emit Incremented(_count);
    }
    
    /**
     * @dev 카운트를 1 감소시킵니다.
     */
    function decrement() public {
        require(_count > 0, "Counter: cannot decrement below zero");
        _count -= 1;
        emit Decremented(_count);
    }
    
    /**
     * @dev 카운트를 특정 값으로 설정합니다.
     */
    function setCount(uint256 newCount) public {
        _count = newCount;
    }
    
    /**
     * @dev 카운트를 초기화합니다.
     */
    function reset() public {
        _count = 0;
    }
}