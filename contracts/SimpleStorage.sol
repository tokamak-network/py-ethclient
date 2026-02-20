// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title SimpleStorage
 * @dev 간단한 스토리지 컨트랙트
 */
contract SimpleStorage {
    uint256 private _value;
    
    event ValueChanged(uint256 oldValue, uint256 newValue);
    
    /**
     * @dev 저장된 값을 반환합니다.
     */
    function getValue() public view returns (uint256) {
        return _value;
    }
    
    /**
     * @dev 새로운 값을 저장합니다.
     */
    function setValue(uint256 newValue) public {
        uint256 oldValue = _value;
        _value = newValue;
        emit ValueChanged(oldValue, newValue);
    }
    
    /**
     * @dev 현재 값에 amount를 더합니다.
     */
    function increment(uint256 amount) public {
        _value += amount;
    }
}