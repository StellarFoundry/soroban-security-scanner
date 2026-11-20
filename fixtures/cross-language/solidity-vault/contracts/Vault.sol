// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// A valid Solidity contract. The Rust scanner must reject it rather than
/// attempting a partial parse.
contract Vault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient balance");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
}
