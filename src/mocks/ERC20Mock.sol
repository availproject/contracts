// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {ERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";

contract ERC20Mock is ERC20 {
    constructor() ERC20("ERC20Mock", "ERC20M") {}

    function mint(address dest, uint256 amount) external {
        _mint(dest, amount);
    }

    function burn(address from, uint256 amount) external {
        _burn(from, amount);
    }
}
