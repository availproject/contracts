// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

interface IAvail is IERC20 {
    function mint(address destination, uint256 amount) external;
    function burn(address from, uint256 amount) external;
}
