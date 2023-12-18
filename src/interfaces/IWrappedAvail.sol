// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

interface IWrappedAvail is IERC20 {
    function mint(address destination, uint256 amount) external;
    function burn(address from, uint256 amount) external;
}
