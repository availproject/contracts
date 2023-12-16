// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

import {IERC20Permit} from "lib/openzeppelin-contracts/contracts/token/ERC20/extensions/IERC20Permit.sol";

interface IWrappedAvail is IERC20Permit {
    function mint(address destination, uint256 amount) external;
    function burn(address from, uint256 amount) external;
}
