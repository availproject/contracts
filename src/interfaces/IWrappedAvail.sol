// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

import {IERC20Permit} from "lib/openzeppelin-contracts/contracts/token/ERC20/extensions/IERC20Permit.sol";

interface IWrappedAvail is IERC20Permit {
    function mint(address destination, uint256 amount) external returns (bool);
    function burn(bytes32 destination, uint256 amount) external returns (bool);
}
