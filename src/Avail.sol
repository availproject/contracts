// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {ERC20, ERC20Permit} from "lib/openzeppelin-contracts/contracts/token/ERC20/extensions/ERC20Permit.sol";
import {IAvail} from "src/interfaces/IAvail.sol";

/**
 * @author  @QEDK (Avail)
 * @title   Avail ERC20 token
 * @notice  An Avail token implementation for Ethereum
 * @custom:security security@availproject.org
 */
contract Avail is ERC20Permit, IAvail {
    address public immutable bridge;

    error OnlyAvailBridge();

    constructor(address _bridge) ERC20Permit("Avail") ERC20("Avail", "AVAIL") {
        // slither-disable-next-line missing-zero-check
        bridge = _bridge;
    }

    modifier onlyAvailBridge() {
        if (msg.sender != bridge) {
            revert OnlyAvailBridge();
        }
        _;
    }

    function mint(address destination, uint256 amount) external onlyAvailBridge {
        _mint(destination, amount);
    }

    function burn(address from, uint256 amount) external onlyAvailBridge {
        _burn(from, amount);
    }
}
