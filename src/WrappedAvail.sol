// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.23;

import {ERC20, ERC20Permit} from "lib/openzeppelin-contracts/contracts/token/ERC20/extensions/ERC20Permit.sol";
import {IWrappedAvail} from "src/interfaces/IWrappedAvail.sol";

/**
 * @author  @QEDK (Avail)
 * @title   WrappedAvail
 * @notice  An Avail token implementation for Ethereum
 * @custom:security security@availproject.org
 */
contract WrappedAvail is ERC20Permit, IWrappedAvail {
    address public immutable bridge;

    error OnlyBridge();

    constructor(address _bridge) ERC20Permit("Wrapped Avail") ERC20("WAVL", "Wrapped Avail") {
        // slither-disable-next-line missing-zero-check
        bridge = _bridge;
    }

    modifier onlyBridge() {
        if (msg.sender != bridge) {
            revert OnlyBridge();
        }
        _;
    }

    function mint(address destination, uint256 amount) external onlyBridge {
        _mint(destination, amount);
    }

    function burn(address from, uint256 amount) external onlyBridge {
        _burn(from, amount);
    }
}
