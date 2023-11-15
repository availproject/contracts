// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

import {ERC20, ERC20Permit} from "lib/openzeppelin-contracts/contracts/token/ERC20/extensions/ERC20Permit.sol";

contract WrappedAvail is ERC20Permit {
    address public bridge;

    error OnlyBridge();
    error AlreadyMinted();
    error InvalidProof();

    event Send(bytes32 indexed destination, uint256 amount);

    constructor(address _bridge) ERC20Permit("Wrapped Avail") ERC20("WAVL", "Wrapped Avail") {
        bridge = _bridge;
    }

    function mint(address destination, uint256 amount) external returns (bool) {
        if (msg.sender != bridge) {
            revert OnlyBridge();
        }
        _mint(destination, amount);
        return true;
    }

    function burn(bytes32 destination, uint256 amount) external returns (bool) {
        _burn(msg.sender, amount);
        emit Send(destination, amount);

        return true;
    }
}
