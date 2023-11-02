// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

import {ERC20, ERC20Permit} from "lib/openzeppelin-contracts/contracts/token/ERC20/extensions/ERC20Permit.sol";
import {ISuccinctBridge} from "./interfaces/ISuccinctBridge.sol";

contract WrappedAvail is ERC20Permit {
    ISuccinctBridge public bridge;

    mapping(bytes32 => bool) isMinted;

    error AlreadyMinted();
    error InvalidProof();

    event Send(bytes destination, uint256 amount);

    constructor(ISuccinctBridge _bridge) ERC20Permit("Wrapped Avail") ERC20("WAVL", "Wrapped Avail") {
        bridge = _bridge;
    }

    function mint(address destination, uint256 amount, uint256 depositId, bytes32[] calldata proof) external {
        bytes32 depositHash = keccak256(abi.encodePacked(destination, amount, depositId));
        if (isMinted[depositHash]) {
            revert AlreadyMinted();
        }
        if (!bridge.verify(proof, depositHash)) {
            revert InvalidProof();
        }
        isMinted[depositHash] = true;
        _mint(destination, amount);
    }

    function burn(bytes calldata destination, uint256 amount) external {
        // TODO: validate destination if possible
        _burn(msg.sender, amount);
        emit Send(destination, amount);
    }
}
