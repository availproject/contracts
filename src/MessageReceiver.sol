// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

import {IMessageReceiver} from "./interfaces/IMessageReceiver.sol";

abstract contract MessageReceiver is IMessageReceiver {
    address public availBridge;

    error OnlyAvailBridge();

    function onAvailMessage(bytes32 from, bytes calldata data) external virtual {
        if (msg.sender != availBridge) {
            revert OnlyAvailBridge();
        }
        _onAvailMessage(from, data);
    }

    function _onAvailMessage(bytes32 from, bytes calldata data) internal virtual;
}
