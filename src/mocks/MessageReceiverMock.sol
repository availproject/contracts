// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {MessageReceiver} from "src/MessageReceiver.sol";

contract MessageReceiverMock is MessageReceiver {
    event MessageReceived(bytes32 indexed from, bytes data);

    function initialize(address bridge) external initializer {
        __MessageReceiver_init(bridge);
    }

    function _onAvailMessage(bytes32 from, bytes calldata data) internal virtual override {
        emit MessageReceived(from, data);
    }
}
