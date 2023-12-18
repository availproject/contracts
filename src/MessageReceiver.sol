// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.23;

import {IMessageReceiver} from "src/interfaces/IMessageReceiver.sol";

/**
 * @author  @QEDK (Avail)
 * @title   MessageReceiver
 * @notice  A message receiver implementation for receiving messages from the Avail AMB
 * @custom:security security@availproject.org
 */
abstract contract MessageReceiver is IMessageReceiver {
    address public availBridge;

    error OnlyAvailBridge();

    function onAvailMessage(bytes32 from, bytes calldata data) public virtual {
        if (msg.sender != availBridge) {
            revert OnlyAvailBridge();
        }
        _onAvailMessage(from, data);
    }

    // slither-disable-next-line naming-convention,dead-code
    function __MessageReceiver_init(address _availBridge) internal virtual {
        availBridge = _availBridge;
    }

    // slither-disable-next-line,unimplemented-functions
    function _onAvailMessage(bytes32 from, bytes calldata data) internal virtual;
}
