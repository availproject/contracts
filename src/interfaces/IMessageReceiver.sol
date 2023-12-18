// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.23;

interface IMessageReceiver {
    function onAvailMessage(bytes32 from, bytes calldata data) external;
}
