// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

interface IMessageReceiver {
    function onAvailMessage(bytes32 from, bytes calldata data) external;
}
