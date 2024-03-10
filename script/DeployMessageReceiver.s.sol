// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {MessageReceiverMock} from "src/mocks/MessageReceiverMock.sol";
import {Script} from "forge-std/Script.sol";

contract DeployMessageReceiver is Script {
    function run() external {
        vm.startBroadcast();
        address bridge = vm.envAddress("BRIDGE");
        MessageReceiverMock receiver = new MessageReceiverMock();
        receiver.initialize(bridge);
        vm.stopBroadcast();
    }
}
