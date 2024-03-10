// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {MessageReceiver, MessageReceiverMock} from "src/mocks/MessageReceiverMock.sol";
import {Vm, Test} from "forge-std/Test.sol";

contract MessageReceiverTest is Test {
    MessageReceiverMock public receiver;
    address public bridge;

    function setUp() external {
        bridge = makeAddr("bridge");
        receiver = new MessageReceiverMock();
        receiver.initialize(bridge);
    }

    function testRevertOnlyBridge_onAvailMessage(address sender, bytes32 from, bytes calldata data) external {
        vm.assume(sender != bridge);
        vm.prank(sender);
        vm.expectRevert(MessageReceiver.OnlyAvailBridge.selector);
        receiver.onAvailMessage(from, data);
    }

    function test_onAvailMessage(bytes32 from, bytes calldata data) external {
        vm.prank(bridge);
        vm.expectEmit(true, false, false, true, address(receiver));
        emit MessageReceiverMock.MessageReceived(from, data);
        receiver.onAvailMessage(from, data);
    }
}
