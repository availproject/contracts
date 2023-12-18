// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.23;

import {TransparentUpgradeableProxy} from "lib/openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ProxyAdmin} from "lib/openzeppelin-contracts/contracts/proxy/transparent/ProxyAdmin.sol";
import {AvailBridge} from "src/AvailBridge.sol";
import {WrappedAvail, IWrappedAvail} from "src/WrappedAvail.sol";
import {VectorxMock, IVectorx} from "src/mocks/VectorxMock.sol";
import {MessageReceiverMock} from "src/mocks/MessageReceiverMock.sol";
import {Test} from "forge-std/Test.sol";

contract AvailBridgeTest is Test {
    AvailBridge public bridge;
    WrappedAvail public avail;
    VectorxMock public vectorx;
    ProxyAdmin public admin;
    address public owner;

    function setUp() external {
        vectorx = new VectorxMock();
        admin = new ProxyAdmin(msg.sender);
        address impl = address(new AvailBridge());
        bridge = AvailBridge(address(new TransparentUpgradeableProxy(impl, address(admin), "")));
        avail = new WrappedAvail(address(bridge));
        bridge.initialize(IWrappedAvail(address(avail)), msg.sender, IVectorx(vectorx));
        owner = msg.sender;
    }

    function test_owner() external {
        assertEq(bridge.owner() != address(0), true);
        assertEq(bridge.owner() == owner, true);
    }

    function test_receiveMessage(bytes32 rangeHash, bytes calldata data, bytes32 from, uint64 messageId) external {
        MessageReceiverMock messageReceiver = new MessageReceiverMock();
        messageReceiver.initialize(address(bridge));

        AvailBridge.Message memory message = AvailBridge.Message(
            0x01,
            from,
            bytes32(bytes20(address(messageReceiver))),
            1,
            2,
            data,
            messageId
        );
        bytes32 messageHash = keccak256(abi.encode(message));
        bytes32 dataRoot = keccak256(abi.encode(bytes32(0), messageHash));

        vectorx.set(rangeHash, dataRoot);
    }
}
