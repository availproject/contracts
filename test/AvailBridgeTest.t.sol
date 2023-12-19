// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.23;

import {TransparentUpgradeableProxy} from
    "lib/openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ProxyAdmin} from "lib/openzeppelin-contracts/contracts/proxy/transparent/ProxyAdmin.sol";
import {AvailBridge} from "src/AvailBridge.sol";
import {WrappedAvail, IWrappedAvail} from "src/WrappedAvail.sol";
import {VectorxMock, IVectorx} from "src/mocks/VectorxMock.sol";
import {MessageReceiverMock} from "src/mocks/MessageReceiverMock.sol";
import {Vm, Test} from "forge-std/Test.sol";

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

        AvailBridge.Message memory message =
            AvailBridge.Message(0x01, from, bytes32(bytes20(address(messageReceiver))), 1, 2, data, messageId);
        bytes32 messageHash = keccak256(abi.encode(message));
        bytes32 dataRoot = keccak256(abi.encode(bytes32(0), messageHash));

        vectorx.set(rangeHash, dataRoot);

        bytes32[] memory emptyArr;
        AvailBridge.MerkleProofInput memory input =
            AvailBridge.MerkleProofInput(emptyArr, emptyArr, rangeHash, 0, bytes32(0), messageHash, messageHash, 0);

        vm.expectCall(address(messageReceiver), abi.encodeCall(messageReceiver.onAvailMessage, (from, data)));
        bridge.receiveMessage(message, input);
    }

    function test_receiveAVL(bytes32 rangeHash, bytes32 from, address to, uint256 amount, uint64 messageId) external {
        vm.assume(to != address(0) && amount != 0);
        AvailBridge.Message memory message =
            AvailBridge.Message(0x02, from, bytes32(bytes20(to)), 1, 2, abi.encode(bytes32(0), amount), messageId);
        bytes32 messageHash = keccak256(abi.encode(message));
        bytes32 dataRoot = keccak256(abi.encode(bytes32(0), messageHash));

        vectorx.set(rangeHash, dataRoot);

        bytes32[] memory emptyArr;
        AvailBridge.MerkleProofInput memory input =
            AvailBridge.MerkleProofInput(emptyArr, emptyArr, rangeHash, 0, bytes32(0), messageHash, messageHash, 0);

        vm.expectCall(address(avail), abi.encodeCall(avail.mint, (to, amount)));
        bridge.receiveAVL(message, input);
    }

    function test_receiveETH(bytes32 rangeHash, bytes32 from, address to, uint256 amount, uint64 messageId) external {
        vm.assume(uint256(uint160(to)) > 9 && amount != 0 && to != address(vm));
        vm.deal(address(bridge), amount);
        AvailBridge.Message memory message = AvailBridge.Message(
            0x02,
            from,
            bytes32(bytes20(to)),
            1,
            2,
            abi.encode(0x4554480000000000000000000000000000000000000000000000000000000000, amount),
            messageId
        );
        bytes32 messageHash = keccak256(abi.encode(message));
        bytes32 dataRoot = keccak256(abi.encode(bytes32(0), messageHash));

        vectorx.set(rangeHash, dataRoot);

        bytes32[] memory emptyArr;
        AvailBridge.MerkleProofInput memory input =
            AvailBridge.MerkleProofInput(emptyArr, emptyArr, rangeHash, 0, bytes32(0), messageHash, messageHash, 0);

        uint256 balance = to.balance;
        bridge.receiveETH(message, input);
        assertEq(to.balance, balance + amount);
    }
}
