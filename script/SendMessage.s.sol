// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {TransparentUpgradeableProxy} from
    "lib/openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ProxyAdmin} from "lib/openzeppelin-contracts/contracts/proxy/transparent/ProxyAdmin.sol";
import {AvailBridgeV1} from "src/AvailBridgeV1.sol";
import {IAvailBridge} from "src/interfaces/IAvailBridge.sol";
import {Avail} from "src/Avail.sol";
import {IAvail} from "src/interfaces/IAvail.sol";
import {IVectorx} from "src/interfaces/IVectorx.sol";
import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";

contract SendMessageScript is Script {
    function run() external {
        vm.startBroadcast();
        address bridgeAddr = vm.envAddress("BRIDGE");
        AvailBridgeV1 bridge = AvailBridgeV1(bridgeAddr);
        bridge.sendMessage(bytes32(bytes("5GQsUevGEkoxGDJPDWbQiKDxqKmgZ5pGc732x7iXNBa1oAij")), "Hello, World!");
        console.logBytes32(bridge.isSent(0));
        IAvailBridge.Message memory message = IAvailBridge.Message(
            0x01,
            bytes32(bytes20(0x681257BED628425a28B469114Dc21A7c30205cFD)),
            bytes32(bytes("5GQsUevGEkoxGDJPDWbQiKDxqKmgZ5pGc732x7iXNBa1oAij")),
            2,
            1,
            "Hello, World!",
            0
        );
        console.logBytes(abi.encode(message));
        console.logBytes32(keccak256(abi.encode(message)));
        vm.stopBroadcast();
    }
}
