// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.23;

import {TransparentUpgradeableProxy} from
    "lib/openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ProxyAdmin} from "lib/openzeppelin-contracts/contracts/proxy/transparent/ProxyAdmin.sol";
import {AvailBridge} from "src/AvailBridge.sol";
import {WrappedAvail} from "src/WrappedAvail.sol";
import {IWrappedAvail} from "src/interfaces/IWrappedAvail.sol";
import {IVectorx} from "src/interfaces/IVectorx.sol";
import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";

contract SendMessageScript is Script {
    function run() external {
        vm.startBroadcast();
        //address bridgeAddr = vm.envAddress("BRIDGE");
        //AvailBridge bridge = AvailBridge(bridgeAddr);
        // bridge.sendMessage(bytes32(bytes("5GQsUevGEkoxGDJPDWbQiKDxqKmgZ5pGc732x7iXNBa1oAij")), "Hello, World!");
        // console.logBytes32(bridge.isSent(0));
        // AvailBridge.Message memory message = AvailBridge.Message(
        //     0x01,
        //     bytes32(bytes20(0x681257BED628425a28B469114Dc21A7c30205cFD)),
        //     bytes32(bytes("5GQsUevGEkoxGDJPDWbQiKDxqKmgZ5pGc732x7iXNBa1oAij")),
        //     2,
        //     1,
        //     "Hello, World!",
        //     0
        // );
        // console.logBytes(abi.encode(message));
        // console.logBytes32(keccak256(abi.encode(message)));
        // bridge.sendETH{value: 1 wei}(bytes32(bytes("5GQsUevGEkoxGDJPDWbQiKDxqKmgZ5pGc732x7iXNBa1oAij")));
        // console.logBytes32(bridge.isSent(1));
        // AvailBridge.Message memory message = AvailBridge.Message(
        //     0x02,
        //     bytes32(bytes20(0x681257BED628425a28B469114Dc21A7c30205cFD)),
        //     bytes32(bytes("5GQsUevGEkoxGDJPDWbQiKDxqKmgZ5pGc732x7iXNBa1oAij")),
        //     2,
        //     1,
        //     abi.encode(0x4554480000000000000000000000000000000000000000000000000000000000, 1),
        //     1
        // );
        // console.logBytes(abi.encode(message));
        // console.logBytes32(keccak256(abi.encode(message)));
        vm.stopBroadcast();
    }
}
