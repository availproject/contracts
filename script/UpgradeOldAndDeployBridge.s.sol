// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {
    ITransparentUpgradeableProxy,
    TransparentUpgradeableProxy
} from "lib/openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ProxyAdmin} from "lib/openzeppelin-contracts/contracts/proxy/transparent/ProxyAdmin.sol";
import {AvailBridgeV1} from "src/AvailBridgeV1.sol";
import {AvailBridgeV1Old} from "src/AvailBridgeOld.sol";
import {IAvail} from "src/interfaces/IAvail.sol";
import {IOldAvailBridge} from "src/interfaces/IAvailBridge.sol";
import {IVectorx} from "src/interfaces/IVectorx.sol";
import {Script, console} from "forge-std/Script.sol";

contract UpgradeOldAndDeployBridge is Script {
    function run() external {
        address oldBridge = vm.envAddress("OLD_BRIDGE");
        ProxyAdmin proxyAdmin = ProxyAdmin(vm.envAddress("PROXY_ADMIN"));
        address governance = vm.envAddress("GOVERNANCE");
        address pauser = vm.envAddress("PAUSER");
        uint256 haltSendBlock = vm.envOr("HALT_SEND_BLOCK", block.number);
        uint256 haltReceiveBlock = vm.envOr("HALT_RECEIVE_BLOCK", uint256(0));

        uint256 feePerByte = AvailBridgeV1(oldBridge).feePerByte();
        address feeRecipient = AvailBridgeV1(oldBridge).feeRecipient();
        IAvail avail = AvailBridgeV1(oldBridge).avail();
        IVectorx vectorx = AvailBridgeV1(oldBridge).vectorx();

        vm.startBroadcast();

        AvailBridgeV1Old oldBridgeImplementation = new AvailBridgeV1Old();
        proxyAdmin.upgradeAndCall(ITransparentUpgradeableProxy(oldBridge), address(oldBridgeImplementation), "");
        AvailBridgeV1Old(oldBridge).setHaltSend(haltSendBlock);

        AvailBridgeV1 newBridgeImplementation = new AvailBridgeV1();
        AvailBridgeV1 newBridge =
            AvailBridgeV1(address(new TransparentUpgradeableProxy(address(newBridgeImplementation), governance, "")));

        newBridge.initialize(feePerByte, feeRecipient, avail, governance, pauser, vectorx);
        AvailBridgeV1Old(oldBridge).setNewBridgeAddress(address(newBridge));
        if (haltReceiveBlock != 0) {
            AvailBridgeV1Old(oldBridge).setHaltReceive(haltReceiveBlock);
        }
        newBridge.setOldBridgeAddress(IOldAvailBridge(oldBridge));

        vm.stopBroadcast();

        console.log("oldBridgeProxy", oldBridge);
        console.log("oldBridgeImplementation", address(oldBridgeImplementation));
        console.log("newBridgeProxy", address(newBridge));
        console.log("newBridgeImplementation", address(newBridgeImplementation));
        console.log("feeRecipient", feeRecipient);
        console.log("feePerByte", feePerByte);
        console.log("avail", address(avail));
        console.log("vectorx", address(vectorx));
        console.log("haltSendBlock", haltSendBlock);
        console.log("haltReceiveBlock", haltReceiveBlock);
    }
}
