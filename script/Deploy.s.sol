// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {TransparentUpgradeableProxy} from
    "lib/openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {AvailBridge} from "src/AvailBridge.sol";
import {Avail} from "src/Avail.sol";
import {IAvail} from "src/interfaces/IAvail.sol";
import {IVectorx} from "src/interfaces/IVectorx.sol";
import {Script} from "forge-std/Script.sol";

contract Deploy is Script {
    function run() external {
        vm.startBroadcast();
        address admin = vm.envAddress("ADMIN");
        address vectorx = vm.envAddress("VECTORX");
        address impl = address(new AvailBridge());
        AvailBridge bridge = AvailBridge(address(new TransparentUpgradeableProxy(impl, admin, "")));
        Avail avail = new Avail(address(bridge));
        bridge.initialize(0, admin, IAvail(address(avail)), admin, admin, IVectorx(vectorx));
        vm.stopBroadcast();
    }
}
