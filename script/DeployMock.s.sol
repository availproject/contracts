// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {TransparentUpgradeableProxy} from
    "lib/openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ProxyAdmin} from "lib/openzeppelin-contracts/contracts/proxy/transparent/ProxyAdmin.sol";
import {DummyAvailBridge} from "src/mocks/DummyAvailBridge.sol";
import {Avail} from "src/Avail.sol";
import {IAvail} from "src/interfaces/IAvail.sol";
import {IVectorx} from "src/interfaces/IVectorx.sol";
import {Script} from "forge-std/Script.sol";

contract GetProofMockScript is Script {
    function run() external {
        vm.startBroadcast();
        address admin = vm.envAddress("ADMIN");
        address vectorx = vm.envAddress("VECTORX");
        ProxyAdmin proxyAdmin = new ProxyAdmin(admin);
        address impl = address(new DummyAvailBridge());
        DummyAvailBridge bridge =
            DummyAvailBridge(address(new TransparentUpgradeableProxy(impl, address(proxyAdmin), "")));
        Avail avail = new Avail(address(bridge));
        bridge.initialize(0, admin, IAvail(address(avail)), admin, admin, IVectorx(vectorx));
        vm.stopBroadcast();
    }
}
