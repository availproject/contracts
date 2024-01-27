// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.23;

import {TransparentUpgradeableProxy} from
    "lib/openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ProxyAdmin} from "lib/openzeppelin-contracts/contracts/proxy/transparent/ProxyAdmin.sol";
import {DummyAvailBridge} from "src/mocks/DummyAvailBridge.sol";
import {WrappedAvail} from "src/WrappedAvail.sol";
import {IWrappedAvail} from "src/interfaces/IWrappedAvail.sol";
import {IDummyVectorx} from "src/mocks/interfaces/IDummyVectorx.sol";
import {Script} from "forge-std/Script.sol";

contract GetProofMockScript is Script {
    function run() external {
        vm.startBroadcast();
        address admin = vm.envAddress("ADMIN");
        address vectorx = vm.envAddress("VECTORX");
        ProxyAdmin proxyAdmin = new ProxyAdmin(admin);
        address impl = address(new DummyAvailBridge());
        DummyAvailBridge bridge = DummyAvailBridge(address(new TransparentUpgradeableProxy(impl, address(proxyAdmin), "")));
        WrappedAvail avail = new WrappedAvail(address(bridge));
        bridge.initialize(
            0, admin, IWrappedAvail(address(avail)), admin, admin, IDummyVectorx(vectorx)
        );
        vm.stopBroadcast();
    }
}
