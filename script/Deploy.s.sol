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

contract GetProofMockScript is Script {
    function run() external {
        vm.startBroadcast();
        address admin = vm.envAddress("ADMIN");
        ProxyAdmin proxyAdmin = new ProxyAdmin(admin);
        address impl = address(new AvailBridge());
        AvailBridge bridge = AvailBridge(address(new TransparentUpgradeableProxy(impl, address(proxyAdmin), "")));
        WrappedAvail avail = new WrappedAvail(address(bridge));
        bridge.initialize(
            10000000000,
            IWrappedAvail(address(avail)),
            admin,
            admin,
            IVectorx(0x5ac10644a873AAcd288775A90d6D0303496A4304)
        );
        vm.stopBroadcast();
    }
}
