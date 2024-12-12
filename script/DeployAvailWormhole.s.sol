// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {TransparentUpgradeableProxy} from
    "lib/openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {AvailWormhole} from "src/AvailWormhole.sol";
import {Script} from "forge-std/Script.sol";

contract Deploy is Script {
    function run() external {
        vm.startBroadcast();
        address admin = vm.envAddress("ADMIN");
        address impl = address(new AvailWormhole());
        AvailWormhole avail = AvailWormhole(address(new TransparentUpgradeableProxy(impl, admin, "")));
        avail.initialize();
        vm.stopBroadcast();
    }
}
