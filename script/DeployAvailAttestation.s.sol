// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.29;

import {TransparentUpgradeableProxy} from
    "lib/openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {AvailAttestation} from "src/AvailAttestation.sol";
import {IVectorx} from "src/interfaces/IVectorx.sol";
import {Script} from "forge-std/Script.sol";

contract Deploy is Script {
    function run() external {
        vm.startBroadcast();
        address admin = vm.envAddress("ADMIN");
        address vectorx = vm.envAddress("VECTORX");
        address impl = address(new AvailAttestation());
        AvailAttestation bridge = AvailAttestation(address(new TransparentUpgradeableProxy(impl, admin, "")));
        bridge.initialize(admin, IVectorx(vectorx));
        vm.stopBroadcast();
    }
}
