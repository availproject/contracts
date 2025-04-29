// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {TimelockController} from "lib/openzeppelin-contracts/contracts/governance/TimelockController.sol";
import {console} from "forge-std/console.sol";
import {Script} from "forge-std/Script.sol";

contract DeployTimelock is Script {
    function run() external {
        vm.startBroadcast();
        address governance = vm.envAddress("GOVERNANCE");
        address[] memory proposers = new address[](1);
        proposers[0] = governance;
        address[] memory executors = new address[](1);
        executors[0] = governance;
        uint256 delay = 1 days;
        TimelockController timelock = new TimelockController(delay, proposers, executors, governance);
        console.log("        ################        ");
        console.log("Timelock deployed at: ", address(timelock));
        console.log("Timelock admin: ", governance);
        console.log("Timelock controller: ", executors[0]);
        console.log("Timelock delay:", delay);
        console.log("        ################        ");
        vm.stopBroadcast();
    }
}
