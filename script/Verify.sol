// VerificationTester.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "forge-std/Script.sol";
import "forge-std/console.sol";

contract VerificationTester is Script {
    function run() external view {
        // Load environment variables;
        address CONTRACT_ADDRESS = 0xEaf1db02ad660f832AAa6F84F2Cb639c0F1cB5C6;

        // Get deployed bytecode
        bytes memory deployedBytecode =
            vm.getDeployedCode(string.concat(vm.projectRoot(), "/src/AvailWormhole.sol:AvailWormhole"));

        // Get on-chain bytecode
        bytes memory onchainBytecode;
        assembly {
            let size := extcodesize(CONTRACT_ADDRESS)
            onchainBytecode := mload(0x40)
            mstore(0x40, add(onchainBytecode, add(size, 0x20)))
            mstore(onchainBytecode, size)
            extcodecopy(CONTRACT_ADDRESS, add(onchainBytecode, 0x20), 0, size)
        }

        // Compare bytecode lengths
        console.log("Deployed bytecode length:", deployedBytecode.length);
        console.log("On-chain bytecode length:", onchainBytecode.length);

        console.log("          ##############          ");
        console.logBytes(deployedBytecode);
        console.log("          ##############          ");
        console.logBytes(onchainBytecode);
    }
}
