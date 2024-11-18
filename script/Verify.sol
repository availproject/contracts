// VerificationTester.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "forge-std/Script.sol";
import "forge-std/console.sol";

contract VerificationTester is Script {
    function run() public {
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

        // Compare bytecode (first 100 bytes for quick check)
        bytes memory deployedPrefix = new bytes(14613);
        bytes memory onchainPrefix = new bytes(14613);
        for (uint256 i = 0; i < 14613; i++) {
            if (i < deployedBytecode.length) deployedPrefix[i] = deployedBytecode[i];
            if (i < onchainBytecode.length) onchainPrefix[i] = onchainBytecode[i];
        }

        console.logBytes(deployedPrefix);
        console.log("          ##############          ");
        console.logBytes(onchainPrefix);
    }
}