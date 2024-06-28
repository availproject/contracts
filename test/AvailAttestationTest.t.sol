// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {IAvailBridge, AvailAttestation, AvailAttestationMock} from "src/mocks/AvailAttestationMock.sol";
import {VectorxMock} from "src/mocks/VectorxMock.sol";
import {Vm, Test} from "forge-std/Test.sol";

contract AvailAttestationTest is Test {
    AvailAttestationMock public attestation;
    VectorxMock public vectorx;
    address public bridge;

    function setUp() external {
        bridge = makeAddr("bridge");
        vectorx = new VectorxMock();
        vm.etch(bridge, "0xFF");
        attestation = new AvailAttestationMock();
        vm.mockCall(
            address(bridge), abi.encodeWithSelector(bytes4(keccak256("vectorx()"))), abi.encode(address(vectorx))
        );
        attestation.initialize(IAvailBridge(bridge));
    }

    function testRevertInvalidAttestationProof_attest(IAvailBridge.MerkleProofInput calldata input) external {
        vm.mockCall(
            address(bridge), abi.encodeWithSelector(IAvailBridge.verifyBlobLeaf.selector, input), abi.encode(false)
        );
        vm.expectRevert(AvailAttestation.InvalidAttestationProof.selector);
        attestation.attest(input);
    }

    function test_attest(IAvailBridge.MerkleProofInput calldata input, uint24 startBlockNumber) external {
        vm.assume(input.dataRootIndex < type(uint24).max && input.leafIndex <= type(uint128).max);
        vectorx.setStartBlock(input.rangeHash, startBlockNumber);
        vm.mockCall(
            address(bridge), abi.encodeWithSelector(IAvailBridge.verifyBlobLeaf.selector, input), abi.encode(true)
        );
        attestation.attest(input);
        assertEq(vectorx.rangeStartBlocks(input.rangeHash), startBlockNumber);
        (uint32 blockNumber, uint128 leafIndex) = attestation.attestations(input.leaf);
        assertEq(blockNumber, startBlockNumber + input.dataRootIndex + 1);
        assertEq(leafIndex, input.leafIndex);
    }
}
