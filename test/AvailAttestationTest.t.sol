// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {TransparentUpgradeableProxy} from
    "lib/openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {Ownable} from "lib/openzeppelin-contracts/contracts/access/Ownable.sol";
import {IAvailAttestation, AvailAttestation} from "src/AvailAttestation.sol";
import {VectorxMock, IVectorx} from "src/mocks/VectorxMock.sol";
import {MurkyBase} from "lib/murky/src/common/MurkyBase.sol";
import {Vm, Test, console} from "forge-std/Test.sol";

contract AvailAttestationTest is Test, MurkyBase {
    AvailAttestation public bridge;
    VectorxMock public vectorx;
    Sha2Merkle public sha2merkle;
    address public owner;
    bytes public constant revertCode = "5F5FFD";

    function setUp() external {
        vectorx = new VectorxMock();
        sha2merkle = new Sha2Merkle();
        address impl = address(new AvailAttestation());
        bridge = AvailAttestation(address(new TransparentUpgradeableProxy(impl, msg.sender, "")));
        bridge.initialize(msg.sender, IVectorx(vectorx));
        owner = msg.sender;
    }

    function test_owner() external view {
        assertNotEq(bridge.owner(), address(0));
        assertEq(bridge.owner(), owner);
    }

    function testRevertOwnableUnauthorizedAccount_updateVectorx(IVectorx newVectorx) external {
        address rand = makeAddr("rand");
        vm.assume(rand != owner);
        vm.expectRevert(abi.encodeWithSelector((Ownable.OwnableUnauthorizedAccount.selector), rand, 0x0));
        vm.prank(rand);
        bridge.updateVectorx(newVectorx);
    }

    function test_updateVectorx(IVectorx newVectorx) external {
        vm.prank(owner);
        bridge.updateVectorx(newVectorx);
        assertEq(address(bridge.vectorx()), address(newVectorx));
    }

    function testRevertBlobRootEmpty_verifyBlobLeaf(IAvailAttestation.MerkleProofInput memory input) external {
        input.blobRoot = 0x0;
        vm.expectRevert(IAvailAttestation.BlobRootEmpty.selector);
        bridge.verifyBlobLeaf(input);
    }

    function test_verifyBlobLeaf(
        bytes32[16] calldata preimages,
        bytes32[16] calldata c_dataRoots,
        bytes32 rangeHash,
        uint256 rand,
        bytes32 bridgeRoot
    ) external {
        // we use a fixed size array because the fuzzer rejects too many inputs with arbitrary lengths
        bytes32[] memory dataRoots = new bytes32[](c_dataRoots.length);
        bytes32[] memory leaves = new bytes32[](preimages.length);
        for (uint256 i = 0; i < preimages.length;) {
            dataRoots[i] = c_dataRoots[i];
            leaves[i] = keccak256(abi.encode(preimages[i]));
            unchecked {
                ++i;
            }
        }
        bytes32 blobRoot = getRoot(leaves);
        bytes32 dataRoot = hashLeafPairs(blobRoot, bridgeRoot);
        // set dataRoot at this point in the array
        dataRoots[rand % dataRoots.length] = dataRoot;
        bytes32 dataRootCommitment = sha2merkle.getRoot(dataRoots);
        bytes32[] memory dataRootProof = sha2merkle.getProof(dataRoots, rand % dataRoots.length);
        vectorx.set(rangeHash, dataRootCommitment);
        for (uint256 i = 0; i < leaves.length;) {
            bytes32[] memory leafProof = getProof(leaves, i);
            IAvailAttestation.MerkleProofInput memory input = IAvailAttestation.MerkleProofInput(
                dataRootProof, leafProof, rangeHash, rand % dataRoots.length, blobRoot, bridgeRoot, preimages[i], i
            );
            assertTrue(bridge.verifyBlobLeaf(input));
            unchecked {
                ++i;
            }
        }
    }

    function hashLeafPairs(bytes32 left, bytes32 right) public pure override returns (bytes32) {
        return keccak256(abi.encode(left, right));
    }
}

contract Sha2Merkle is MurkyBase {
    function hashLeafPairs(bytes32 left, bytes32 right) public pure override returns (bytes32) {
        return sha256(abi.encode(left, right));
    }
}
