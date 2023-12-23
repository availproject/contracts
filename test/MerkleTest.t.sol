// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.23;

import {MurkyBase} from "lib/murky/src/common/MurkyBase.sol";
import {Merkle} from "src/lib/Merkle.sol";
import {Vm, Test} from "forge-std/Test.sol";

contract MerkleTest is Test, MurkyBase {
    MerkleUser merkleUser;

    function setUp() public {
        merkleUser = new MerkleUser();
    }

    /// @notice Hashing function for Murky
    function hashLeafPairs(bytes32 left, bytes32 right) public pure override returns (bytes32) {
        return keccak256(abi.encode(left, right));
    }

    function test_checkMembershipSingleLeaf(bytes32 leaf, bytes32 wrongRoot, uint256 index) external {
        vm.assume(index != 0 && wrongRoot != leaf);
        bytes32 randomDataHash = keccak256(abi.encode(leaf));
        bytes32[] memory proof = new bytes32[](0);

        // should return true for leaf and false for random hash
        assertTrue(merkleUser.checkMembership(leaf, 0, leaf, proof));
        // check with wrong leaf
        assertFalse(merkleUser.checkMembership(randomDataHash, 0, leaf, proof));
        // check with fixed wrong index
        assertFalse(merkleUser.checkMembership(leaf, 1, leaf, proof));
        // check with wrong index
        assertFalse(merkleUser.checkMembership(leaf, index, leaf, proof));
        // check with wrong leaf and wrong index
        assertFalse(merkleUser.checkMembership(randomDataHash, index, leaf, proof));
        // check with wrong index, wrong leaf and wrong root
        assertFalse(merkleUser.checkMembership(randomDataHash, index, wrongRoot, proof));
    }

    function test_checkMembership(bytes32[] memory leaves, uint256 index, uint256 wrongIndex, bytes32 wrongRoot)
        external
    {
        vm.assume(leaves.length > 1 && index < leaves.length && wrongIndex != index);
        bytes32 root = getRoot(leaves);
        vm.assume(wrongRoot != root);
        bytes32[] memory proof = getProof(leaves, index);
        bytes32 leaf = leaves[index];
        bytes32 randomDataHash = keccak256(abi.encode(leaf));

        // should return true for leaf and false for random hash
        assertTrue(merkleUser.checkMembership(leaf, index, root, proof));
        // check with wrong leaf
        assertFalse(merkleUser.checkMembership(randomDataHash, index, root, proof));
        // check with fixed wrong index
        assertFalse(merkleUser.checkMembership(leaf, leaves.length, root, proof));
        // check with wrong index
        assertFalse(merkleUser.checkMembership(leaf, wrongIndex, root, proof));
        // check with wrong index and wrong leaf
        assertFalse(merkleUser.checkMembership(randomDataHash, wrongIndex, root, proof));
        // check with wrong index, wrong leaf and wrong root
        assertFalse(merkleUser.checkMembership(randomDataHash, wrongIndex, wrongRoot, proof));
    }

    function test_checkMembershipLargeTree(bytes32[] memory leaves, uint256 index, uint256 wrongIndex, bytes32 wrongRoot)
        external
    {
        vm.assume(leaves.length >= 128 && index < leaves.length && wrongIndex != index);
        bytes32 root = getRoot(leaves);
        vm.assume(wrongRoot != root);
        bytes32[] memory proof = getProof(leaves, index);
        bytes32 leaf = leaves[index];
        bytes32 randomDataHash = keccak256(abi.encode(leaf));

        // should return true for leaf and false for random hash
        assertTrue(merkleUser.checkMembership(leaf, index, root, proof));
        // check with wrong leaf
        assertFalse(merkleUser.checkMembership(randomDataHash, index, root, proof));
        // check with fixed wrong index
        assertFalse(merkleUser.checkMembership(leaf, leaves.length, root, proof));
        // check with wrong index
        assertFalse(merkleUser.checkMembership(leaf, wrongIndex, root, proof));
        // check with wrong index and wrong leaf
        assertFalse(merkleUser.checkMembership(randomDataHash, wrongIndex, root, proof));
        // check with wrong index, wrong leaf and wrong root
        assertFalse(merkleUser.checkMembership(randomDataHash, wrongIndex, wrongRoot, proof));
    }

    function test_checkMembershipLargeTree2(bytes32[256] memory c_leaves, uint256 index, uint256 wrongIndex, bytes32 wrongRoot)
        external
    {
        vm.assume(index < c_leaves.length && wrongIndex != index);
        bytes32[] memory leaves = new bytes32[](c_leaves.length);
        for (uint256 i = 0; i < c_leaves.length; ) {
            leaves[i] = c_leaves[i];
            unchecked {
                ++i;
            }
        }
        bytes32 root = getRoot(leaves);
        vm.assume(wrongRoot != root);
        bytes32[] memory proof = getProof(leaves, index);
        bytes32 leaf = leaves[index];
        bytes32 randomDataHash = keccak256(abi.encode(leaf));

        // should return true for leaf and false for random hash
        assertTrue(merkleUser.checkMembership(leaf, index, root, proof));
        // check with wrong leaf
        assertFalse(merkleUser.checkMembership(randomDataHash, index, root, proof));
        // check with fixed wrong index
        assertFalse(merkleUser.checkMembership(leaf, leaves.length, root, proof));
        // check with wrong index
        assertFalse(merkleUser.checkMembership(leaf, wrongIndex, root, proof));
        // check with wrong index and wrong leaf
        assertFalse(merkleUser.checkMembership(randomDataHash, wrongIndex, root, proof));
        // check with wrong index, wrong leaf and wrong root
        assertFalse(merkleUser.checkMembership(randomDataHash, wrongIndex, wrongRoot, proof));
    }
}

/*//////////////////////////////////////////////////////////////////////////
                                MOCKS
//////////////////////////////////////////////////////////////////////////*/

contract MerkleUser {
    function checkMembership(bytes32 leaf, uint256 index, bytes32 rootHash, bytes32[] calldata proof)
        external
        pure
        returns (bool)
    {
        return Merkle.verify(proof, rootHash, index, leaf);
    }
}
