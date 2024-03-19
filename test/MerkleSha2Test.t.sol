// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

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
        return sha256(abi.encode(left, right));
    }

    function test_checkMembershipSingleLeaf(bytes32 leaf, bytes32 wrongRoot, uint256 index) external {
        vm.assume(index != 0 && wrongRoot != leaf);
        bytes32 randomDataHash = sha256(abi.encode(leaf));
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
        bytes32 randomDataHash = sha256(abi.encode(leaf));

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
        // check with wrong proof
        proof[wrongIndex % proof.length] = keccak256(abi.encode(proof[wrongIndex % proof.length]));
        assertFalse(merkleUser.checkMembership(leaf, index, root, proof));
    }

    function test_checkMembershipLargeTree(
        bytes32[] memory leaves,
        uint256 index,
        uint256 wrongIndex,
        bytes32 wrongRoot
    ) external {
        vm.assume(leaves.length >= 128 && index < leaves.length && wrongIndex != index);
        bytes32 root = getRoot(leaves);
        vm.assume(wrongRoot != root);
        bytes32[] memory proof = getProof(leaves, index);
        bytes32 leaf = leaves[index];
        bytes32 randomDataHash = sha256(abi.encode(leaf));

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
        // check with wrong proof
        proof[wrongIndex % proof.length] = keccak256(abi.encode(proof[wrongIndex % proof.length]));
        assertFalse(merkleUser.checkMembership(leaf, index, root, proof));
    }

    function test_checkMembershipLargeTree2(
        bytes32[256] memory c_leaves,
        uint256 index,
        uint256 wrongIndex,
        bytes32 wrongRoot
    ) external {
        vm.assume(index < c_leaves.length && wrongIndex != index);
        bytes32[] memory leaves = new bytes32[](c_leaves.length);
        for (uint256 i = 0; i < c_leaves.length;) {
            leaves[i] = c_leaves[i];
            unchecked {
                ++i;
            }
        }
        bytes32 root = getRoot(leaves);
        vm.assume(wrongRoot != root);
        bytes32[] memory proof = getProof(leaves, index);
        bytes32 leaf = leaves[index];
        bytes32 randomDataHash = sha256(abi.encode(leaf));

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
        // check with wrong proof
        proof[wrongIndex % proof.length] = keccak256(abi.encode(proof[wrongIndex % proof.length]));
        assertFalse(merkleUser.checkMembership(leaf, index, root, proof));
    }

    function test_checkMembershipHardcoded(uint256 wrongIndex, bytes32 wrongRoot) external {
        vm.assume(wrongIndex != 65 && wrongRoot != 0x8eebcc756e5fd418501eff745f180ff16f151b82f823623b1b656bde0599fa15);
        bytes32[8] memory c_proof = [
            bytes32(0xad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5),
            0x51f84e7279cdf6acb81af77aec64f618f71029b7d9c6d37c035c37134e517af2,
            0x69c8458dd62d27ea9abd40586ce53e5220d43b626c27f76468a57e94347f0d6b,
            0x5a021e65ea5c6b76469b68db28c7a390836e22c21c6f95cdef4d3408eb6b8050,
            0x676a0d0fab94c57be20667b57cd0800d7e5afc9b1c039a3c89995d527fbcf6c4,
            0x9efde052aa15429fae05bad4d0b1d7c64da64d03d7a1854a588c2cb8430c0d30,
            0xe51e1602448430542788cabb952ab87348561d146fe366b2525e581c0530c77e,
            0x87eb0ddba57e35f6d286673802a4af5975e22506c7cf4c64bb6be5ee11527f2c
        ];
        bytes32[] memory proof = new bytes32[](8);
        for (uint256 i = 0; i < 8;) {
            proof[i] = c_proof[i];
            unchecked {
                ++i;
            }
        }
        bytes32 randomDataHash =
            sha256(abi.encode(bytes32(0x2bd651601ffb95b9346c4867848e9621b53236baa08bfb29c9da28e7be7aeb23)));
        assertTrue(
            merkleUser.checkMembershipMemory(
                bytes32(0x2bd651601ffb95b9346c4867848e9621b53236baa08bfb29c9da28e7be7aeb23),
                65,
                bytes32(0x8eebcc756e5fd418501eff745f180ff16f151b82f823623b1b656bde0599fa15),
                proof
            )
        );
        // checked with fixed wrong index
        assertFalse(
            merkleUser.checkMembershipMemory(
                bytes32(0x2bd651601ffb95b9346c4867848e9621b53236baa08bfb29c9da28e7be7aeb23),
                66,
                bytes32(0x8eebcc756e5fd418501eff745f180ff16f151b82f823623b1b656bde0599fa15),
                proof
            )
        );
        // check with fuzzed wrong index
        assertFalse(
            merkleUser.checkMembershipMemory(
                bytes32(0x2bd651601ffb95b9346c4867848e9621b53236baa08bfb29c9da28e7be7aeb23),
                wrongIndex,
                bytes32(0x8eebcc756e5fd418501eff745f180ff16f151b82f823623b1b656bde0599fa15),
                proof
            )
        );
        // check with fuzzed leaf
        assertFalse(
            merkleUser.checkMembershipMemory(
                randomDataHash, 65, bytes32(0x8eebcc756e5fd418501eff745f180ff16f151b82f823623b1b656bde0599fa15), proof
            )
        );
        // check with fuzzed root
        assertFalse(
            merkleUser.checkMembershipMemory(
                bytes32(0x2bd651601ffb95b9346c4867848e9621b53236baa08bfb29c9da28e7be7aeb23), 65, wrongRoot, proof
            )
        );
        // check with fuzzed root and leaf
        assertFalse(merkleUser.checkMembershipMemory(randomDataHash, 65, wrongRoot, proof));
        proof[wrongIndex % proof.length] = keccak256(abi.encode(proof[wrongIndex % proof.length]));
        assertFalse(
            merkleUser.checkMembershipMemory(
                bytes32(0x2bd651601ffb95b9346c4867848e9621b53236baa08bfb29c9da28e7be7aeb23),
                65,
                bytes32(0x8eebcc756e5fd418501eff745f180ff16f151b82f823623b1b656bde0599fa15),
                proof
            )
        );
    }
}

/*//////////////////////////////////////////////////////////////////////////
                                MOCKS
//////////////////////////////////////////////////////////////////////////*/

contract MerkleUser {
    function checkMembership(bytes32 leaf, uint256 index, bytes32 rootHash, bytes32[] calldata proof)
        external
        view
        returns (bool)
    {
        return Merkle.verifySha2(proof, rootHash, index, leaf);
    }

    function checkMembershipMemory(bytes32 leaf, uint256 index, bytes32 rootHash, bytes32[] memory proof)
        external
        view
        returns (bool)
    {
        return Merkle.verifySha2Memory(proof, rootHash, index, leaf);
    }
}
