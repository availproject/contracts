// SPDX-License-Identifier: Apache-2.0
// Modified from https://github.com/QEDK/solidity-misc/blob/master/contracts/Merkle.sol
pragma solidity ^0.8.22;

library Merkle {
    function verify(bytes32[] calldata proof, bytes32 root, uint256 index, bytes32 leaf)
        internal
        pure
        returns (bool isValid)
    {
        assembly ("memory-safe") {
            if proof.length {
                // set end to be the end of the proof array, shl(5, proof.length) is equivalent to proof.length * 32
                let end := add(proof.offset, shl(5, proof.length))
                // set iterator to the start of the proof array
                let i := proof.offset
                // prettier-ignore
                // solhint-disable-next-line no-empty-blocks
                for {} 1 {} {
                    // if index is odd, leaf slot is at 0x20, else 0x0
                    let leafSlot := shl(5, and(0x1, index))
                    // store the leaf at the calculated slot
                    mstore(leafSlot, leaf)
                    // store proof element in whichever slot is not occupied by the leaf
                    mstore(xor(leafSlot, 32), calldataload(i))
                    // hash the first 64 bytes in memory
                    leaf := keccak256(0, 64)
                    // shift index right by 1 bit to divide by 2
                    index := shr(1, index)
                    // increment iterator by 32 bytes
                    i := add(i, 32)
                    // break if iterator is at the end of the proof array
                    if iszero(lt(i, end)) { break }
                }
            }
            // require tree to be balanced
            isValid := and(eq(leaf, root), iszero(index))
        }
    }
}
