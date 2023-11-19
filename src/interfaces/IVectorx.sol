// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

interface IVectorX {
    function dataRootCommitments(bytes32 rangeHash) external view returns (bytes32 dataRoot);
}
