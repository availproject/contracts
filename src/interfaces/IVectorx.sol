// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.23;

interface IVectorX {
    function dataRootCommitments(bytes32 rangeHash) external view returns (bytes32 dataRoot);
}
