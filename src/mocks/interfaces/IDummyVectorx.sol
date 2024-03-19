// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

interface IDummyVectorx {
    function dataRootCommitments(uint8 counter, bytes32 rangeHash) external view returns (bytes32 dataRoot);
}
