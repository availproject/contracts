// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

interface IVectorx {
    function roots(uint64 blockNumber) external view returns (bytes32 root);
}
