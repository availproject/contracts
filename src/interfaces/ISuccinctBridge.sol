// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

interface ISuccinctBridge {
    function verify(bytes32[] calldata proof, bytes32 leaf) external returns (bool);
}
