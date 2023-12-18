// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.23;

import {IVectorx} from "src/interfaces/IVectorx.sol";

contract VectorxMock is IVectorx {
    mapping(bytes32 => bytes32) public dataRootCommitments;

    function set(bytes32 rangeHash, bytes32 dataRoot) external {
        dataRootCommitments[rangeHash] = dataRoot;
    }
}
