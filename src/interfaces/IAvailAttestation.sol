// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.29;

import {IVectorx} from "src/interfaces/IVectorx.sol";

interface IAvailAttestation {
    struct MerkleProofInput {
        // proof of inclusion for the data root
        bytes32[] dataRootProof;
        // proof of inclusion of leaf within blob/bridge root
        bytes32[] leafProof;
        // abi.encodePacked(startBlock, endBlock) of header range commitment on vectorx
        bytes32 rangeHash;
        // index of the data root in the commitment tree
        uint256 dataRootIndex;
        // blob root to check proof against, or reconstruct the data root
        bytes32 blobRoot;
        // bridge root to check proof against, or reconstruct the data root
        bytes32 bridgeRoot;
        // leaf being proven
        bytes32 leaf;
        // index of the leaf in the blob/bridge root tree
        uint256 leafIndex;
    }

    error BlobRootEmpty();
    error DataRootCommitmentEmpty();
    error InvalidDataRootProof();
    error InvalidLeaf();
    error InvalidMerkleProof();

    function vectorx() external view returns (IVectorx);
    function updateVectorx(IVectorx newVectorx) external;
    function verifyBlobLeaf(MerkleProofInput calldata input) external view returns (bool);
}
