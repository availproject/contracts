// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.29;

import {Initializable} from "lib/openzeppelin-contracts-upgradeable/contracts/proxy/utils/Initializable.sol";
import {Ownable2StepUpgradeable} from
    "lib/openzeppelin-contracts-upgradeable/contracts/access/Ownable2StepUpgradeable.sol";
import {Merkle} from "src/lib/Merkle.sol";
import {IVectorx} from "src/interfaces/IVectorx.sol";
import {IAvailAttestation} from "src/interfaces/IAvailAttestation.sol";

/**
 * @author  @QEDK (Avail)
 * @title   AvailAttestation
 * @notice  A data attestation-only bridge contract for Avail blobs
 * @custom:security security@availproject.org
 */
contract AvailAttestation is Initializable, Ownable2StepUpgradeable, IAvailAttestation {
    using Merkle for bytes32[];

    IVectorx public vectorx;

    /**
     * @notice  Initializes the AvailAttestation contract
     * @param   governance  Address of the governance multisig
     * @param   newVectorx  Address of the VectorX contract
     */
    function initialize(address governance, IVectorx newVectorx) external initializer {
        vectorx = newVectorx;
        __Ownable_init(governance);
    }

    /**
     * @notice  Update the address of the VectorX contract
     * @param   newVectorx  Address of new VectorX contract
     */
    function updateVectorx(IVectorx newVectorx) external onlyOwner {
        vectorx = newVectorx;
    }

    /**
     * @notice  Takes a Merkle tree proof of inclusion for a blob leaf and verifies it
     * @dev     This function is used for data attestation on Ethereum
     * @param   input  Merkle tree proof of inclusion for the blob leaf
     * @return  bool  Returns true if the blob leaf is valid, else false
     */
    function verifyBlobLeaf(MerkleProofInput calldata input) external view returns (bool) {
        if (input.blobRoot == 0x0) {
            revert BlobRootEmpty();
        }
        _checkDataRoot(input);
        // leaf must be keccak(blob)
        // we don't need to check that the leaf is non-zero because we hash the pre-image here
        return input.leafProof.verify(input.blobRoot, input.leafIndex, keccak256(abi.encode(input.leaf)));
    }

    /**
     * @notice  Takes a Merkle proof of inclusion, and verifies it
     * @dev     This function is used for verifying a Merkle proof of inclusion for a data root
     * @param   input  Merkle tree proof of inclusion for the data root
     */
    function _checkDataRoot(MerkleProofInput calldata input) private view {
        bytes32 dataRootCommitment = vectorx.dataRootCommitments(input.rangeHash);
        if (dataRootCommitment == 0x0) {
            revert DataRootCommitmentEmpty();
        }
        // we construct the data root here internally, it is not possible to create an invalid data root that is
        // also part of the commitment tree
        if (
            !input.dataRootProof.verifySha2(
                dataRootCommitment, input.dataRootIndex, keccak256(abi.encode(input.blobRoot, input.bridgeRoot))
            )
        ) {
            revert InvalidDataRootProof();
        }
    }
}
