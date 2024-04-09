// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {Initializable} from "lib/openzeppelin-contracts-upgradeable/contracts/proxy/utils/Initializable.sol";
import {IVectorx} from "src/interfaces/IVectorx.sol";
import {IAvailBridge} from "src/interfaces/IAvailBridge.sol";

/**
 * @author  @QEDK (Avail)
 * @title   AvailAttestation
 * @notice  An abstract data attestation implementation for validiums, optimiums and generic rollup stacks
 * @custom:security security@availproject.org
 */
abstract contract AvailAttestation is Initializable {
    struct AttestationData {
        uint32 blockNumber;
        uint128 leafIndex;
    }

    IAvailBridge public bridge;
    IVectorx public vectorx;

    mapping (bytes32 => AttestationData) public attestations;

    error InvalidAttestationProof();
    event Attested(bytes32 indexed leaf, uint32 indexed blockNumber, uint128 indexed leafIndex);

    function initialize(IAvailBridge _bridge) external initializer {
        bridge = _bridge;
        vectorx = bridge.vectorx();
    }

    function _attest(IAvailBridge.MerkleProofInput calldata input) external {
        if (!bridge.verifyBlobLeaf(input)) revert InvalidAttestationProof();
        attestations[input.leaf] = AttestationData(
            vectorx.rangeStartBlocks(input.rangeHash) + uint32(input.dataRootIndex),
            uint128(input.leafIndex)
        );
    }
}
