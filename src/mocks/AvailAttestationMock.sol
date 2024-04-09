// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {Initializable} from "lib/openzeppelin-contracts-upgradeable/contracts/proxy/utils/Initializable.sol";
import {IAvailBridge} from "src/interfaces/IAvailBridge.sol";
import {AvailAttestation} from "src/AvailAttestation.sol";

/**
 * @author  @QEDK (Avail)
 * @title   AvailAttestationMock
 * @notice  An mock data attestation implementation for validiums, optimiums and generic rollup stacks
 * @custom:security security@availproject.org
 */
contract AvailAttestationMock is Initializable, AvailAttestation {
    function initialize(IAvailBridge _bridge) external initializer {
        __AvailAttestation_init(_bridge);
    }

    // this function signature should differ based on rollup contract's expected function signature
    function attest(IAvailBridge.MerkleProofInput calldata input) external {
        _attest(input);
    }
}
