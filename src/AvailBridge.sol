// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

import {Ownable, Ownable2Step} from "lib/openzeppelin-contracts/contracts/access/Ownable2Step.sol";
import {IVectorX} from "./interfaces/IVectorX.sol";
import {Merkle} from "./lib/MerkleProofLib.sol";
import {IWrappedAvail} from "./interfaces/IWrappedAvail.sol";
import {Initializable} from "lib/openzeppelin-contracts/contracts/proxy/utils/Initializable.sol";
import {IMessageReceiver} from "./interfaces/IMessageReceiver.sol";

contract AvailBridge is Ownable2Step, Initializable {
    struct Message {
        bytes32 from;
        bytes32 to;
        bytes data;
        uint256 value;
        uint64 domain;
        uint64 messageId;
    }

    struct MerkleProofInput {
        bytes32[] dataRootProof;
        bytes32[] leafProof;
        bytes32 dataRoot;
        bytes32 rangeHash;
        bytes32 blobRoot;
        bytes32 bridgeRoot;
        bytes32 leaf;
    }

    using Merkle for bytes32[];

    IVectorX public vectorx;
    IWrappedAvail public avail;
    uint64 public constant DOMAIN = 2;

    mapping(bytes32 => bool) public isBridged;

    error InvalidDataRootProof();
    error DataRootCommitmentEmpty();
    error BlobRootEmpty();
    error BridgeRootEmpty();
    error InvalidMerkleProof();
    error InvalidDataRoot();
    error InvalidDomain();
    error MintFailed();
    error AlreadyBridged();

    event MessageSent(bytes32 indexed from, address indexed to, uint64 messageId);

    constructor(address governance, IVectorX _vectorx) Ownable(governance) {
        vectorx = _vectorx;
    }

    function initialize(IWrappedAvail _avail) external initializer {
        avail = _avail;
    }

    function updateVectorx(IVectorX _vectorx) external onlyOwner {
        vectorx = _vectorx;
    }

    function verifyBlobLeaf(MerkleProofInput calldata input) external view returns (bool) {
        if (input.blobRoot == 0x0) {
            revert BlobRootEmpty();
        }
        bytes32 dataRootCommitment = vectorx.dataRootCommitments(input.rangeHash);
        if (dataRootCommitment == 0x0) {
            revert DataRootCommitmentEmpty();
        }
        if (!input.dataRootProof.verify(dataRootCommitment, input.dataRoot)) {
            revert InvalidDataRootProof();
        }
        if (input.dataRoot != keccak256(abi.encode(input.blobRoot, input.bridgeRoot))) {
            revert InvalidDataRoot();
        }
        return input.leafProof.verify(input.blobRoot, input.leaf);
    }

    function verifyBridgeLeaf(MerkleProofInput calldata input) public view returns (bool) {
        if (input.bridgeRoot == 0x0) {
            revert BridgeRootEmpty();
        }
        bytes32 dataRootCommitment = vectorx.dataRootCommitments(input.rangeHash);
        if (dataRootCommitment == 0x0) {
            revert DataRootCommitmentEmpty();
        }
        if (!input.dataRootProof.verify(dataRootCommitment, input.dataRoot)) {
            revert InvalidDataRootProof();
        }
        if (input.dataRoot != keccak256(abi.encode(input.blobRoot, input.bridgeRoot))) {
            revert InvalidDataRoot();
        }
        return input.leafProof.verify(input.bridgeRoot, input.leaf);
    }

    function bridgeMessage(Message calldata message, MerkleProofInput calldata input) external {
        if (message.domain != DOMAIN) {
            revert InvalidDomain();
        }
        bytes32 leaf = keccak256(abi.encode(message));
        if (isBridged[leaf]) {
            revert AlreadyBridged();
        }
        if (!verifyBridgeLeaf(input)) {
            revert InvalidMerkleProof();
        }
        isBridged[leaf] = true;
        address dest = address(bytes20(message.to));
        if (message.value != 0) {
            if (!avail.mint(dest, message.value)) {
                revert MintFailed();
            }
        }
        if (message.data.length > 0) {
            IMessageReceiver(dest).onAvailMessage(message.from, message.data);
        }

        emit MessageSent(message.from, dest, message.messageId);
    }
}
