// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

import {Ownable, Ownable2Step} from "lib/openzeppelin-contracts/contracts/access/Ownable2Step.sol";
import {IVectorX} from "./interfaces/IVectorX.sol";
import {Merkle} from "./lib/Merkle.sol";
import {IWrappedAvail} from "./interfaces/IWrappedAvail.sol";
import {Initializable} from "lib/openzeppelin-contracts/contracts/proxy/utils/Initializable.sol";
import {IMessageReceiver} from "./interfaces/IMessageReceiver.sol";

contract AvailBridge is Ownable2Step, Initializable {
    struct Message {
        bytes1 messageType;
        bytes32 from;
        bytes32 to;
        uint32 domain;
        bytes32 assetId;
        uint256 value;
        bytes data;
        uint64 messageId;
    }

    struct MerkleProofInput {
        bytes32[] dataRootProof;
        bytes32[] leafProof;
        bytes32 dataRoot;
        bytes32 rangeHash;
        uint256 dataRootIndex;
        bytes32 blobRoot;
        bytes32 bridgeRoot;
        bytes32 leaf;
        uint256 leafIndex;
    }

    using Merkle for bytes32[];

    uint32 public constant AVAIL_DOMAIN = 1;
    uint32 public constant ETH_DOMAIN = 2;
    bytes32 public constant ETH_ASSET_ID = 0x4554480000000000000000000000000000000000000000000000000000000000;
    IVectorX public vectorx;
    IWrappedAvail public avail;
    uint256 public messageId;

    mapping(bytes32 => bool) public isBridged;
    mapping(bytes32 => bool) public isSent;
    mapping(bytes32 => address) public tokens;

    error InvalidDataRootProof();
    error DataRootCommitmentEmpty();
    error BlobRootEmpty();
    error BridgeRootEmpty();
    error InvalidMerkleProof();
    error InvalidDataRoot();
    error InvalidDomain();
    error InvalidMessage();
    error InvalidFungibleTokenTransfer();
    error MintFailed();
    error UnlockFailed();
    error AlreadyBridged();
    error InvalidAssetId();

    event MessageReceived(bytes32 indexed from, address indexed to, uint256 messageId);
    event MessageSent(address indexed from, bytes32 indexed to, uint256 messageId);

    constructor(address governance, IVectorX _vectorx) Ownable(governance) {
        vectorx = _vectorx;
    }

    function initialize(IWrappedAvail _avail) external initializer {
        avail = _avail;
    }

    function updateVectorx(IVectorX _vectorx) external onlyOwner {
        vectorx = _vectorx;
    }

    function addTokens(bytes32[] calldata assetIds, address[] calldata tokenAddresses) external onlyOwner {
        require(assetIds.length == tokenAddresses.length, "AvailBridge: assetIds and tokenAddresses length mismatch");
        for (uint256 i = 0; i < assetIds.length; i++) {
            tokens[assetIds[i]] = tokenAddresses[i];
        }
    }

    function verifyBlobLeaf(MerkleProofInput calldata input) external view returns (bool) {
        if (input.blobRoot == 0x0) {
            revert BlobRootEmpty();
        }
        _checkDataRoot(input);
        // leaf must be keccak(blob)
        return input.leafProof.verify(input.blobRoot, input.leafIndex, keccak256(abi.encode(input.leaf)));
    }

    function verifyBridgeLeaf(MerkleProofInput calldata input) public view returns (bool) {
        if (input.bridgeRoot == 0x0) {
            revert BridgeRootEmpty();
        }
        _checkDataRoot(input);
        return input.leafProof.verify(input.bridgeRoot, input.leafIndex, input.leaf);
    }

    function bridgeMessage(Message calldata message, MerkleProofInput calldata input) external {
        if (message.messageType != 0x01 || message.assetId != 0x0 || message.value != 0) {
            revert InvalidMessage();
        }
        if (message.domain != ETH_DOMAIN) {
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
        IMessageReceiver(dest).onAvailMessage(message.from, message.data);

        emit MessageReceived(message.from, dest, message.messageId);
    }

    function receiveAVL(Message calldata message, MerkleProofInput calldata input) external {
        if (message.messageType != 0x02 || message.data.length != 0) {
            revert InvalidFungibleTokenTransfer();
        }
        if (message.domain != ETH_DOMAIN) {
            revert InvalidDomain();
        }
        if (message.assetId != 0x0) {
            revert InvalidAssetId();
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
        if (!avail.mint(dest, message.value)) {
            revert MintFailed();
        }

        emit MessageReceived(message.from, dest, message.messageId);
    }

    function receiveETH(Message calldata message, MerkleProofInput calldata input) external {
        if (message.messageType != bytes1(0x02) || message.data.length > 0) {
            revert InvalidFungibleTokenTransfer();
        }
        if (message.domain != AVAIL_DOMAIN) {
            revert InvalidDomain();
        }
        if (message.assetId != ETH_ASSET_ID) {
            revert InvalidAssetId();
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
        (bool success, ) = dest.call{value: message.value}("");
        if (!success) {
            revert UnlockFailed();
        }

        emit MessageReceived(message.from, dest, message.messageId);
    }

    function sendAVL(bytes32 recipient, uint256 amount) external {
        uint256 id = messageId++;
        Message memory message = Message(
            0x02,
            bytes32(abi.encodePacked(msg.sender)),
            recipient,
            AVAIL_DOMAIN,
            0x0,
            amount,
            "",
            uint64(id)
        );
        isSent[keccak256(abi.encode(message))] = true;
        avail.burn(msg.sender, amount);

        emit MessageSent(msg.sender, recipient, id);
    }

    function sendETH(bytes32 recipient) external payable {
        uint256 id = messageId++;
        Message memory message = Message(
            0x02,
            bytes32(abi.encodePacked(msg.sender)),
            recipient,
            AVAIL_DOMAIN,
            ETH_ASSET_ID,
            msg.value,
            "",
            uint64(id)
        );
        isSent[keccak256(abi.encode(message))] = true;

        emit MessageSent(msg.sender, recipient, id);
    }

    function _checkDataRoot(MerkleProofInput calldata input) private view {
        bytes32 dataRootCommitment = vectorx.dataRootCommitments(input.rangeHash);
        if (dataRootCommitment == 0x0) {
            revert DataRootCommitmentEmpty();
        }
        if (!input.dataRootProof.verify(dataRootCommitment, input.dataRootIndex, input.dataRoot)) {
            revert InvalidDataRootProof();
        }
        if (input.dataRoot != keccak256(abi.encode(input.blobRoot, input.bridgeRoot))) {
            revert InvalidDataRoot();
        }
    }
}
