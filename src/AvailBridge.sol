// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

import {
    OwnableUpgradeable,
    Ownable2StepUpgradeable
} from "lib/openzeppelin-contracts-upgradeable/contracts/access/Ownable2StepUpgradeable.sol";
import {Initializable} from "lib/openzeppelin-contracts-upgradeable/contracts/proxy/utils/Initializable.sol";
import {ReentrancyGuardUpgradeable} from
    "lib/openzeppelin-contracts-upgradeable/contracts/utils/ReentrancyGuardUpgradeable.sol";
import {SafeERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {IVectorX} from "./interfaces/IVectorX.sol";
import {Merkle} from "./lib/Merkle.sol";
import {IWrappedAvail} from "./interfaces/IWrappedAvail.sol";
import {IMessageReceiver} from "./interfaces/IMessageReceiver.sol";

contract AvailBridge is Initializable, Ownable2StepUpgradeable, ReentrancyGuardUpgradeable {
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
    using SafeERC20 for IERC20;

    uint32 public constant AVAIL_DOMAIN = 1;
    uint32 public constant ETH_DOMAIN = 2;
    bytes32 public constant ETH_ASSET_ID = 0x4554480000000000000000000000000000000000000000000000000000000000;
    IVectorX public vectorx;
    IWrappedAvail public avail;
    uint256 public messageId;

    mapping(bytes32 => bool) public isBridged;
    mapping(uint256 => bytes32) public isSent;
    mapping(bytes32 => address) public tokens;

    error ArrayLengthMismatch();
    error InvalidDataRootProof();
    error DataRootCommitmentEmpty();
    error BlobRootEmpty();
    error BridgeRootEmpty();
    error InvalidMerkleProof();
    error InvalidDataRoot();
    error InvalidDomain();
    error InvalidMessage();
    error InvalidFungibleTokenTransfer();
    error UnlockFailed();
    error AlreadyBridged();
    error InvalidAssetId();

    event MessageReceived(bytes32 indexed from, address indexed to, uint256 messageId);
    event MessageSent(address indexed from, bytes32 indexed to, uint256 messageId);

    modifier onlyEthDomain(uint32 domain) {
        if (domain != ETH_DOMAIN) {
            revert InvalidDomain();
        }
        _;
    }

    modifier onlyTokenTransfer(bytes1 messageType, uint256 length) {
        if (messageType != 0x02 || length != 0) {
            revert InvalidFungibleTokenTransfer();
        }
        _;
    }

    function initialize(IWrappedAvail _avail, address governance, IVectorX _vectorx) external initializer {
        vectorx = _vectorx;
        avail = _avail;
        __Ownable_init_unchained(governance);
    }

    function updateVectorx(IVectorX _vectorx) external onlyOwner {
        vectorx = _vectorx;
    }

    function updateTokens(bytes32[] calldata assetIds, address[] calldata tokenAddresses) external onlyOwner {
        if (assetIds.length != tokenAddresses.length) {
            revert ArrayLengthMismatch();
        }
        for (uint256 i = 0; i < assetIds.length;) {
            tokens[assetIds[i]] = tokenAddresses[i];
            unchecked {
                ++i;
            }
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
        // leaf must be keccak(message)
        return input.leafProof.verify(input.bridgeRoot, input.leafIndex, input.leaf);
    }

    function receiveMessage(Message calldata message, MerkleProofInput calldata input)
        external
        onlyEthDomain(message.domain)
        nonReentrant
    {
        if (message.messageType != 0x01 || message.assetId != 0x0 || message.value != 0) {
            revert InvalidMessage();
        }

        _checkBridgeLeaf(message, input);

        address dest = address(bytes20(message.to));
        IMessageReceiver(dest).onAvailMessage(message.from, message.data);

        emit MessageReceived(message.from, dest, message.messageId);
    }

    function receiveAVL(Message calldata message, MerkleProofInput calldata input)
        external
        onlyEthDomain(message.domain)
        onlyTokenTransfer(message.messageType, message.data.length)
    {
        if (message.assetId != 0x0) {
            revert InvalidAssetId();
        }

        _checkBridgeLeaf(message, input);

        address dest = address(bytes20(message.to));
        avail.mint(dest, message.value);

        emit MessageReceived(message.from, dest, message.messageId);
    }

    function receiveETH(Message calldata message, MerkleProofInput calldata input)
        external
        onlyEthDomain(message.domain)
        onlyTokenTransfer(message.messageType, message.data.length)
        nonReentrant
    {
        if (message.assetId != ETH_ASSET_ID) {
            revert InvalidAssetId();
        }

        _checkBridgeLeaf(message, input);

        address dest = address(bytes20(message.to));
        (bool success,) = dest.call{value: message.value}("");
        if (!success) {
            revert UnlockFailed();
        }

        emit MessageReceived(message.from, dest, message.messageId);
    }

    function receiveERC20(Message calldata message, MerkleProofInput calldata input)
        external
        onlyEthDomain(message.domain)
        onlyTokenTransfer(message.messageType, message.data.length)
        nonReentrant
    {
        address token = tokens[message.assetId];
        if (token == address(0)) {
            revert InvalidAssetId();
        }

        _checkBridgeLeaf(message, input);

        address dest = address(bytes20(message.to));
        IERC20(token).safeTransfer(dest, message.value);

        emit MessageReceived(message.from, dest, message.messageId);
    }

    function sendAVL(bytes32 recipient, uint256 amount) external {
        uint256 id = messageId++;
        Message memory message =
            Message(0x02, bytes32(bytes20(msg.sender)), recipient, AVAIL_DOMAIN, 0x0, amount, "", uint64(id));
        isSent[id] = keccak256(abi.encode(message));
        avail.burn(msg.sender, amount);

        emit MessageSent(msg.sender, recipient, id);
    }

    function sendETH(bytes32 recipient) external payable {
        uint256 id = messageId++;
        Message memory message = Message(
            0x02, bytes32(bytes20(msg.sender)), recipient, AVAIL_DOMAIN, ETH_ASSET_ID, msg.value, "", uint64(id)
        );
        isSent[id] = keccak256(abi.encode(message));

        emit MessageSent(msg.sender, recipient, id);
    }

    function sendERC20(bytes32 assetId, bytes32 recipient, uint256 amount) external {
        address token = tokens[assetId];
        if (token == address(0)) {
            revert InvalidAssetId();
        }
        uint256 id = messageId++;
        Message memory message =
            Message(0x02, bytes32(bytes20(msg.sender)), recipient, AVAIL_DOMAIN, assetId, amount, "", uint64(id));
        isSent[id] = keccak256(abi.encode(message));
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);

        emit MessageSent(msg.sender, recipient, id);
    }

    function _checkBridgeLeaf(Message calldata message, MerkleProofInput calldata input) private {
        bytes32 leaf = keccak256(abi.encode(message));
        if (isBridged[leaf]) {
            revert AlreadyBridged();
        }
        if (!verifyBridgeLeaf(input)) {
            revert InvalidMerkleProof();
        }
        isBridged[leaf] = true;
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
