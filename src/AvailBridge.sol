// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.23;

import {
    OwnableUpgradeable,
    Ownable2StepUpgradeable
} from "lib/openzeppelin-contracts-upgradeable/contracts/access/Ownable2StepUpgradeable.sol";
import {Initializable} from "lib/openzeppelin-contracts-upgradeable/contracts/proxy/utils/Initializable.sol";
import {ReentrancyGuardUpgradeable} from
    "lib/openzeppelin-contracts-upgradeable/contracts/utils/ReentrancyGuardUpgradeable.sol";
import {SafeERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {IVectorX} from "src/interfaces/IVectorX.sol";
import {Merkle} from "src/lib/Merkle.sol";
import {IWrappedAvail} from "src/interfaces/IWrappedAvail.sol";
import {IMessageReceiver} from "src/interfaces/IMessageReceiver.sol";

/**
 * @author  @QEDK (Avail)
 * @title   AvailBridge
 * @notice  An arbitrary message bridge between Avail <-> Ethereum  
 * @custom:security security@availproject.org
 */
contract AvailBridge is Initializable, Ownable2StepUpgradeable, ReentrancyGuardUpgradeable {
    struct Message {
        bytes1 messageType;
        bytes32 from;
        bytes32 to;
        uint32 originDomain;
        uint32 destinationDomain;
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

    uint32 private constant AVAIL_DOMAIN = 1;
    uint32 private constant ETH_DOMAIN = 2;
    // slither-disable-next-line too-many-digits
    bytes32 private constant ETH_ASSET_ID = 0x4554480000000000000000000000000000000000000000000000000000000000;
    bytes1 private constant TOKEN_TRANSFER_MESSAGE_TYPE = 0x02;
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
    error InvalidAssetId();
    error InvalidMerkleProof();
    error InvalidDataRoot();
    error InvalidDomain();
    error InvalidDestinationOrAmount();
    error InvalidMessage();
    error InvalidFungibleTokenTransfer();
    error UnlockFailed();
    error AlreadyBridged();

    event MessageReceived(bytes32 indexed from, address indexed to, uint256 messageId);
    event MessageSent(address indexed from, bytes32 indexed to, uint256 messageId);

    modifier onlySupportedDomain(uint32 originDomain, uint32 destinationDomain) {
        if (originDomain != AVAIL_DOMAIN || destinationDomain != ETH_DOMAIN) {
            revert InvalidDomain();
        }
        _;
    }

    modifier onlyTokenTransfer(bytes1 messageType) {
        if (messageType != 0x02) {
            revert InvalidFungibleTokenTransfer();
        }
        _;
    }

    modifier checkDestAmt(bytes32 dest, uint256 amount) {
        if (dest == 0x0 || amount == 0) {
            revert InvalidDestinationOrAmount();
        }
        _;
    }

    function initialize(IWrappedAvail newAvail, address governance, IVectorX newVectorx) external initializer {
        vectorx = newVectorx;
        avail = newAvail;
        __Ownable_init_unchained(governance);
    }

    /**
     * @notice  Update the address of the VectorX contract
     * @param   newVectorx  Address of new VectorX contract
     */
    function updateVectorx(IVectorX newVectorx) external onlyOwner {
        vectorx = newVectorx;
    }

    /**
     * @notice  Function to update asset ID -> token address mapping
     * @dev     Only callable by governance
     * @param   assetIds  Asset IDs to update
     * @param   tokenAddresses  Token addresses to update
     */
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

    /**
     * @notice  Takes a Merkle tree proof of inclusion for a bridge leaf and verifies it
     * @param   input  Merkle tree proof of inclusion for the bridge leaf
     * @return  bool  Returns true if the bridge leaf is valid, else false
     */
    function verifyBridgeLeaf(MerkleProofInput calldata input) public view returns (bool) {
        if (input.bridgeRoot == 0x0) {
            revert BridgeRootEmpty();
        }
        _checkDataRoot(input);
        // leaf must be keccak(message)
        return input.leafProof.verify(input.bridgeRoot, input.leafIndex, input.leaf);
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
        return input.leafProof.verify(input.blobRoot, input.leafIndex, keccak256(abi.encode(input.leaf)));
    }

    /**
     * @notice  Takes an arbitrary message and its proof of inclusion, verifies and executes it (if valid)
     * @dev     This function is used for passing arbitrary data from Avail to Ethereum
     * @param   message  Message that is used to reconstruct the bridge leaf
     * @param   input  Merkle tree proof of inclusion for the bridge leaf
     */
    function receiveMessage(Message calldata message, MerkleProofInput calldata input)
        external
        onlySupportedDomain(message.originDomain, message.destinationDomain)
        nonReentrant
    {
        if (message.messageType != 0x01) {
            revert InvalidMessage();
        }

        _checkBridgeLeaf(message, input);

        address dest = address(bytes20(message.to));
        IMessageReceiver(dest).onAvailMessage(message.from, message.data);

        emit MessageReceived(message.from, dest, message.messageId);
    }

    /**
     * @notice  Takes an AVL transfer message and its proof of inclusion, verifies and executes it (if valid)
     * @dev     This function is used for AVL transfers from Avail to Ethereum
     * @param   message  Message that is used to reconstruct the bridge leaf
     * @param   input  Merkle tree proof of inclusion for the bridge leaf
     */
    function receiveAVL(Message calldata message, MerkleProofInput calldata input)
        external
        onlySupportedDomain(message.originDomain, message.destinationDomain)
        onlyTokenTransfer(message.messageType)
    {
        (bytes32 assetId, uint256 value) = abi.decode(message.data, (bytes32, uint256));
        if (assetId != 0x0) {
            revert InvalidAssetId();
        }

        _checkBridgeLeaf(message, input);

        address dest = address(bytes20(message.to));

        emit MessageReceived(message.from, dest, message.messageId);

        avail.mint(dest, value);
    }

    /**
     * @notice  Takes an ETH transfer message and its proof of inclusion, verifies and executes it (if valid)
     * @dev     This function is used for ETH transfers from Avail to Ethereum
     * @param   message  Message that is used to reconstruct the bridge leaf
     * @param   input  Merkle tree proof of inclusion for the bridge leaf
     */
    function receiveETH(Message calldata message, MerkleProofInput calldata input)
        external
        onlySupportedDomain(message.originDomain, message.destinationDomain)
        onlyTokenTransfer(message.messageType)
        nonReentrant
    {
        (bytes32 assetId, uint256 value) = abi.decode(message.data, (bytes32, uint256));
        if (assetId != ETH_ASSET_ID) {
            revert InvalidAssetId();
        }

        _checkBridgeLeaf(message, input);

        address dest = address(bytes20(message.to));

        emit MessageReceived(message.from, dest, message.messageId);

        // slither-disable-next-line arbitrary-send-eth,missing-zero-check,low-level-calls
        (bool success,) = dest.call{value: value}("");
        if (!success) {
            revert UnlockFailed();
        }
    }

    /**
     * @notice  Takes an ERC20 transfer message and its proof of inclusion, verifies and executes it (if valid)
     * @dev     This function is used for ERC20 transfers from Avail to Ethereum
     * @param   message  Message that is used to reconstruct the bridge leaf
     * @param   input  Merkle tree proof of inclusion for the bridge leaf
     */
    function receiveERC20(Message calldata message, MerkleProofInput calldata input)
        external
        onlySupportedDomain(message.originDomain, message.destinationDomain)
        onlyTokenTransfer(message.messageType)
        nonReentrant
    {
        (bytes32 assetId, uint256 value) = abi.decode(message.data, (bytes32, uint256));
        address token = tokens[assetId];
        if (token == address(0)) {
            revert InvalidAssetId();
        }

        _checkBridgeLeaf(message, input);

        address dest = address(bytes20(message.to));

        emit MessageReceived(message.from, dest, message.messageId);

        IERC20(token).safeTransfer(dest, value);
    }

    /**
     * @notice  Burns amount worth of WAVL tokens and bridges it to the specified recipient on Avail
     * @dev     This function is used for AVL transfers from Ethereum to Avail
     * @param   recipient  Recipient of the AVL tokens on Avail
     * @param   amount  Amount of AVL tokens to bridge
     */
    function sendAVL(bytes32 recipient, uint256 amount) external checkDestAmt(recipient, amount) {
        uint256 id = messageId++;
        Message memory message = Message(
            TOKEN_TRANSFER_MESSAGE_TYPE,
            bytes32(bytes20(msg.sender)),
            recipient,
            ETH_DOMAIN,
            AVAIL_DOMAIN,
            abi.encode(bytes32(0), amount),
            uint64(id)
        );
        isSent[id] = keccak256(abi.encode(message));

        emit MessageSent(msg.sender, recipient, id);

        avail.burn(msg.sender, amount);
    }

    /**
     * @notice  Bridges ETH to the specified recipient on Avail
     * @dev     This function is used for ETH transfers from Ethereum to Avail
     * @param   recipient  Recipient of the ETH on Avail
     */
    function sendETH(bytes32 recipient) external payable checkDestAmt(recipient, msg.value) {
        uint256 id = messageId++;
        Message memory message = Message(
            TOKEN_TRANSFER_MESSAGE_TYPE,
            bytes32(bytes20(msg.sender)),
            recipient,
            ETH_DOMAIN,
            AVAIL_DOMAIN,
            abi.encode(ETH_ASSET_ID, msg.value),
            uint64(id)
        );
        isSent[id] = keccak256(abi.encode(message));

        emit MessageSent(msg.sender, recipient, id);
    }

    /**
     * @notice  Bridges ERC20 tokens to the specified recipient on Avail
     * @dev     This function is used for ERC20 transfers from Ethereum to Avail
     * @param   assetId  Asset ID of the ERC20 token
     * @param   recipient  Recipient of the asset on Avail
     * @param   amount  Amount of ERC20 tokens to bridge
     */
    function sendERC20(bytes32 assetId, bytes32 recipient, uint256 amount) external checkDestAmt(recipient, amount) {
        address token = tokens[assetId];
        if (token == address(0)) {
            revert InvalidAssetId();
        }
        uint256 id = messageId++;
        Message memory message = Message(
            TOKEN_TRANSFER_MESSAGE_TYPE,
            bytes32(bytes20(msg.sender)),
            recipient,
            ETH_DOMAIN,
            AVAIL_DOMAIN,
            abi.encode(assetId, amount),
            uint64(id)
        );
        isSent[id] = keccak256(abi.encode(message));

        emit MessageSent(msg.sender, recipient, id);

        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
    }

    /**
     * @notice  Takes a message and its proof of inclusion, verifies and marks it as spent (if valid)
     * @dev     This function is used for verifying a message and marking it as spent (if valid)
     * @param   message  Message that is used to reconstruct the bridge leaf
     * @param   input  Merkle tree proof of inclusion for the bridge leaf
     */
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
        if (!input.dataRootProof.verify(dataRootCommitment, input.dataRootIndex, input.dataRoot)) {
            revert InvalidDataRootProof();
        }
        if (input.dataRoot != keccak256(abi.encode(input.blobRoot, input.bridgeRoot))) {
            revert InvalidDataRoot();
        }
    }
}
