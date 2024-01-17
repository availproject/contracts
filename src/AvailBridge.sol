// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.23;

import {Initializable} from "lib/openzeppelin-contracts-upgradeable/contracts/proxy/utils/Initializable.sol";
import {ReentrancyGuardUpgradeable} from
    "lib/openzeppelin-contracts-upgradeable/contracts/utils/ReentrancyGuardUpgradeable.sol";
import {PausableUpgradeable} from "lib/openzeppelin-contracts-upgradeable/contracts/utils/PausableUpgradeable.sol";
import {AccessControlDefaultAdminRulesUpgradeable} from
    "lib/openzeppelin-contracts-upgradeable/contracts/access/extensions/AccessControlDefaultAdminRulesUpgradeable.sol";
import {SafeERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {Merkle} from "src/lib/Merkle.sol";
import {IVectorx} from "src/interfaces/IVectorx.sol";
import {IWrappedAvail} from "src/interfaces/IWrappedAvail.sol";
import {IMessageReceiver} from "src/interfaces/IMessageReceiver.sol";
import {IAvailBridge} from "src/interfaces/IAvailBridge.sol";

/**
 * @author  @QEDK (Avail)
 * @title   AvailBridge
 * @notice  An arbitrary message bridge between Avail <-> Ethereum
 * @custom:security security@availproject.org
 */
contract AvailBridge is
    Initializable,
    ReentrancyGuardUpgradeable,
    PausableUpgradeable,
    AccessControlDefaultAdminRulesUpgradeable,
    IAvailBridge
{
    using Merkle for bytes32[];
    using SafeERC20 for IERC20;

    bytes1 private constant MESSAGE_TX_PREFIX = 0x01;
    bytes1 private constant TOKEN_TX_PREFIX = 0x02;
    uint32 private constant AVAIL_DOMAIN = 1;
    uint32 private constant ETH_DOMAIN = 2;
    uint256 private constant MAX_DATA_LENGTH = 102_400;
    // Derived from abi.encodePacked("ETH")
    // slither-disable-next-line too-many-digits
    bytes32 private constant ETH_ASSET_ID = 0x4554480000000000000000000000000000000000000000000000000000000000;
    bytes32 private constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    // map store spent message hashes, used for Avail -> Ethereum messages
    mapping(bytes32 => bool) public isBridged;
    // map message hashes to their message ID, used for Ethereum -> Avail messages
    mapping(uint256 => bytes32) public isSent;
    // map Avail asset IDs to an Ethereum address
    mapping(bytes32 => address) public tokens;

    IVectorx public vectorx;
    IWrappedAvail public avail;
    address public feeRecipient;
    uint256 public fees; // total fees accumulated by bridge
    uint256 public feePerByte; // in wei
    uint256 public messageId; // next nonce

    modifier onlySupportedDomain(uint32 originDomain, uint32 destinationDomain) {
        if (originDomain != AVAIL_DOMAIN || destinationDomain != ETH_DOMAIN) {
            revert InvalidDomain();
        }
        _;
    }

    modifier onlyTokenTransfer(bytes1 messageType) {
        if (messageType != TOKEN_TX_PREFIX) {
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

    /**
     * @notice  Initializes the AvailBridge contract
     * @param   newFeePerByte  New fee per byte value
     * @param   newFeeRecipient  New fee recipient address
     * @param   newAvail  Address of the WAVAIL token contract
     * @param   governance  Address of the governance multisig
     * @param   pauser  Address of the pauser multisig
     * @param   newVectorx  Address of the VectorX contract
     */
    function initialize(
        uint256 newFeePerByte,
        address newFeeRecipient,
        IWrappedAvail newAvail,
        address governance,
        address pauser,
        IVectorx newVectorx
    ) external initializer {
        feePerByte = newFeePerByte;
        feeRecipient = newFeeRecipient;
        vectorx = newVectorx;
        avail = newAvail;
        __AccessControlDefaultAdminRules_init(0, governance);
        _grantRole(PAUSER_ROLE, pauser);
        __Pausable_init();
        __ReentrancyGuard_init();
    }

    /**
     * @notice  Updates pause status of the bridge
     * @param   status  New pause status
     */
    function setPaused(bool status) external onlyRole(PAUSER_ROLE) {
        if (status) {
            _pause();
        } else {
            _unpause();
        }
    }

    /**
     * @notice  Update the address of the VectorX contract
     * @param   newVectorx  Address of new VectorX contract
     */
    function updateVectorx(IVectorx newVectorx) external onlyRole(DEFAULT_ADMIN_ROLE) {
        vectorx = newVectorx;
    }

    /**
     * @notice  Function to update asset ID -> token address mapping
     * @dev     Only callable by governance
     * @param   assetIds  Asset IDs to update
     * @param   tokenAddresses  Token addresses to update
     */
    function updateTokens(bytes32[] calldata assetIds, address[] calldata tokenAddresses)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
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
     * @notice  Function to update the fee per byte value
     * @dev     Only callable by governance
     * @param   newFeePerByte  New fee per byte value
     */
    function updateFeePerByte(uint256 newFeePerByte) external onlyRole(DEFAULT_ADMIN_ROLE) {
        feePerByte = newFeePerByte;
    }

    /**
     * @notice  Function to update the fee recipient
     * @dev     Only callable by governance
     * @param   newFeeRecipient  New fee recipient address
     */
    function updateFeeRecipient(address newFeeRecipient) external onlyRole(DEFAULT_ADMIN_ROLE) {
        feeRecipient = newFeeRecipient;
    }

    /**
     * @notice  Function to withdraw fees to the fee recipient
     * @dev     Callable by anyone because all fees are always sent to the recipient
     */
    function withdrawFees() external {
        uint256 val = fees;
        delete fees;
        (bool success, ) = feeRecipient.call{value: val}("");
        if (!success) {
            revert WithdrawFailed();
        }
    }

    /**
     * @notice  Takes an arbitrary message and its proof of inclusion, verifies and executes it (if valid)
     * @dev     This function is used for passing arbitrary data from Avail to Ethereum
     * @param   message  Message that is used to reconstruct the bridge leaf
     * @param   input  Merkle tree proof of inclusion for the bridge leaf
     */
    function receiveMessage(Message calldata message, MerkleProofInput calldata input)
        external
        whenNotPaused
        onlySupportedDomain(message.originDomain, message.destinationDomain)
        nonReentrant
    {
        if (message.messageType != MESSAGE_TX_PREFIX) {
            revert InvalidMessage();
        }

        _checkBridgeLeaf(message, input);

        // downcast SCALE-encoded bytes to an Ethereum address
        address dest = address(bytes20(message.to));
        IMessageReceiver(dest).onAvailMessage(message.from, message.data);

        emit MessageReceived(message.from, dest, message.messageId);
    }

    /**
     * @notice  Takes an AVAIL transfer message and its proof of inclusion, verifies and executes it (if valid)
     * @dev     This function is used for AVAIL transfers from Avail to Ethereum
     * @param   message  Message that is used to reconstruct the bridge leaf
     * @param   input  Merkle tree proof of inclusion for the bridge leaf
     */
    function receiveAVAIL(Message calldata message, MerkleProofInput calldata input)
        external
        whenNotPaused
        onlySupportedDomain(message.originDomain, message.destinationDomain)
        onlyTokenTransfer(message.messageType)
    {
        (bytes32 assetId, uint256 value) = abi.decode(message.data, (bytes32, uint256));
        if (assetId != 0x0) {
            revert InvalidAssetId();
        }

        _checkBridgeLeaf(message, input);

        // downcast SCALE-encoded bytes to an Ethereum address
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
        whenNotPaused
        onlySupportedDomain(message.originDomain, message.destinationDomain)
        onlyTokenTransfer(message.messageType)
        nonReentrant
    {
        (bytes32 assetId, uint256 value) = abi.decode(message.data, (bytes32, uint256));
        if (assetId != ETH_ASSET_ID) {
            revert InvalidAssetId();
        }

        _checkBridgeLeaf(message, input);

        // downcast SCALE-encoded bytes to an Ethereum address
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
        whenNotPaused
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

        // downcast SCALE-encoded bytes to an Ethereum address
        address dest = address(bytes20(message.to));

        emit MessageReceived(message.from, dest, message.messageId);

        IERC20(token).safeTransfer(dest, value);
    }

    /**
     * @notice  Emits a corresponding arbitrary messag event on Avail
     * @dev     This function is used for passing arbitrary data from Ethereum to Avail
     * @param   recipient  Recipient of the message on Avail
     * @param   data  Data to send
     */
    function sendMessage(bytes32 recipient, bytes calldata data) external payable whenNotPaused {
        uint256 length = data.length;
        if (length >= MAX_DATA_LENGTH) {
            revert ExceedsMaxDataLength();
        }
        // ensure that fee is above minimum amount
        if (msg.value < getFee(length)) {
            revert FeeTooLow();
        }
        uint256 id;
        unchecked {
            id = messageId++;
        }
        fees += msg.value;
        Message memory message = Message(
            MESSAGE_TX_PREFIX, bytes32(bytes20(msg.sender)), recipient, ETH_DOMAIN, AVAIL_DOMAIN, data, uint64(id)
        );
        // store message hash to be retrieved later by our light client
        isSent[id] = keccak256(abi.encode(message));

        emit MessageSent(msg.sender, recipient, id);
    }

    /**
     * @notice  Burns amount worth of WAVAIL tokens and bridges it to the specified recipient on Avail
     * @dev     This function is used for WAVAIL transfers from Ethereum to Avail
     * @param   recipient  Recipient of the AVAIL tokens on Avail
     * @param   amount  Amount of AVAIL tokens to bridge
     */
    function sendAVAIL(bytes32 recipient, uint256 amount) external whenNotPaused checkDestAmt(recipient, amount) {
        uint256 id;
        unchecked {
            id = messageId++;
        }
        Message memory message = Message(
            TOKEN_TX_PREFIX,
            bytes32(bytes20(msg.sender)),
            recipient,
            ETH_DOMAIN,
            AVAIL_DOMAIN,
            abi.encode(bytes32(0), amount),
            uint64(id)
        );
        // store message hash to be retrieved later by our light client
        isSent[id] = keccak256(abi.encode(message));

        emit MessageSent(msg.sender, recipient, id);

        avail.burn(msg.sender, amount);
    }

    /**
     * @notice  Bridges ETH to the specified recipient on Avail
     * @dev     This function is used for ETH transfers from Ethereum to Avail
     * @param   recipient  Recipient of the ETH on Avail
     */
    function sendETH(bytes32 recipient) external payable whenNotPaused checkDestAmt(recipient, msg.value) {
        uint256 id;
        unchecked {
            id = messageId++;
        }
        Message memory message = Message(
            TOKEN_TX_PREFIX,
            bytes32(bytes20(msg.sender)),
            recipient,
            ETH_DOMAIN,
            AVAIL_DOMAIN,
            abi.encode(ETH_ASSET_ID, msg.value),
            uint64(id)
        );
        // store message hash to be retrieved later by our light client
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
    function sendERC20(bytes32 assetId, bytes32 recipient, uint256 amount)
        external
        whenNotPaused
        checkDestAmt(recipient, amount)
    {
        address token = tokens[assetId];
        if (token == address(0)) {
            revert InvalidAssetId();
        }
        uint256 id;
        unchecked {
            id = messageId++;
        }
        Message memory message = Message(
            TOKEN_TX_PREFIX,
            bytes32(bytes20(msg.sender)),
            recipient,
            ETH_DOMAIN,
            AVAIL_DOMAIN,
            abi.encode(assetId, amount),
            uint64(id)
        );
        // store message hash to be retrieved later by our light client
        isSent[id] = keccak256(abi.encode(message));

        emit MessageSent(msg.sender, recipient, id);

        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
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
     * @notice  Takes a Merkle tree proof of inclusion for a bridge leaf and verifies it
     * @dev     This function does not validate that the leaf itself is valid, only that it's included
     * @param   input  Merkle tree proof of inclusion for the bridge leaf
     * @return  bool  Returns true if the bridge leaf is valid, else false
     */
    function verifyBridgeLeaf(MerkleProofInput calldata input) public view returns (bool) {
        if (input.bridgeRoot == 0x0) {
            revert BridgeRootEmpty();
        }
        _checkDataRoot(input);
        // leaf must be keccak(message)
        // we don't need to check that the leaf is non-zero because we check that the root is non-zero
        return input.leafProof.verify(input.bridgeRoot, input.leafIndex, input.leaf);
    }

    /**
     * @notice  Returns the minimum fee for a given message length
     * @param   length  Length of the message (in bytes)
     * @return  uint256  The minimum fee
     */
    function getFee(uint256 length) public view returns (uint256) {
        return length * feePerByte;
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
        // validate that the leaf being proved is indeed the message hash!
        if (input.leaf != leaf) {
            revert InvalidLeaf();
        }
        // check proof of inclusion
        if (!verifyBridgeLeaf(input)) {
            revert InvalidMerkleProof();
        }
        // mark as spent
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
        // we construct the data root here internally, it is not possible to create an invalid data root that is
        // also part of the commitment tree
        if (
            !input.dataRootProof.verify(
                dataRootCommitment, input.dataRootIndex, keccak256(abi.encode(input.blobRoot, input.bridgeRoot))
            )
        ) {
            revert InvalidDataRootProof();
        }
    }
}
