// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

import {Ownable, Ownable2Step} from "lib/openzeppelin-contracts/contracts/access/Ownable2Step.sol";
import {IVectorx} from "./interfaces/IVectorx.sol";
import {Merkle} from "./lib/Merkle.sol";
import {IWrappedAvail} from "./interfaces/IWrappedAvail.sol";
import {Initializable} from "lib/openzeppelin-contracts/contracts/proxy/utils/Initializable.sol";
import {IMessageReceiver} from "./interfaces/IMessageReceiver.sol";

contract AvailBridge is Ownable2Step, Initializable {
    using Merkle for bytes32;
    IVectorx public vectorx;
    IWrappedAvail public avail;
    uint64 public constant DOMAIN = 2;

    mapping(bytes32 => bool) public isBridged;

    error DataRootEmpty();
    error InvalidMerkleProof();
    error InvalidDataRoot();
    error InvalidDomain();
    error MintFailed();
    error AlreadyBridged();

    event MessageSent(bytes32 indexed from, address indexed to, uint256 messageId);

    constructor(address governance, IVectorx _vectorx) Ownable(governance) {
        vectorx = _vectorx;
    }

    function initialize(IWrappedAvail _avail) external initializer {
        avail = _avail;
    }

    function updateVectorx(IVectorx _vectorx) external onlyOwner {
        vectorx = _vectorx;
    }

    function verifyBlobLeaf(
        bytes32[] calldata proof,
        bytes32 blobRoot,
        bytes32 bridgeRoot,
        bytes32 leaf,
        uint256 width,
        uint256 index,
        uint64 blockNumber
    ) external view returns (bool) {
        bytes32 dataRoot = vectorx.roots(blockNumber);
        if (dataRoot == 0x0) {
            revert DataRootEmpty();
        }
        if (dataRoot != keccak256(abi.encodePacked(blobRoot, bridgeRoot))) {
            revert InvalidDataRoot();
        }
        return leaf.checkMembership(blobRoot, proof, width, index);
    }

    function verifyBridgeLeaf(
        bytes32[] calldata proof,
        bytes32 blobRoot,
        bytes32 bridgeRoot,
        bytes32 leaf,
        uint256 width,
        uint256 index,
        uint64 blockNumber
    ) public view returns (bool) {
        bytes32 dataRoot = vectorx.roots(blockNumber);
        if (dataRoot == 0x0) {
            revert DataRootEmpty();
        }
        if (dataRoot != keccak256(abi.encodePacked(blobRoot, bridgeRoot))) {
            revert InvalidDataRoot();
        }
        return leaf.checkMembership(bridgeRoot, proof, width, index);
    }

    function bridgeMessage(
        bytes32 from,
        bytes32 to,
        bytes calldata data,
        uint256 value,
        uint64 domain,
        uint256 messageId,
        bytes32[] calldata proof,
        bytes32 blobRoot,
        bytes32 bridgeRoot,
        uint256 width,
        uint256 index,
        uint64 blockNumber
    ) external {
        if (domain != DOMAIN) {
            revert InvalidDomain();
        }
        bytes32 leaf = keccak256(abi.encodePacked(from, to, data, value, domain, messageId));
        if (isBridged[leaf]) {
            revert AlreadyBridged();
        }
        if (
            !verifyBridgeLeaf(
                proof,
                blobRoot,
                bridgeRoot,
                leaf,
                width,
                index,
                blockNumber
            )
        ) {
            revert InvalidMerkleProof();
        }
        isBridged[leaf] = true;
        if (value != 0) {
            if (!avail.mint(address(bytes20(to)), value)) {
                revert MintFailed();
            }
        }
        if (data.length > 0) {
            IMessageReceiver(address(bytes20(to))).onAvailMessage(from, data);
        }

        emit MessageSent(from, address(bytes20(to)), messageId);
    }
}
