// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.23;

import {TransparentUpgradeableProxy} from
    "lib/openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ProxyAdmin} from "lib/openzeppelin-contracts/contracts/proxy/transparent/ProxyAdmin.sol";
import {AvailBridge} from "src/AvailBridge.sol";
import {WrappedAvail, IWrappedAvail} from "src/WrappedAvail.sol";
import {VectorxMock, IVectorx} from "src/mocks/VectorxMock.sol";
import {ERC20Mock} from "src/mocks/ERC20Mock.sol";
import {MessageReceiverMock} from "src/mocks/MessageReceiverMock.sol";
import {Vm, Test} from "forge-std/Test.sol";
import {MurkyBase} from "lib/murky/src/common/MurkyBase.sol";

contract AvailBridgeTest is Test, MurkyBase {
    AvailBridge public bridge;
    WrappedAvail public avail;
    VectorxMock public vectorx;
    ProxyAdmin public admin;
    address public owner;
    bytes public constant revertCode = "5F5FFD";

    function setUp() external {
        vectorx = new VectorxMock();
        admin = new ProxyAdmin(msg.sender);
        address impl = address(new AvailBridge());
        bridge = AvailBridge(address(new TransparentUpgradeableProxy(impl, address(admin), "")));
        avail = new WrappedAvail(address(bridge));
        bridge.initialize(IWrappedAvail(address(avail)), msg.sender, IVectorx(vectorx));
        owner = msg.sender;
    }

    function test_owner() external {
        assertEq(bridge.owner() != address(0), true);
        assertEq(bridge.owner() == owner, true);
    }

    function test_updateVectorx(IVectorx newVectorx) external {
        vm.prank(owner);
        bridge.updateVectorx(newVectorx);
        assertEq(address(bridge.vectorx()), address(newVectorx));
    }

    function testRevertArrayLengthMismatch_updateTokens(uint8 len1, uint8 len2) external {
        // using len > uint8 slows tests by a *lot*
        vm.assume(len1 != len2);
        bytes32[] memory assetIds = new bytes32[](len1);
        address[] memory addresses = new address[](len2);
        vm.prank(owner);
        vm.expectRevert(AvailBridge.ArrayLengthMismatch.selector);
        bridge.updateTokens(assetIds, addresses);
    }

    function testRevertInvalidMessage_receiveMessage(bytes1 prefix) external {
        vm.assume(prefix != 0x01);
        AvailBridge.Message memory message = AvailBridge.Message(prefix, bytes32(0), bytes32(0), 1, 2, "", 0);
        AvailBridge.MerkleProofInput memory input = AvailBridge.MerkleProofInput(
            new bytes32[](0), new bytes32[](0), bytes32(0), 0, bytes32(0), bytes32(0), bytes32(0), 0
        );
        vm.expectRevert(AvailBridge.InvalidMessage.selector);
        bridge.receiveMessage(message, input);
    }

    function test_receiveMessage(bytes32 rangeHash, bytes calldata data, bytes32 from, uint64 messageId) external {
        MessageReceiverMock messageReceiver = new MessageReceiverMock();
        messageReceiver.initialize(address(bridge));

        AvailBridge.Message memory message =
            AvailBridge.Message(0x01, from, bytes32(bytes20(address(messageReceiver))), 1, 2, data, messageId);
        bytes32 messageHash = keccak256(abi.encode(message));
        bytes32 dataRoot = keccak256(abi.encode(bytes32(0), messageHash));

        vectorx.set(rangeHash, dataRoot);

        bytes32[] memory emptyArr;
        AvailBridge.MerkleProofInput memory input =
            AvailBridge.MerkleProofInput(emptyArr, emptyArr, rangeHash, 0, bytes32(0), messageHash, messageHash, 0);

        vm.expectCall(address(messageReceiver), abi.encodeCall(messageReceiver.onAvailMessage, (from, data)));
        bridge.receiveMessage(message, input);
    }

    function testRevertAlreadyBridged_receiveMessage(
        bytes32 rangeHash,
        bytes calldata data,
        bytes32 from,
        uint64 messageId
    ) external {
        MessageReceiverMock messageReceiver = new MessageReceiverMock();
        messageReceiver.initialize(address(bridge));

        AvailBridge.Message memory message =
            AvailBridge.Message(0x01, from, bytes32(bytes20(address(messageReceiver))), 1, 2, data, messageId);
        bytes32 messageHash = keccak256(abi.encode(message));
        bytes32 dataRoot = keccak256(abi.encode(bytes32(0), messageHash));

        vectorx.set(rangeHash, dataRoot);

        bytes32[] memory emptyArr;
        AvailBridge.MerkleProofInput memory input =
            AvailBridge.MerkleProofInput(emptyArr, emptyArr, rangeHash, 0, bytes32(0), messageHash, messageHash, 0);

        vm.expectCall(address(messageReceiver), abi.encodeCall(messageReceiver.onAvailMessage, (from, data)));
        bridge.receiveMessage(message, input);
        vm.expectRevert(AvailBridge.AlreadyBridged.selector);
        bridge.receiveMessage(message, input);
    }

    function testRevertInvalidLeaf_receiveMessage(
        bytes32 rangeHash,
        bytes calldata data,
        bytes32 from,
        uint64 messageId
    ) external {
        MessageReceiverMock messageReceiver = new MessageReceiverMock();
        messageReceiver.initialize(address(bridge));

        AvailBridge.Message memory message =
            AvailBridge.Message(0x01, from, bytes32(bytes20(address(messageReceiver))), 1, 2, data, messageId);
        bytes32 messageHash = keccak256(abi.encode(message));
        bytes32 dataRoot = keccak256(abi.encode(bytes32(0), messageHash));

        vectorx.set(rangeHash, dataRoot);

        bytes32[] memory emptyArr;
        // hash the hash to generate a wrong leaf
        AvailBridge.MerkleProofInput memory input = AvailBridge.MerkleProofInput(
            emptyArr, emptyArr, rangeHash, 0, bytes32(0), messageHash, keccak256(abi.encode(messageHash)), 0
        );

        vm.expectRevert(AvailBridge.InvalidLeaf.selector);
        bridge.receiveMessage(message, input);
        assertEq(bridge.isBridged(messageHash), false);
    }

    function testRevertInvalidMerkleProof_receiveMessage(
        bytes32 rangeHash,
        bytes calldata data,
        bytes32 from,
        uint64 messageId,
        bytes32[] calldata wrongProof,
        uint256 wrongLeafIndex
    ) external {
        vm.assume(wrongLeafIndex != 0 && wrongProof.length != 0);
        MessageReceiverMock messageReceiver = new MessageReceiverMock();
        messageReceiver.initialize(address(bridge));

        AvailBridge.Message memory message =
            AvailBridge.Message(0x01, from, bytes32(bytes20(address(messageReceiver))), 1, 2, data, messageId);
        bytes32 messageHash = keccak256(abi.encode(message));
        bytes32 dataRoot = keccak256(abi.encode(bytes32(0), messageHash));

        vectorx.set(rangeHash, dataRoot);

        bytes32[] memory emptyArr;
        // give a fuzzed wrong index
        AvailBridge.MerkleProofInput memory input = AvailBridge.MerkleProofInput(
            emptyArr, emptyArr, rangeHash, 0, bytes32(0), messageHash, messageHash, wrongLeafIndex
        );

        vm.expectRevert(AvailBridge.InvalidMerkleProof.selector);
        bridge.receiveMessage(message, input);
        assertEq(bridge.isBridged(messageHash), false);
        // give a fuzzed wrong proof
        input =
            AvailBridge.MerkleProofInput(emptyArr, wrongProof, rangeHash, 0, bytes32(0), messageHash, messageHash, 0);

        vm.expectRevert(AvailBridge.InvalidMerkleProof.selector);
        bridge.receiveMessage(message, input);
        assertEq(bridge.isBridged(messageHash), false);

        // give a fuzzed wrong proof and index
        input = AvailBridge.MerkleProofInput(
            emptyArr, wrongProof, rangeHash, 0, bytes32(0), messageHash, messageHash, wrongLeafIndex
        );

        vm.expectRevert(AvailBridge.InvalidMerkleProof.selector);
        bridge.receiveMessage(message, input);
        assertEq(bridge.isBridged(messageHash), false);
    }

    function testRevertDataRootCommitmentEmpty_receiveMessage(
        bytes32 rangeHash,
        bytes calldata data,
        bytes32 from,
        uint64 messageId
    ) external {
        MessageReceiverMock messageReceiver = new MessageReceiverMock();
        messageReceiver.initialize(address(bridge));

        AvailBridge.Message memory message =
            AvailBridge.Message(0x01, from, bytes32(bytes20(address(messageReceiver))), 1, 2, data, messageId);
        bytes32 messageHash = keccak256(abi.encode(message));

        bytes32[] memory emptyArr;
        AvailBridge.MerkleProofInput memory input = AvailBridge.MerkleProofInput(
            emptyArr, emptyArr, rangeHash, 0, bytes32(0), messageHash, messageHash, 0
        );

        // data root is not set in vectorx!
        vm.expectRevert(AvailBridge.DataRootCommitmentEmpty.selector);
        bridge.receiveMessage(message, input);
        assertEq(bridge.isBridged(messageHash), false);
    }

    function testRevertInvalidDataRootProof_receiveMessage(
        bytes32 rangeHash,
        bytes calldata data,
        bytes32 from,
        uint64 messageId,
        bytes32[] calldata wrongProof,
        uint256 wrongIndex
    ) external {
        vm.assume(wrongIndex != 0 && wrongProof.length != 0);
        MessageReceiverMock messageReceiver = new MessageReceiverMock();
        messageReceiver.initialize(address(bridge));

        AvailBridge.Message memory message =
            AvailBridge.Message(0x01, from, bytes32(bytes20(address(messageReceiver))), 1, 2, data, messageId);
        bytes32 messageHash = keccak256(abi.encode(message));
        bytes32 dataRoot = keccak256(abi.encode(bytes32(0), messageHash));

        vectorx.set(rangeHash, dataRoot);

        bytes32[] memory emptyArr;
        // give fuzzed wrong proof
        AvailBridge.MerkleProofInput memory input = AvailBridge.MerkleProofInput(
            wrongProof, emptyArr, rangeHash, 0, bytes32(0), messageHash, messageHash, 0
        );

        vm.expectRevert(AvailBridge.InvalidDataRootProof.selector);
        bridge.receiveMessage(message, input);
        assertEq(bridge.isBridged(messageHash), false);

        // give fuzzed wrong index
        input = AvailBridge.MerkleProofInput(
            emptyArr, emptyArr, rangeHash, wrongIndex, bytes32(0), messageHash, messageHash, 0
        );

        vm.expectRevert(AvailBridge.InvalidDataRootProof.selector);
        bridge.receiveMessage(message, input);
        assertEq(bridge.isBridged(messageHash), false);

        // give fuzzed wrong proof and wrong index
        input = AvailBridge.MerkleProofInput(
            wrongProof, emptyArr, rangeHash, wrongIndex, bytes32(0), messageHash, messageHash, 0
        );

        vm.expectRevert(AvailBridge.InvalidDataRootProof.selector);
        bridge.receiveMessage(message, input);
        assertEq(bridge.isBridged(messageHash), false);
    }

    function testRevertInvalidAssetId_receiveAvail(bytes32 assetId) external {
        vm.assume(assetId != 0x0);
        AvailBridge.Message memory message =
            AvailBridge.Message(0x02, bytes32(0), bytes32(0), 1, 2, abi.encode(assetId, 0), 0);
        AvailBridge.MerkleProofInput memory input = AvailBridge.MerkleProofInput(
            new bytes32[](0), new bytes32[](0), bytes32(0), 0, bytes32(0), bytes32(0), bytes32(0), 0
        );
        vm.expectRevert(AvailBridge.InvalidAssetId.selector);
        bridge.receiveAVL(message, input);
    }

    function test_receiveAVL(bytes32 rangeHash, bytes32 from, uint256 amount, uint64 messageId) external {
        vm.assume(amount != 0);
        address to = makeAddr("to");
        AvailBridge.Message memory message =
            AvailBridge.Message(0x02, from, bytes32(bytes20(to)), 1, 2, abi.encode(bytes32(0), amount), messageId);
        bytes32 messageHash = keccak256(abi.encode(message));
        bytes32 dataRoot = keccak256(abi.encode(bytes32(0), messageHash));

        vectorx.set(rangeHash, dataRoot);

        bytes32[] memory emptyArr;
        AvailBridge.MerkleProofInput memory input =
            AvailBridge.MerkleProofInput(emptyArr, emptyArr, rangeHash, 0, bytes32(0), messageHash, messageHash, 0);

        vm.expectCall(address(avail), abi.encodeCall(avail.mint, (to, amount)));
        bridge.receiveAVL(message, input);
        assertEq(avail.totalSupply(), amount);
    }

    function testRevertInvalidAssetId_receiveETH(bytes32 assetId) external {
        vm.assume(assetId != 0x4554480000000000000000000000000000000000000000000000000000000000);
        AvailBridge.Message memory message =
            AvailBridge.Message(0x02, bytes32(0), bytes32(0), 1, 2, abi.encode(assetId, 0), 0);
        AvailBridge.MerkleProofInput memory input = AvailBridge.MerkleProofInput(
            new bytes32[](0), new bytes32[](0), bytes32(0), 0, bytes32(0), bytes32(0), bytes32(0), 0
        );
        vm.expectRevert(AvailBridge.InvalidAssetId.selector);
        bridge.receiveETH(message, input);
    }

    function testRevertUnlockFailed_receiveETH(bytes32 rangeHash, bytes32 from, uint256 amount, uint64 messageId)
        external
    {
        vm.assume(amount != 0);
        address to = makeAddr("to");
        vm.deal(address(bridge), amount);
        AvailBridge.Message memory message = AvailBridge.Message(
            0x02,
            from,
            bytes32(bytes20(to)),
            1,
            2,
            abi.encode(0x4554480000000000000000000000000000000000000000000000000000000000, amount),
            messageId
        );
        bytes32 messageHash = keccak256(abi.encode(message));
        bytes32 dataRoot = keccak256(abi.encode(bytes32(0), messageHash));

        vectorx.set(rangeHash, dataRoot);

        bytes32[] memory emptyArr;
        AvailBridge.MerkleProofInput memory input =
            AvailBridge.MerkleProofInput(emptyArr, emptyArr, rangeHash, 0, bytes32(0), messageHash, messageHash, 0);

        vm.etch(to, revertCode);
        vm.expectRevert(AvailBridge.UnlockFailed.selector);
        bridge.receiveETH(message, input);
        assertEq(address(bridge).balance, amount);
    }

    function test_receiveETH(bytes32 rangeHash, bytes32 from, uint256 amount, uint64 messageId) external {
        vm.assume(amount != 0);
        address to = makeAddr("to");
        vm.deal(address(bridge), amount);
        AvailBridge.Message memory message = AvailBridge.Message(
            0x02,
            from,
            bytes32(bytes20(to)),
            1,
            2,
            abi.encode(0x4554480000000000000000000000000000000000000000000000000000000000, amount),
            messageId
        );
        bytes32 messageHash = keccak256(abi.encode(message));
        bytes32 dataRoot = keccak256(abi.encode(bytes32(0), messageHash));

        vectorx.set(rangeHash, dataRoot);

        bytes32[] memory emptyArr;
        AvailBridge.MerkleProofInput memory input =
            AvailBridge.MerkleProofInput(emptyArr, emptyArr, rangeHash, 0, bytes32(0), messageHash, messageHash, 0);

        uint256 balance = to.balance;
        bridge.receiveETH(message, input);
        assertEq(to.balance, balance + amount);
    }

    function testRevertInvalidAssetId_receiveERC20(bytes32 assetId) external {
        AvailBridge.Message memory message =
            AvailBridge.Message(0x02, bytes32(0), bytes32(0), 1, 2, abi.encode(assetId, 0), 0);
        AvailBridge.MerkleProofInput memory input = AvailBridge.MerkleProofInput(
            new bytes32[](0), new bytes32[](0), bytes32(0), 0, bytes32(0), bytes32(0), bytes32(0), 0
        );
        vm.expectRevert(AvailBridge.InvalidAssetId.selector);
        bridge.receiveERC20(message, input);
    }

    function test_receiveERC20(bytes32 rangeHash, bytes32 assetId, bytes32 from, uint256 amount, uint64 messageId)
        external
    {
        vm.assume(amount != 0);
        address to = makeAddr("to");
        ERC20Mock token = new ERC20Mock();
        token.mint(address(bridge), amount);
        bytes32[] memory assetIdArr = new bytes32[](1);
        assetIdArr[0] = assetId;
        address[] memory tokenArr = new address[](1);
        tokenArr[0] = address(token);
        vm.prank(owner);
        bridge.updateTokens(assetIdArr, tokenArr);
        AvailBridge.Message memory message =
            AvailBridge.Message(0x02, from, bytes32(bytes20(to)), 1, 2, abi.encode(assetId, amount), messageId);
        bytes32 messageHash = keccak256(abi.encode(message));
        bytes32 dataRoot = keccak256(abi.encode(bytes32(0), messageHash));

        vectorx.set(rangeHash, dataRoot);

        bytes32[] memory emptyArr;
        AvailBridge.MerkleProofInput memory input =
            AvailBridge.MerkleProofInput(emptyArr, emptyArr, rangeHash, 0, bytes32(0), messageHash, messageHash, 0);

        uint256 balance = token.balanceOf(to);
        bridge.receiveERC20(message, input);
        uint256 newBalance = token.balanceOf(to);
        assertEq(newBalance, balance + amount);
    }

    function test_sendAVL(bytes32 to, uint256 amount) external {
        vm.assume(to != bytes32(0) && amount != 0);
        address from = makeAddr("from");
        vm.prank(address(bridge));
        avail.mint(from, amount);
        AvailBridge.Message memory message =
            AvailBridge.Message(0x02, bytes32(bytes20(from)), to, 2, 1, abi.encode(bytes32(0), amount), 0);
        vm.expectCall(address(avail), abi.encodeCall(avail.burn, (from, amount)));
        vm.prank(from);
        bridge.sendAVL(to, amount);
        assertEq(bridge.isSent(0), keccak256(abi.encode(message)));
        assertEq(avail.balanceOf(from), 0);
        assertEq(avail.totalSupply(), 0);
    }

    function test_sendETH(bytes32 to, uint256 amount) external {
        vm.assume(to != bytes32(0) && amount != 0);
        address from = makeAddr("from");
        vm.deal(from, amount);
        AvailBridge.Message memory message = AvailBridge.Message(
            0x02,
            bytes32(bytes20(from)),
            to,
            2,
            1,
            abi.encode(0x4554480000000000000000000000000000000000000000000000000000000000, amount),
            0
        );
        uint256 balance = from.balance;
        vm.prank(from);
        bridge.sendETH{value: amount}(to);
        assertEq(address(bridge).balance, amount);
        assertEq(bridge.isSent(0), keccak256(abi.encode(message)));
        assertEq(from.balance, balance - amount);
    }

    function testRevertInvalidAssetId_sendERC20(bytes32 assetId, bytes32 dest, uint256 amount) external {
        vm.assume(dest != 0x0 && amount != 0);
        vm.expectRevert(AvailBridge.InvalidAssetId.selector);
        bridge.sendERC20(assetId, dest, amount);
    }

    function test_sendERC20(bytes32 assetId, bytes32 to, uint256 amount) external {
        vm.assume(to != bytes32(0) && amount != 0);
        address from = makeAddr("from");
        ERC20Mock token = new ERC20Mock();
        token.mint(from, amount);
        bytes32[] memory assetIdArr = new bytes32[](1);
        assetIdArr[0] = assetId;
        address[] memory tokenArr = new address[](1);
        tokenArr[0] = address(token);
        vm.prank(owner);
        bridge.updateTokens(assetIdArr, tokenArr);
        AvailBridge.Message memory message =
            AvailBridge.Message(0x02, bytes32(bytes20(from)), to, 2, 1, abi.encode(assetId, amount), 0);
        vm.startPrank(from);
        token.approve(address(bridge), amount);
        vm.expectCall(address(token), abi.encodeCall(token.transferFrom, (from, address(bridge), amount)));
        bridge.sendERC20(assetId, to, amount);
        assertEq(bridge.isSent(0), keccak256(abi.encode(message)));
        assertEq(token.balanceOf(from), 0);
        assertEq(token.balanceOf(address(bridge)), amount);
    }

    function testRevertBlobRootEmpty_verifyBlobLeaf(AvailBridge.MerkleProofInput memory input) external {
        input.blobRoot = 0x0;
        vm.expectRevert(AvailBridge.BlobRootEmpty.selector);
        bridge.verifyBlobLeaf(input);
    }

    function test_verifyBlobLeaf(
        bytes32[16] calldata preimages,
        bytes32[16] calldata c_dataRoots,
        bytes32 rangeHash,
        uint256 rand,
        bytes32 bridgeRoot
    ) external {
        // we use a fixed size array because the fuzzer rejects too many inputs with arbitrary lengths
        bytes32[] memory dataRoots = new bytes32[](c_dataRoots.length);
        bytes32[] memory leaves = new bytes32[](preimages.length);
        for (uint256 i = 0; i < preimages.length;) {
            dataRoots[i] = c_dataRoots[i];
            leaves[i] = keccak256(abi.encode(preimages[i]));
            unchecked {
                ++i;
            }
        }
        bytes32 blobRoot = getRoot(leaves);
        bytes32 dataRoot = hashLeafPairs(blobRoot, bridgeRoot);
        // set dataRoot at this point in the array
        dataRoots[rand % dataRoots.length] = dataRoot;
        bytes32 dataRootCommitment = getRoot(dataRoots);
        bytes32[] memory dataRootProof = getProof(dataRoots, rand % dataRoots.length);
        vectorx.set(rangeHash, dataRootCommitment);
        for (uint256 i = 0; i < leaves.length;) {
            bytes32[] memory leafProof = getProof(leaves, i);
            AvailBridge.MerkleProofInput memory input = AvailBridge.MerkleProofInput(
                dataRootProof, leafProof, rangeHash, rand % dataRoots.length, blobRoot, bridgeRoot, preimages[i], i
            );
            assertTrue(bridge.verifyBlobLeaf(input));
            unchecked {
                ++i;
            }
        }
    }

    function testRevertBridgeRootEmpty_verifyBridgeLeaf(AvailBridge.MerkleProofInput memory input) external {
        input.bridgeRoot = 0x0;
        vm.expectRevert(AvailBridge.BridgeRootEmpty.selector);
        bridge.verifyBridgeLeaf(input);
    }

    function test_verifyBridgeLeaf(
        bytes32[16] calldata c_leaves,
        bytes32[16] calldata c_dataRoots,
        bytes32 rangeHash,
        uint256 rand,
        bytes32 blobRoot
    ) external {
        // we use a fixed size array because the fuzzer rejects too many inputs with arbitrary lengths
        bytes32[] memory dataRoots = new bytes32[](c_dataRoots.length);
        bytes32[] memory leaves = new bytes32[](c_leaves.length);
        for (uint256 i = 0; i < c_leaves.length;) {
            dataRoots[i] = c_dataRoots[i];
            leaves[i] = c_leaves[i];
            unchecked {
                ++i;
            }
        }
        bytes32 bridgeRoot = getRoot(leaves);
        bytes32 dataRoot = hashLeafPairs(blobRoot, bridgeRoot);
        // set dataRoot at this point in the array
        dataRoots[rand % dataRoots.length] = dataRoot;
        bytes32 dataRootCommitment = getRoot(dataRoots);
        bytes32[] memory dataRootProof = getProof(dataRoots, rand % dataRoots.length);
        vectorx.set(rangeHash, dataRootCommitment);
        for (uint256 i = 0; i < leaves.length;) {
            bytes32[] memory leafProof = getProof(leaves, i);
            AvailBridge.MerkleProofInput memory input = AvailBridge.MerkleProofInput(
                dataRootProof, leafProof, rangeHash, rand % dataRoots.length, blobRoot, bridgeRoot, leaves[i], i
            );
            assertTrue(bridge.verifyBridgeLeaf(input));
            unchecked {
                ++i;
            }
        }
    }

    function hashLeafPairs(bytes32 left, bytes32 right) public pure override returns (bytes32) {
        return keccak256(abi.encode(left, right));
    }
}
