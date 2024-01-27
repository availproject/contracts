// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.23;

import {TransparentUpgradeableProxy} from
    "lib/openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ProxyAdmin} from "lib/openzeppelin-contracts/contracts/proxy/transparent/ProxyAdmin.sol";
import {IAccessControl} from "lib/openzeppelin-contracts/contracts/access/IAccessControl.sol";
import {Pausable} from "lib/openzeppelin-contracts/contracts/utils/Pausable.sol";
import {IAvailBridge, AvailBridge} from "src/AvailBridge.sol";
import {WrappedAvail, IWrappedAvail} from "src/WrappedAvail.sol";
import {VectorxMock, IVectorx} from "src/mocks/VectorxMock.sol";
import {ERC20Mock} from "src/mocks/ERC20Mock.sol";
import {MessageReceiverMock} from "src/mocks/MessageReceiverMock.sol";
import {MurkyBase} from "lib/murky/src/common/MurkyBase.sol";
import {Vm, Test, console} from "forge-std/Test.sol";

contract AvailBridgeTest is Test, MurkyBase {
    AvailBridge public bridge;
    WrappedAvail public avail;
    VectorxMock public vectorx;
    ProxyAdmin public admin;
    Sha2Merkle public sha2merkle;
    address public owner;
    address public pauser;
    bytes public constant revertCode = "5F5FFD";

    function setUp() external {
        vectorx = new VectorxMock();
        admin = new ProxyAdmin(msg.sender);
        pauser = makeAddr("pauser");
        sha2merkle = new Sha2Merkle();
        address impl = address(new AvailBridge());
        bridge = AvailBridge(address(new TransparentUpgradeableProxy(impl, address(admin), "")));
        avail = new WrappedAvail(address(bridge));
        bridge.initialize(0, msg.sender, IWrappedAvail(address(avail)), msg.sender, pauser, IVectorx(vectorx));
        owner = msg.sender;
    }

    function test_owner() external {
        assertNotEq(bridge.owner(), address(0));
        assertEq(bridge.owner(), owner);
    }

    function test_feeRecipient() external {
        assertNotEq(bridge.feeRecipient(), address(0));
        assertEq(bridge.feeRecipient(), owner);
    }

    function testRevertUnauthorizedAccount_setFeePerByte(uint256 feePerByte) external {
        address rand = makeAddr("rand");
        vm.assume(rand != owner);
        vm.expectRevert(abi.encodeWithSelector((IAccessControl.AccessControlUnauthorizedAccount.selector), rand, 0x0));
        vm.prank(rand);
        bridge.updateFeePerByte(feePerByte);
    }

    function test_setFeePerByte(uint256 feePerByte) external {
        vm.prank(owner);
        bridge.updateFeePerByte(feePerByte);
        assertEq(bridge.feePerByte(), feePerByte);
    }

    function testRevertUnauthorizedAccount_updateVectorx(IVectorx newVectorx) external {
        address rand = makeAddr("rand");
        vm.assume(rand != owner);
        vm.expectRevert(abi.encodeWithSelector((IAccessControl.AccessControlUnauthorizedAccount.selector), rand, 0x0));
        vm.prank(rand);
        bridge.updateVectorx(newVectorx);
    }

    function test_updateVectorx(IVectorx newVectorx) external {
        vm.prank(owner);
        bridge.updateVectorx(newVectorx);
        assertEq(address(bridge.vectorx()), address(newVectorx));
    }

    function testRevertUnauthorizedAccount_updateFeeRecipient(address newFeeRecipient) external {
        address rand = makeAddr("rand");
        vm.assume(rand != owner);
        vm.expectRevert(abi.encodeWithSelector((IAccessControl.AccessControlUnauthorizedAccount.selector), rand, 0x0));
        vm.prank(rand);
        bridge.updateFeeRecipient(newFeeRecipient);
    }

    function test_updateFeeRecipient(address newFeeRecipient) external {
        vm.prank(owner);
        bridge.updateFeeRecipient(newFeeRecipient);
        assertEq(bridge.feeRecipient(), newFeeRecipient);
    }

    function testRevertUnauthorizedAccount_updateTokens() external {
        address rand = makeAddr("rand");
        vm.assume(rand != owner);
        vm.expectRevert(abi.encodeWithSelector((IAccessControl.AccessControlUnauthorizedAccount.selector), rand, 0x0));
        vm.prank(rand);
        bridge.updateTokens(new bytes32[](0), new address[](0));
    }

    function testRevertArrayLengthMismatch_updateTokens(uint8 len1, uint8 len2) external {
        // using len > uint8 slows tests by a *lot*
        vm.assume(len1 != len2);
        bytes32[] memory assetIds = new bytes32[](len1);
        address[] memory addresses = new address[](len2);
        vm.prank(owner);
        vm.expectRevert(IAvailBridge.ArrayLengthMismatch.selector);
        bridge.updateTokens(assetIds, addresses);
    }

    function test_updateTokens(uint256 val1, uint256 val2, uint8 len) external {
        // we do this to get unique assetIds and addresses
        bytes32[] memory assetIds = new bytes32[](len);
        address[] memory addresses = new address[](len);
        for (uint256 i = 0; i < len;) {
            assetIds[i] = keccak256(abi.encode(val1, i));
            addresses[i] = makeAddr(string(abi.encode(val2, i)));
            unchecked {
                ++i;
            }
        }
        vm.prank(owner);
        bridge.updateTokens(assetIds, addresses);
        for (uint256 i = 0; i < len;) {
            assertEq(bridge.tokens(assetIds[i]), addresses[i]);
            unchecked {
                ++i;
            }
        }
    }

    function testRevertInvalidMessage_receiveMessage(bytes1 prefix) external {
        vm.assume(prefix != 0x01);
        IAvailBridge.Message memory message = IAvailBridge.Message(prefix, bytes32(0), bytes32(0), 1, 2, "", 0);
        IAvailBridge.MerkleProofInput memory input = IAvailBridge.MerkleProofInput(
            new bytes32[](0), new bytes32[](0), bytes32(0), 0, bytes32(0), bytes32(0), bytes32(0), 0
        );
        vm.expectRevert(IAvailBridge.InvalidMessage.selector);
        bridge.receiveMessage(message, input);
        assertFalse(bridge.isBridged(keccak256(abi.encode(message))));
    }

    function testRevertOnlyPauser_setPaused(bool status) external {
        address rand = makeAddr("rand");
        vm.expectRevert(
            abi.encodeWithSelector(
                (IAccessControl.AccessControlUnauthorizedAccount.selector), rand, keccak256("PAUSER_ROLE")
            )
        );
        vm.prank(rand);
        bridge.setPaused(status);
    }

    function test_setPaused() external {
        vm.startPrank(pauser);
        bridge.setPaused(true);
        assertTrue(bridge.paused());
        bridge.setPaused(false);
        assertFalse(bridge.paused());
    }

    function test_setPausedWithMessage(bytes32 rangeHash, bytes calldata data, bytes32 from, uint64 messageId)
        external
    {
        vm.startPrank(pauser);
        bridge.setPaused(true);
        assertTrue(bridge.paused());
        MessageReceiverMock messageReceiver = new MessageReceiverMock();
        messageReceiver.initialize(address(bridge));

        IAvailBridge.Message memory message =
            IAvailBridge.Message(0x01, from, bytes32(bytes20(address(messageReceiver))), 1, 2, data, messageId);
        bytes32 messageHash = keccak256(abi.encode(message));
        bytes32 dataRoot = keccak256(abi.encode(bytes32(0), messageHash));

        vectorx.set(rangeHash, dataRoot);

        bytes32[] memory emptyArr;
        IAvailBridge.MerkleProofInput memory input =
            IAvailBridge.MerkleProofInput(emptyArr, emptyArr, rangeHash, 0, bytes32(0), messageHash, messageHash, 0);

        vm.expectRevert(Pausable.EnforcedPause.selector);
        bridge.receiveMessage(message, input);
        assertFalse(bridge.isBridged(messageHash));
        bridge.setPaused(false);
        assertFalse(bridge.paused());
        vm.expectCall(address(messageReceiver), abi.encodeCall(messageReceiver.onAvailMessage, (from, data)));
        bridge.receiveMessage(message, input);
        assertTrue(bridge.isBridged(messageHash));
    }

    function test_receiveMessage(bytes32 rangeHash, bytes calldata data, bytes32 from, uint64 messageId) external {
        MessageReceiverMock messageReceiver = new MessageReceiverMock();
        messageReceiver.initialize(address(bridge));

        IAvailBridge.Message memory message =
            IAvailBridge.Message(0x01, from, bytes32(bytes20(address(messageReceiver))), 1, 2, data, messageId);
        bytes32 messageHash = keccak256(abi.encode(message));
        bytes32 dataRoot = keccak256(abi.encode(bytes32(0), messageHash));

        vectorx.set(rangeHash, dataRoot);

        bytes32[] memory emptyArr;
        IAvailBridge.MerkleProofInput memory input =
            IAvailBridge.MerkleProofInput(emptyArr, emptyArr, rangeHash, 0, bytes32(0), messageHash, messageHash, 0);

        vm.expectCall(address(messageReceiver), abi.encodeCall(messageReceiver.onAvailMessage, (from, data)));
        bridge.receiveMessage(message, input);
        assertTrue(bridge.isBridged(messageHash));
    }

    function testRevertAlreadyBridged_receiveMessage(
        bytes32 rangeHash,
        bytes calldata data,
        bytes32 from,
        uint64 messageId
    ) external {
        MessageReceiverMock messageReceiver = new MessageReceiverMock();
        messageReceiver.initialize(address(bridge));

        IAvailBridge.Message memory message =
            IAvailBridge.Message(0x01, from, bytes32(bytes20(address(messageReceiver))), 1, 2, data, messageId);
        bytes32 messageHash = keccak256(abi.encode(message));
        bytes32 dataRoot = keccak256(abi.encode(bytes32(0), messageHash));

        vectorx.set(rangeHash, dataRoot);

        bytes32[] memory emptyArr;
        IAvailBridge.MerkleProofInput memory input =
            IAvailBridge.MerkleProofInput(emptyArr, emptyArr, rangeHash, 0, bytes32(0), messageHash, messageHash, 0);

        vm.expectCall(address(messageReceiver), abi.encodeCall(messageReceiver.onAvailMessage, (from, data)));
        bridge.receiveMessage(message, input);
        assertTrue(bridge.isBridged(messageHash));
        vm.expectRevert(IAvailBridge.AlreadyBridged.selector);
        bridge.receiveMessage(message, input);
        assertTrue(bridge.isBridged(messageHash));
    }

    function testRevertInvalidLeaf_receiveMessage(
        bytes32 rangeHash,
        bytes calldata data,
        bytes32 from,
        uint64 messageId
    ) external {
        MessageReceiverMock messageReceiver = new MessageReceiverMock();
        messageReceiver.initialize(address(bridge));

        IAvailBridge.Message memory message =
            IAvailBridge.Message(0x01, from, bytes32(bytes20(address(messageReceiver))), 1, 2, data, messageId);
        bytes32 messageHash = keccak256(abi.encode(message));
        bytes32 dataRoot = keccak256(abi.encode(bytes32(0), messageHash));

        vectorx.set(rangeHash, dataRoot);

        bytes32[] memory emptyArr;
        // hash the hash to generate a wrong leaf
        IAvailBridge.MerkleProofInput memory input = IAvailBridge.MerkleProofInput(
            emptyArr, emptyArr, rangeHash, 0, bytes32(0), messageHash, keccak256(abi.encode(messageHash)), 0
        );

        vm.expectRevert(IAvailBridge.InvalidLeaf.selector);
        bridge.receiveMessage(message, input);
        assertFalse(bridge.isBridged(messageHash));
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

        IAvailBridge.Message memory message =
            IAvailBridge.Message(0x01, from, bytes32(bytes20(address(messageReceiver))), 1, 2, data, messageId);
        bytes32 messageHash = keccak256(abi.encode(message));
        bytes32 dataRoot = keccak256(abi.encode(bytes32(0), messageHash));

        vectorx.set(rangeHash, dataRoot);

        bytes32[] memory emptyArr;
        // give a fuzzed wrong index
        IAvailBridge.MerkleProofInput memory input = IAvailBridge.MerkleProofInput(
            emptyArr, emptyArr, rangeHash, 0, bytes32(0), messageHash, messageHash, wrongLeafIndex
        );

        vm.expectRevert(IAvailBridge.InvalidMerkleProof.selector);
        bridge.receiveMessage(message, input);
        assertFalse(bridge.isBridged(messageHash));
        // give a fuzzed wrong proof
        input =
            IAvailBridge.MerkleProofInput(emptyArr, wrongProof, rangeHash, 0, bytes32(0), messageHash, messageHash, 0);

        vm.expectRevert(IAvailBridge.InvalidMerkleProof.selector);
        bridge.receiveMessage(message, input);
        assertFalse(bridge.isBridged(messageHash));

        // give a fuzzed wrong proof and index
        input = IAvailBridge.MerkleProofInput(
            emptyArr, wrongProof, rangeHash, 0, bytes32(0), messageHash, messageHash, wrongLeafIndex
        );

        vm.expectRevert(IAvailBridge.InvalidMerkleProof.selector);
        bridge.receiveMessage(message, input);
        assertFalse(bridge.isBridged(messageHash));
    }

    function testRevertDataRootCommitmentEmpty_receiveMessage(
        bytes32 rangeHash,
        bytes calldata data,
        bytes32 from,
        uint64 messageId
    ) external {
        MessageReceiverMock messageReceiver = new MessageReceiverMock();
        messageReceiver.initialize(address(bridge));

        IAvailBridge.Message memory message =
            IAvailBridge.Message(0x01, from, bytes32(bytes20(address(messageReceiver))), 1, 2, data, messageId);
        bytes32 messageHash = keccak256(abi.encode(message));

        bytes32[] memory emptyArr;
        IAvailBridge.MerkleProofInput memory input =
            IAvailBridge.MerkleProofInput(emptyArr, emptyArr, rangeHash, 0, bytes32(0), messageHash, messageHash, 0);

        // data root is not set in vectorx!
        vm.expectRevert(IAvailBridge.DataRootCommitmentEmpty.selector);
        bridge.receiveMessage(message, input);
        assertFalse(bridge.isBridged(messageHash));
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

        IAvailBridge.Message memory message =
            IAvailBridge.Message(0x01, from, bytes32(bytes20(address(messageReceiver))), 1, 2, data, messageId);
        bytes32 messageHash = keccak256(abi.encode(message));
        bytes32 dataRoot = keccak256(abi.encode(bytes32(0), messageHash));

        vectorx.set(rangeHash, dataRoot);

        bytes32[] memory emptyArr;
        // give fuzzed wrong proof
        IAvailBridge.MerkleProofInput memory input =
            IAvailBridge.MerkleProofInput(wrongProof, emptyArr, rangeHash, 0, bytes32(0), messageHash, messageHash, 0);

        vm.expectRevert(IAvailBridge.InvalidDataRootProof.selector);
        bridge.receiveMessage(message, input);
        assertFalse(bridge.isBridged(messageHash));

        // give fuzzed wrong index
        input = IAvailBridge.MerkleProofInput(
            emptyArr, emptyArr, rangeHash, wrongIndex, bytes32(0), messageHash, messageHash, 0
        );

        vm.expectRevert(IAvailBridge.InvalidDataRootProof.selector);
        bridge.receiveMessage(message, input);
        assertFalse(bridge.isBridged(messageHash));

        // give fuzzed wrong proof and wrong index
        input = IAvailBridge.MerkleProofInput(
            wrongProof, emptyArr, rangeHash, wrongIndex, bytes32(0), messageHash, messageHash, 0
        );

        vm.expectRevert(IAvailBridge.InvalidDataRootProof.selector);
        bridge.receiveMessage(message, input);
        assertFalse(bridge.isBridged(messageHash));
    }

    function testRevertInvalidAssetId_receiveAvail(bytes32 assetId) external {
        vm.assume(assetId != 0x0);
        IAvailBridge.Message memory message =
            IAvailBridge.Message(0x02, bytes32(0), bytes32(0), 1, 2, abi.encode(assetId, 0), 0);
        IAvailBridge.MerkleProofInput memory input = IAvailBridge.MerkleProofInput(
            new bytes32[](0), new bytes32[](0), bytes32(0), 0, bytes32(0), bytes32(0), bytes32(0), 0
        );
        vm.expectRevert(IAvailBridge.InvalidAssetId.selector);
        bridge.receiveAVAIL(message, input);
        assertFalse(bridge.isBridged(keccak256(abi.encode(message))));
    }

    function test_receiveAVAIL(bytes32 rangeHash, bytes32 from, uint256 amount, uint64 messageId) external {
        vm.assume(amount != 0);
        address to = makeAddr("to");
        IAvailBridge.Message memory message =
            IAvailBridge.Message(0x02, from, bytes32(bytes20(to)), 1, 2, abi.encode(bytes32(0), amount), messageId);
        bytes32 messageHash = keccak256(abi.encode(message));
        bytes32 dataRoot = keccak256(abi.encode(bytes32(0), messageHash));

        vectorx.set(rangeHash, dataRoot);

        bytes32[] memory emptyArr;
        IAvailBridge.MerkleProofInput memory input =
            IAvailBridge.MerkleProofInput(emptyArr, emptyArr, rangeHash, 0, bytes32(0), messageHash, messageHash, 0);

        vm.expectCall(address(avail), abi.encodeCall(avail.mint, (to, amount)));
        bridge.receiveAVAIL(message, input);
        assertTrue(bridge.isBridged(messageHash));
        assertEq(avail.totalSupply(), amount);
    }

    function test_receiveAVAIL_2(
        bytes32 rangeHash,
        uint64 messageId,
        bytes32[16] calldata c_leaves,
        bytes32[16] calldata c_dataRoots,
        uint256 rand,
        bytes32 blobRoot
    ) external {
        // this function is a bit unreadable because forge coverage does not support IR compilation which results
        // in stack too deep errors
        bytes32[] memory dataRoots = new bytes32[](c_dataRoots.length);
        bytes32[] memory leaves = new bytes32[](c_leaves.length);
        for (uint256 i = 0; i < c_leaves.length;) {
            dataRoots[i] = c_dataRoots[i];
            leaves[i] = c_leaves[i];
            unchecked {
                ++i;
            }
        }
        address to = makeAddr("to");
        leaves[rand % leaves.length] = keccak256(
            abi.encode(
                IAvailBridge.Message(
                    0x02, bytes32("1"), bytes32(bytes20(to)), 1, 2, abi.encode(bytes32(0), 1), messageId
                )
            )
        );
        // set dataRoot at this point in the array
        dataRoots[rand % dataRoots.length] = hashLeafPairs(blobRoot, getRoot(leaves));
        vectorx.set(rangeHash, sha2merkle.getRoot(dataRoots));

        vm.expectCall(address(avail), abi.encodeCall(avail.mint, (to, 1)));
        {
            bridge.receiveAVAIL(
                IAvailBridge.Message(
                    0x02, bytes32("1"), bytes32(bytes20(to)), 1, 2, abi.encode(bytes32(0), 1), messageId
                ),
                IAvailBridge.MerkleProofInput(
                    sha2merkle.getProof(dataRoots, rand % dataRoots.length),
                    getProof(leaves, rand % leaves.length),
                    rangeHash,
                    rand % dataRoots.length,
                    blobRoot,
                    getRoot(leaves),
                    keccak256(
                        abi.encode(
                            IAvailBridge.Message(
                                0x02, bytes32("1"), bytes32(bytes20(to)), 1, 2, abi.encode(bytes32(0), 1), messageId
                            )
                        )
                    ),
                    rand % leaves.length
                )
            );
        }
        {
            assertTrue(
                bridge.isBridged(
                    keccak256(
                        abi.encode(
                            IAvailBridge.Message(
                                0x02, bytes32("1"), bytes32(bytes20(to)), 1, 2, abi.encode(bytes32(0), 1), messageId
                            )
                        )
                    )
                )
            );
        }
        {
            assertEq(avail.totalSupply(), 1);
        }
    }

    function testRevertInvalidAssetId_receiveETH(bytes32 assetId) external {
        vm.assume(assetId != 0x4554480000000000000000000000000000000000000000000000000000000000);
        IAvailBridge.Message memory message =
            IAvailBridge.Message(0x02, bytes32(0), bytes32(0), 1, 2, abi.encode(assetId, 0), 0);
        IAvailBridge.MerkleProofInput memory input = IAvailBridge.MerkleProofInput(
            new bytes32[](0), new bytes32[](0), bytes32(0), 0, bytes32(0), bytes32(0), bytes32(0), 0
        );
        vm.expectRevert(IAvailBridge.InvalidAssetId.selector);
        bridge.receiveETH(message, input);
        assertFalse(bridge.isBridged(keccak256(abi.encode(message))));
    }

    function testRevertUnlockFailed_receiveETH(bytes32 rangeHash, bytes32 from, uint256 amount, uint64 messageId)
        external
    {
        vm.assume(amount != 0);
        address to = makeAddr("to");
        vm.deal(address(bridge), amount);
        IAvailBridge.Message memory message = IAvailBridge.Message(
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
        IAvailBridge.MerkleProofInput memory input =
            IAvailBridge.MerkleProofInput(emptyArr, emptyArr, rangeHash, 0, bytes32(0), messageHash, messageHash, 0);

        vm.etch(to, revertCode);
        vm.expectRevert(IAvailBridge.UnlockFailed.selector);
        bridge.receiveETH(message, input);
        assertEq(address(bridge).balance, amount);
        assertFalse(bridge.isBridged(messageHash));
    }

    function test_receiveETH(bytes32 rangeHash, bytes32 from, uint256 amount, uint64 messageId) external {
        vm.assume(amount != 0);
        address to = makeAddr("to");
        vm.deal(address(bridge), amount);
        IAvailBridge.Message memory message = IAvailBridge.Message(
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
        IAvailBridge.MerkleProofInput memory input =
            IAvailBridge.MerkleProofInput(emptyArr, emptyArr, rangeHash, 0, bytes32(0), messageHash, messageHash, 0);

        uint256 balance = to.balance;
        bridge.receiveETH(message, input);
        assertEq(to.balance, balance + amount);
        assertTrue(bridge.isBridged(messageHash));
    }

    function testRevertInvalidAssetId_receiveERC20(bytes32 assetId) external {
        IAvailBridge.Message memory message =
            IAvailBridge.Message(0x02, bytes32(0), bytes32(0), 1, 2, abi.encode(assetId, 0), 0);
        IAvailBridge.MerkleProofInput memory input = IAvailBridge.MerkleProofInput(
            new bytes32[](0), new bytes32[](0), bytes32(0), 0, bytes32(0), bytes32(0), bytes32(0), 0
        );
        vm.expectRevert(IAvailBridge.InvalidAssetId.selector);
        bridge.receiveERC20(message, input);
        assertFalse(bridge.isBridged(keccak256(abi.encode(message))));
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
        IAvailBridge.Message memory message =
            IAvailBridge.Message(0x02, from, bytes32(bytes20(to)), 1, 2, abi.encode(assetId, amount), messageId);
        bytes32 messageHash = keccak256(abi.encode(message));
        bytes32 dataRoot = keccak256(abi.encode(bytes32(0), messageHash));

        vectorx.set(rangeHash, dataRoot);

        bytes32[] memory emptyArr;
        IAvailBridge.MerkleProofInput memory input =
            IAvailBridge.MerkleProofInput(emptyArr, emptyArr, rangeHash, 0, bytes32(0), messageHash, messageHash, 0);

        uint256 balance = token.balanceOf(to);
        bridge.receiveERC20(message, input);
        uint256 newBalance = token.balanceOf(to);
        assertEq(newBalance, balance + amount);
        assertTrue(bridge.isBridged(messageHash));
    }

    function testRevertInvalidDataLength_sendMessage(bytes32 to, bytes32[3200] calldata c_data, uint256 amount)
        external
    {
        bytes memory data = abi.encode(c_data);
        address from = makeAddr("from");
        vm.prank(from);
        vm.deal(from, amount);
        vm.expectRevert(IAvailBridge.InvalidDataLength.selector);
        bridge.sendMessage{value: amount}(to, data);
        assertEq(bridge.isSent(0), 0x0);
        assertEq(bridge.fees(), 0);
    }

    function testRevertFeeTooLow_sendMessage(bytes32 to, bytes calldata data, uint32 feePerByte, uint256 amount)
        external
    {
        vm.assume(feePerByte != 0 && data.length != 0 && data.length < 102_400);
        vm.prank(owner);
        bridge.updateFeePerByte(feePerByte);
        vm.assume(amount < bridge.getFee(data.length));
        address from = makeAddr("from");
        vm.prank(from);
        vm.deal(from, amount);
        vm.expectRevert(IAvailBridge.FeeTooLow.selector);
        bridge.sendMessage{value: amount}(to, data);
        assertEq(bridge.isSent(0), 0x0);
        assertEq(bridge.fees(), 0);
    }

    function test_sendMessage(bytes32 to, bytes calldata data, uint32 feePerByte, uint256 amount) external {
        vm.prank(owner);
        bridge.updateFeePerByte(feePerByte);
        vm.assume(data.length < 102_400 && amount >= bridge.getFee(data.length));
        address from = makeAddr("from");
        IAvailBridge.Message memory message = IAvailBridge.Message(0x01, bytes32(bytes20(from)), to, 2, 1, data, 0);
        vm.prank(from);
        vm.deal(from, amount);
        bridge.sendMessage{value: amount}(to, data);
        assertEq(bridge.isSent(0), keccak256(abi.encode(message)));
        assertEq(bridge.fees(), amount);
    }

    function testRevertWithdrawalFailed_withdrawFees(bytes32 to, bytes calldata data, uint32 feePerByte, uint256 amount)
        external
    {
        vm.prank(owner);
        bridge.updateFeePerByte(feePerByte);
        vm.assume(data.length < 102_400 && amount >= bridge.getFee(data.length));
        address from = makeAddr("from");
        IAvailBridge.Message memory message = IAvailBridge.Message(0x01, bytes32(bytes20(from)), to, 2, 1, data, 0);
        vm.prank(from);
        vm.deal(from, amount);
        bridge.sendMessage{value: amount}(to, data);
        assertEq(bridge.isSent(0), keccak256(abi.encode(message)));
        assertEq(bridge.fees(), amount);

        uint256 balance = bridge.feeRecipient().balance;
        vm.etch(bridge.feeRecipient(), revertCode);
        vm.expectRevert(IAvailBridge.WithdrawFailed.selector);
        bridge.withdrawFees();
        assertEq(bridge.feeRecipient().balance, balance);
        assertEq(bridge.fees(), amount);
    }

    function test_withdrawFees(bytes32 to, bytes calldata data, uint32 feePerByte, uint248 amount) external {
        vm.prank(owner);
        bridge.updateFeePerByte(feePerByte);
        vm.assume(data.length < 102_400 && amount >= bridge.getFee(data.length));
        address from = makeAddr("from");
        IAvailBridge.Message memory message = IAvailBridge.Message(0x01, bytes32(bytes20(from)), to, 2, 1, data, 0);
        vm.prank(from);
        vm.deal(from, amount);
        bridge.sendMessage{value: amount}(to, data);
        assertEq(bridge.isSent(0), keccak256(abi.encode(message)));
        assertEq(bridge.fees(), amount);

        uint256 balance = bridge.feeRecipient().balance;
        bridge.withdrawFees();
        assertEq(bridge.feeRecipient().balance, balance + amount);
        assertEq(bridge.fees(), 0);
    }

    function test_sendAVAIL(bytes32 to, uint256 amount) external {
        vm.assume(to != bytes32(0) && amount != 0);
        address from = makeAddr("from");
        vm.prank(address(bridge));
        avail.mint(from, amount);
        IAvailBridge.Message memory message =
            IAvailBridge.Message(0x02, bytes32(bytes20(from)), to, 2, 1, abi.encode(bytes32(0), amount), 0);
        vm.expectCall(address(avail), abi.encodeCall(avail.burn, (from, amount)));
        vm.prank(from);
        bridge.sendAVAIL(to, amount);
        assertEq(bridge.isSent(0), keccak256(abi.encode(message)));
        assertEq(avail.balanceOf(from), 0);
        assertEq(avail.totalSupply(), 0);
    }

    function test_sendETH(bytes32 to, uint256 amount) external {
        vm.assume(to != bytes32(0) && amount != 0);
        address from = makeAddr("from");
        vm.deal(from, amount);
        IAvailBridge.Message memory message = IAvailBridge.Message(
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
        assertEq(bridge.messageId(), 1);
    }

    function testRevertInvalidAssetId_sendERC20(bytes32 assetId, bytes32 dest, uint256 amount) external {
        vm.assume(dest != 0x0 && amount != 0);
        vm.expectRevert(IAvailBridge.InvalidAssetId.selector);
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
        IAvailBridge.Message memory message =
            IAvailBridge.Message(0x02, bytes32(bytes20(from)), to, 2, 1, abi.encode(assetId, amount), 0);
        vm.startPrank(from);
        token.approve(address(bridge), amount);
        vm.expectCall(address(token), abi.encodeCall(token.transferFrom, (from, address(bridge), amount)));
        bridge.sendERC20(assetId, to, amount);
        assertEq(bridge.isSent(0), keccak256(abi.encode(message)));
        assertEq(token.balanceOf(from), 0);
        assertEq(token.balanceOf(address(bridge)), amount);
    }

    function testRevertBlobRootEmpty_verifyBlobLeaf(IAvailBridge.MerkleProofInput memory input) external {
        input.blobRoot = 0x0;
        vm.expectRevert(IAvailBridge.BlobRootEmpty.selector);
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
        bytes32 dataRootCommitment = sha2merkle.getRoot(dataRoots);
        bytes32[] memory dataRootProof = sha2merkle.getProof(dataRoots, rand % dataRoots.length);
        vectorx.set(rangeHash, dataRootCommitment);
        for (uint256 i = 0; i < leaves.length;) {
            bytes32[] memory leafProof = getProof(leaves, i);
            IAvailBridge.MerkleProofInput memory input = IAvailBridge.MerkleProofInput(
                dataRootProof, leafProof, rangeHash, rand % dataRoots.length, blobRoot, bridgeRoot, preimages[i], i
            );
            assertTrue(bridge.verifyBlobLeaf(input));
            unchecked {
                ++i;
            }
        }
    }

    function testRevertBridgeRootEmpty_verifyBridgeLeaf(IAvailBridge.MerkleProofInput memory input) external {
        input.bridgeRoot = 0x0;
        vm.expectRevert(IAvailBridge.BridgeRootEmpty.selector);
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
        bytes32 dataRootCommitment = sha2merkle.getRoot(dataRoots);
        bytes32[] memory dataRootProof = sha2merkle.getProof(dataRoots, rand % dataRoots.length);
        vectorx.set(rangeHash, dataRootCommitment);
        for (uint256 i = 0; i < leaves.length;) {
            bytes32[] memory leafProof = getProof(leaves, i);
            IAvailBridge.MerkleProofInput memory input = IAvailBridge.MerkleProofInput(
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

contract Sha2Merkle is MurkyBase {
    function hashLeafPairs(bytes32 left, bytes32 right) public pure override returns (bytes32) {
        return sha256(abi.encode(left, right));
    }
}
