// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {PausableUpgradeable} from "lib/openzeppelin-contracts-upgradeable/contracts/utils/PausableUpgradeable.sol";
import {AccessControlDefaultAdminRulesUpgradeable} from
    "lib/openzeppelin-contracts-upgradeable/contracts/access/extensions/AccessControlDefaultAdminRulesUpgradeable.sol";
import {MulticallUpgradeable} from "lib/openzeppelin-contracts-upgradeable/contracts/utils/MulticallUpgradeable.sol";
import {SafeERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {MessageReceiver} from "./MessageReceiver.sol";
import {IAvailBridge} from "./interfaces/IAvailBridge.sol";
import {IFusion} from "./interfaces/IFusion.sol";

contract Fusion is PausableUpgradeable, AccessControlDefaultAdminRulesUpgradeable, MulticallUpgradeable, MessageReceiver, IFusion {
    using SafeERC20 for IERC20;

    bytes32 private constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    IAvailBridge public bridge;
    /// @dev Pot address of pallet used to receive and send assets
    bytes32 public fusion;

    /// @dev Pool ID -> pool data
    mapping (bytes32 => Pool) public pools;
    /// @dev Pool ID -> user address -> amount staked
    mapping (bytes32 => mapping (address => uint256)) public stakes;

    function initialize(IAvailBridge newBridge, bytes32 newFusion, address governance, address pauser) external initializer {
        bridge = newBridge;
        fusion = newFusion;
        __MessageReceiver_init(address(newBridge));
        __AccessControlDefaultAdminRules_init(0, governance);
        _grantRole(PAUSER_ROLE, pauser);
        __Pausable_init();
    }

    /**
     * @notice  Function to update pool ID -> asset mapping
     * @dev     Only callable by governance
     * @param   ids  Assets to update
     * @param   newPools  New pool data
     */
    function updatePools(bytes32[] calldata ids, Pool[] calldata newPools) external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 length = newPools.length;
        if (length != ids.length) {
            revert ArrayLengthMismatch();
        }
        for (uint256 i = 0; i < length;) {
            pools[ids[i]] = newPools[i];
            unchecked {
                ++i;
            }
        }
    }

    function stake(bytes32 poolId, uint256 amount, bytes32 controller, bool toCompound) external payable whenNotPaused {
        if (controller == bytes32(0)) {
            revert InvalidController();
        }
        Pool memory pool = pools[poolId];
        if (address(pool.token) == address(0)) {
            revert InvalidPoolId();
        }
        if (!pool.depositsEnabled) {
            revert DepositsDisabled();
        }
        if (amount < pool.minDeposit) {
            revert InvalidAmount();
        }
        uint256 messageSize = 1;
        FusionStake memory stakeMessage = FusionStake({
            poolId: poolId,
            amount: amount
        });
        FusionSetCompounding memory compoundMessage = FusionSetCompounding({
            poolId: poolId,
            toCompound: toCompound
        });
        if (controller != bytes32(0)) {
            messageSize += 1;
        }
        FusionMessageTypes[] memory messageTypes = new FusionMessageTypes[](messageSize);
        bytes[] memory data = new bytes[](messageSize);
        messageTypes[0] = FusionMessageTypes.Stake;
        data[0] = abi.encode(stakeMessage);
        messageTypes[1] = FusionMessageTypes.SetCompounding;
        data[1] = abi.encode(compoundMessage);
        if (controller != bytes32(0)) {
            messageTypes[2] = FusionMessageTypes.SetController;
            data[2] = abi.encode(controller);
        }
        pool.token.safeTransferFrom(msg.sender, address(this), amount);
        stakes[poolId][msg.sender] += amount;
        bridge.sendMessage{value: msg.value}(fusion, abi.encode(FusionMessage({
            account: msg.sender,
            messageType: messageTypes,
            data: data
        })));

        emit Staked(poolId, msg.sender, amount);
    }

    function unbond(bytes32 poolId, uint256 amount) external payable whenNotPaused {
        Pool memory pool = pools[poolId];
        if (address(pool.token) == address(0)) {
            revert InvalidPoolId();
        }
        if (!pool.withdrawalsEnabled) {
            revert WithdrawalsDisabled();
        }
        if (amount < pool.minWithdrawal) {
            revert InvalidAmount();
        }
        FusionUnbond memory unbondMessage = FusionUnbond({
            poolId: poolId,
            amount: amount
        });
        FusionMessageTypes[] memory messageTypes = new FusionMessageTypes[](1);
        bytes[] memory data = new bytes[](1);
        messageTypes[0] = FusionMessageTypes.Unbond;
        data[0] = abi.encode(unbondMessage);
        bridge.sendMessage{value: msg.value}(fusion, abi.encode(FusionMessage({
            account: msg.sender,
            messageType: messageTypes,
            data: data
        })));

        emit Unbonded(poolId, msg.sender, amount);
    }

    function withdraw(bytes32 poolId, uint256 amount) external payable whenNotPaused {
        Pool memory pool = pools[poolId];
        if (address(pool.token) == address(0)) {
            revert InvalidPoolId();
        }
        if (!pool.withdrawalsEnabled) {
            revert WithdrawalsDisabled();
        }
        if (amount < pool.minWithdrawal) {
            revert InvalidAmount();
        }
        FusionWithdraw memory withdrawMessage = FusionWithdraw({
            poolId: poolId,
            amount: amount
        });
        FusionMessageTypes[] memory messageTypes = new FusionMessageTypes[](1);
        bytes[] memory data = new bytes[](1);
        messageTypes[0] = FusionMessageTypes.Withdraw;
        data[0] = abi.encode(withdrawMessage);
        bridge.sendMessage(fusion, abi.encode(FusionMessage({
            account: msg.sender,
            messageType: messageTypes,
            data: data
        })));

        emit Withdrawn(poolId, msg.sender, amount);
    }

    function claim(bytes32 poolId, uint256 amount) external payable whenNotPaused {
        Pool memory pool = pools[poolId];
        if (address(pool.token) == address(0)) {
            revert InvalidPoolId();
        }
        FusionClaim memory claimMessage = FusionClaim({
            poolId: poolId,
            amount: amount
        });
        FusionMessageTypes[] memory messageTypes = new FusionMessageTypes[](1);
        bytes[] memory data = new bytes[](1);
        messageTypes[0] = FusionMessageTypes.Claim;
        data[0] = abi.encode(claimMessage);
        bridge.sendMessage{value: msg.value}(fusion, abi.encode(FusionMessage({
            account: msg.sender,
            messageType: messageTypes,
            data: data
        })));

        emit Claimed(poolId, msg.sender, amount);
    }

    function setCompounding(bytes32 poolId, bool toCompound) external payable whenNotPaused {
        Pool memory pool = pools[poolId];
        if (address(pool.token) == address(0)) {
            revert InvalidPoolId();
        }
        FusionSetCompounding memory compoundMessage = FusionSetCompounding({
            poolId: poolId,
            toCompound: toCompound
        });
        FusionMessageTypes[] memory messageTypes = new FusionMessageTypes[](1);
        bytes[] memory data = new bytes[](1);
        messageTypes[0] = FusionMessageTypes.SetCompounding;
        data[0] = abi.encode(compoundMessage);
        bridge.sendMessage{value: msg.value}(fusion, abi.encode(FusionMessage({
            account: msg.sender,
            messageType: messageTypes,
            data: data
        })));

        emit CompoundingSet(poolId, msg.sender, toCompound);
    }

    function setController(bytes32 poolId, bytes32 controller) external payable whenNotPaused {
        if (controller == bytes32(0)) {
            revert InvalidController();
        }
        Pool memory pool = pools[poolId];
        if (address(pool.token) == address(0)) {
            revert InvalidPoolId();
        }
        FusionSetController memory controllerMessage = FusionSetController({
            controller: controller
        });
        FusionMessageTypes[] memory messageTypes = new FusionMessageTypes[](1);
        bytes[] memory data = new bytes[](1);
        messageTypes[0] = FusionMessageTypes.SetController;
        data[0] = abi.encode(controllerMessage);
        bridge.sendMessage{value: msg.value}(fusion, abi.encode(FusionMessage({
            account: msg.sender,
            messageType: messageTypes,
            data: data
        })));

        emit ControllerSet(poolId, msg.sender, controller);
    }

    function _onAvailMessage(bytes32 from, bytes calldata data) internal override whenNotPaused {
        if (from != fusion) {
            revert OnlyFusionPallet();
        }
        FusionMessage memory message = abi.decode(data, (FusionMessage));
        if (message.messageType.length != 1 || message.messageType.length != message.data.length || message.messageType[0] != FusionMessageTypes.Unstake) {
            revert InvalidMessage();
        }
        FusionUnstake memory unstakeMessage = abi.decode(message.data[0], (FusionUnstake));
        Pool memory pool = pools[unstakeMessage.poolId];
        if (address(pool.token) == address(0)) {
            revert InvalidPoolId();
        }
        uint256 amount = stakes[unstakeMessage.poolId][message.account];
        if (amount < unstakeMessage.amount) {
            revert InvalidAmount();
        }
        stakes[unstakeMessage.poolId][message.account] -= unstakeMessage.amount;
        pool.token.safeTransfer(message.account, unstakeMessage.amount);

        emit Unstaked(unstakeMessage.poolId, message.account, unstakeMessage.amount);
    }
}
