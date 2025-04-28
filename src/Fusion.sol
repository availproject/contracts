// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.29;

import {Initializable} from "lib/openzeppelin-contracts-upgradeable/contracts/proxy/utils/Initializable.sol";
import {PausableUpgradeable} from "lib/openzeppelin-contracts-upgradeable/contracts/utils/PausableUpgradeable.sol";
import {AccessControlDefaultAdminRulesUpgradeable} from
    "lib/openzeppelin-contracts-upgradeable/contracts/access/extensions/AccessControlDefaultAdminRulesUpgradeable.sol";
import {ReentrancyGuardTransientUpgradeable} from
    "lib/openzeppelin-contracts-upgradeable/contracts/utils/ReentrancyGuardTransientUpgradeable.sol";
import {SafeERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {MessageReceiver} from "./MessageReceiver.sol";
import {IAvailBridge} from "./interfaces/IAvailBridge.sol";
import {IAvail} from "./interfaces/IAvail.sol";
import {IFusion} from "./interfaces/IFusion.sol";

/**
 * @author  @QEDK (Avail)
 * @title   Fusion
 * @notice  A staking contract leveraging the Avail AMB to send to the Fusion pallet
 * @custom:security security@availproject.org
 */
contract Fusion is
    Initializable,
    PausableUpgradeable,
    AccessControlDefaultAdminRulesUpgradeable,
    ReentrancyGuardTransientUpgradeable,
    MessageReceiver,
    IFusion
{
    using SafeERC20 for IERC20;

    bytes32 private constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    uint256 private constant MAX_BUNDLE_SIZE = 50;
    IAvailBridge private immutable bridge;
    bytes32 private immutable fusion;

    /// @dev Pool ID -> pool data
    mapping(bytes32 => Pool) public pools;
    /// @dev Token address -> limit
    mapping(IERC20 => Asset) public assets;
    /// @dev Token address -> balance
    mapping(IERC20 => uint256) public balances;

    constructor(IAvailBridge newBridge, IAvail newAvail, bytes32 newFusion) {
        bridge = newBridge;
        fusion = newFusion;
        _disableInitializers();
    }

    function initialize(address governance, address pauser)
        external
        initializer
    {
        __MessageReceiver_init(address(newBridge));
        __AccessControlDefaultAdminRules_init(0, governance);
        _grantRole(PAUSER_ROLE, pauser);
    }

    /**
     * @notice  Updates pause status of the deposit contract
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

    /**
     * @notice  Function to update token address -> asset mapping
     * @dev     Only callable by governance
     * @param   tokens  Tokens to update
     * @param   newAssets  New asset data
     */
    function updateAssets(IERC20[] calldata tokens, Asset[] calldata newAssets) external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 length = newAssets.length;
        if (length != tokens.length) {
            revert ArrayLengthMismatch();
        }
        for (uint256 i = 0; i < length;) {
            assets[tokens[i]] = newAssets[i];
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice  Function to send Fusion messages via the bridge to the Fusion pallet
     * @dev     We use nonReentrant here because we break the CEI pattern
     * @param   messages  Fusion messages to be sent as a bundle
     */
    // slither-disable-next-line cyclomatic-complexity function has a complexity of 12, just over the limit of 11
    function execute(FusionMessage[] calldata messages) external payable whenNotPaused nonReentrant {
        uint256 length = messages.length;
        require(length > 0 && length <= MAX_BUNDLE_SIZE, "Invalid bundle size");

        emit Executed(msg.sender, length);

        for (uint256 i = 0; i < length;) {
            FusionMessage memory message = messages[i];
            if (message.messageType < FusionMessageType.Withdraw) {
                // Enum idx 0-3
                if (message.messageType == FusionMessageType.Deposit) {
                    // Idx = 0
                    _deposit(message);
                } else if (message.messageType == FusionMessageType.Stake) {
                    // Idx = 1
                    _stake(message);
                } else if (message.messageType == FusionMessageType.Unbond) {
                    // Idx = 2
                    _unbond(message);
                } else {
                    // Idx = 3
                    _pull(message);
                }
            } else if (message.messageType < FusionMessageType.Boost) {
                // Enum idx 4-6
                if (message.messageType == FusionMessageType.Withdraw) {
                    // Idx = 4
                    _withdraw(message);
                } else if (message.messageType == FusionMessageType.Claim) {
                    // Idx = 5
                    _claim(message);
                } else {
                    // Idx = 6
                    _extract(message);
                }
            } else if (message.messageType < FusionMessageType.Unstake) {
                // Enum idx 7-9
                if (message.messageType == FusionMessageType.Boost) {
                    // Idx = 7
                    _boost(message);
                } else if (message.messageType == FusionMessageType.SetCompounding) {
                    // Idx = 8
                    _setCompounding(message);
                } else {
                    // Idx = 9
                    _setController(message);
                }
            } else {
                // Idx >= 10
                revert InvalidMessage();
            }
            unchecked {
                ++i;
            }
        }

        bridge.sendMessage{value: msg.value}(
            fusion, abi.encode(FusionMessageBundle({account: msg.sender, messages: messages}))
        );
    }

    function _deposit(FusionMessage memory message) private {
        FusionDeposit memory depositMessage = abi.decode(message.data, (FusionDeposit));
        Asset memory asset = assets[depositMessage.token];
        uint256 balance = balances[depositMessage.token];
        uint256 newBalance = balance + depositMessage.amount;
        if (newBalance > asset.limit) {
            revert ExceedsGlobalLimit();
        }
        if (!asset.depositsEnabled) {
            revert DepositsDisabled();
        }
        if (depositMessage.amount < asset.minDepositAmount) {
            revert InvalidAmount();
        }
        balances[depositMessage.token] = newBalance;

        emit Deposited(depositMessage.token, msg.sender, depositMessage.amount);

        depositMessage.token.safeTransferFrom(msg.sender, address(this), depositMessage.amount);
    }

    function _stake(FusionMessage memory message) private {
        FusionStake memory stakeMessage = abi.decode(message.data, (FusionStake));
        Pool memory pool = pools[stakeMessage.poolId];
        if (address(pool.token) == address(0)) {
            revert InvalidPoolId();
        }
        if (!pool.stakingEnabled) {
            revert StakingDisabled();
        }
        if (stakeMessage.amount < pool.minStakingAmount) {
            revert InvalidAmount();
        }

        emit StakeIntention(stakeMessage.poolId, msg.sender, stakeMessage.amount);
    }

    function _unbond(FusionMessage memory message) private {
        FusionUnbond memory unbondMessage = abi.decode(message.data, (FusionUnbond));
        Pool memory pool = pools[unbondMessage.poolId];
        if (address(pool.token) == address(0)) {
            revert InvalidPoolId();
        }
        if (!pool.unbondingEnabled) {
            revert UnbondingDisabled();
        }
        if (unbondMessage.amount < pool.minUnbondingAmount) {
            revert InvalidAmount();
        }

        emit UnbondIntention(unbondMessage.poolId, msg.sender, unbondMessage.amount);
    }

    function _pull(FusionMessage memory message) private {
        FusionPull memory pullMessage = abi.decode(message.data, (FusionPull));
        Pool memory pool = pools[pullMessage.poolId];
        if (address(pool.token) == address(0)) {
            revert InvalidPoolId();
        }
        if (pullMessage.amount < pool.minPullAmount) {
            revert InvalidAmount();
        }

        emit PullIntention(pullMessage.poolId, msg.sender, pullMessage.amount);
    }

    function _withdraw(FusionMessage memory message) private {
        FusionWithdraw memory withdrawMessage = abi.decode(message.data, (FusionWithdraw));
        Asset memory asset = assets[withdrawMessage.token];
        if (!asset.withdrawalsEnabled) {
            revert WithdrawalsDisabled();
        }
        if (withdrawMessage.amount < asset.minWithdrawalAmount) {
            revert InvalidAmount();
        }

        emit WithdrawIntention(withdrawMessage.token, msg.sender, withdrawMessage.amount);
    }

    function _extract(FusionMessage memory message) private {
        FusionExtract memory extractMessage = abi.decode(message.data, (FusionExtract));
        Pool memory pool = pools[extractMessage.poolId];
        if (address(pool.token) == address(0)) {
            revert InvalidPoolId();
        }
        if (extractMessage.amount < pool.minExtractionAmount) {
            revert InvalidAmount();
        }

        emit ExtractIntention(extractMessage.poolId, msg.sender, extractMessage.amount);
    }

    function _claim(FusionMessage memory message) private {
        FusionClaim memory claimMessage = abi.decode(message.data, (FusionClaim));
        Pool memory pool = pools[claimMessage.poolId];
        if (address(pool.token) == address(0)) {
            revert InvalidPoolId();
        }

        emit ClaimIntention(claimMessage.poolId, msg.sender);
    }

    function _boost(FusionMessage memory message) private {
        FusionBoost memory boostMessage = abi.decode(message.data, (FusionBoost));
        Pool memory pool = pools[boostMessage.poolId];
        if (address(pool.token) == address(0)) {
            revert InvalidPoolId();
        }
        if (boostMessage.amount == 0) {
            revert InvalidAmount();
        }

        emit BoostIntention(boostMessage.poolId, msg.sender, boostMessage.amount);
    }

    function _setCompounding(FusionMessage memory message) private {
        FusionSetCompounding memory setCompoundingMessage = abi.decode(message.data, (FusionSetCompounding));
        Pool memory pool = pools[setCompoundingMessage.poolId];
        if (address(pool.token) == address(0)) {
            revert InvalidPoolId();
        }

        emit SetCompoundingIntention(setCompoundingMessage.poolId, msg.sender, setCompoundingMessage.toCompound);
    }

    function _setController(FusionMessage memory message) private {
        FusionSetController memory setControllerMessage = abi.decode(message.data, (FusionSetController));
        if (setControllerMessage.controller == bytes32(0)) {
            revert InvalidController();
        }

        emit SetControllerIntention(msg.sender, setControllerMessage.controller);
    }

    function _onAvailMessage(bytes32 from, bytes calldata data) internal override whenNotPaused nonReentrant {
        if (from != fusion) {
            revert OnlyFusionPallet();
        }
        FusionMessageBundle memory bundle = abi.decode(data, (FusionMessageBundle));
        if (bundle.messages.length != 1) {
            revert InvalidBundleSize();
        }
        FusionMessage memory message = bundle.messages[0];
        if (message.messageType != FusionMessageType.Unstake) {
            revert InvalidMessage();
        }
        FusionUnstake memory unstakeMessage = abi.decode(message.data, (FusionUnstake));
        Asset memory asset = assets[unstakeMessage.token];
        if (!asset.withdrawalsEnabled) {
            revert WithdrawalsDisabled();
        }
        balances[unstakeMessage.token] -= unstakeMessage.amount;

        emit Withdrawn(unstakeMessage.token, bundle.account, unstakeMessage.amount);

        unstakeMessage.token.safeTransfer(bundle.account, unstakeMessage.amount);
    }
}
