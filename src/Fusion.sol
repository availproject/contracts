// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.29;

import {PausableUpgradeable} from "lib/openzeppelin-contracts-upgradeable/contracts/utils/PausableUpgradeable.sol";
import {AccessControlDefaultAdminRulesUpgradeable} from
    "lib/openzeppelin-contracts-upgradeable/contracts/access/extensions/AccessControlDefaultAdminRulesUpgradeable.sol";
import {MulticallUpgradeable} from "lib/openzeppelin-contracts-upgradeable/contracts/utils/MulticallUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from
    "lib/openzeppelin-contracts-upgradeable/contracts/utils/ReentrancyGuardUpgradeable.sol";
import {SafeERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {MessageReceiver} from "./MessageReceiver.sol";
import {IAvailBridge} from "./interfaces/IAvailBridge.sol";
import {IFusion} from "./interfaces/IFusion.sol";

contract Fusion is
    PausableUpgradeable,
    AccessControlDefaultAdminRulesUpgradeable,
    MulticallUpgradeable,
    ReentrancyGuardUpgradeable,
    MessageReceiver,
    IFusion
{
    using SafeERC20 for IERC20;

    bytes32 private constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    IAvailBridge public bridge;
    /// @dev Pot address of pallet used to receive and send assets
    bytes32 public fusion;

    /// @dev Pool ID -> pool data
    mapping(bytes32 => Pool) public pools;
    /// @dev Token address -> limit 
    mapping(IERC20 => Asset) public assets;
    /// @dev Token address -> balance
    mapping(IERC20 => uint256) public balances;

    constructor() {
        _disableInitializers();
    }

    function initialize(IAvailBridge newBridge, bytes32 newFusion, address governance, address pauser)
        external
        initializer
    {
        bridge = newBridge;
        fusion = newFusion;
        __MessageReceiver_init(address(newBridge));
        __AccessControlDefaultAdminRules_init(0, governance);
        _grantRole(PAUSER_ROLE, pauser);
        __Pausable_init();
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
     * @notice  Function to update the fusion pot address
     * @dev     Only callable by governance
     * @param   newFusion  New fusion pot address
     */
    function updateFusion(bytes32 newFusion) external onlyRole(DEFAULT_ADMIN_ROLE) {
        fusion = newFusion;
    }

    /**
     * @notice  Function to update the bridge contract address
     * @dev     Only callable by governance
     * @param   newBridge  New bridge contract address
     */
    function updateBridge(IAvailBridge newBridge) external onlyRole(DEFAULT_ADMIN_ROLE) {
        bridge = newBridge;
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
    function execute(FusionMessage[] calldata messages) external payable whenNotPaused nonReentrant {
        uint256 length = messages.length;
        for (uint256 i = 0; i < length;) {
            FusionMessage memory message = messages[i];
            if (message.messageType == FusionMessageType.Deposit) {
                _deposit(message);
            } else if (message.messageType == FusionMessageType.Stake) {
                _stake(message);
            } else if (message.messageType == FusionMessageType.Unbond) {
                _unbond(message);
            } else if (message.messageType == FusionMessageType.Pull) {
                _pull(message);
            } else if (message.messageType == FusionMessageType.Withdraw) {
                _withdraw(message);
            } else if (message.messageType == FusionMessageType.Extract) {
                _extract(message);
            } else if (message.messageType == FusionMessageType.Claim) {
                _claim(message);
            } else if (message.messageType == FusionMessageType.Boost) {
                _boost(message);
            } else if (message.messageType == FusionMessageType.SetCompounding) {
                _setCompounding(message);
            } else if (message.messageType == FusionMessageType.SetController) {
                _setController(message);
            } else {
                assert(false); // unreachable
            }
            unchecked {
                ++i;
            }
        }
        bridge.sendMessage{value: msg.value}(fusion, abi.encode(FusionMessageBundle({account: msg.sender, messages: messages})));
    }

    function _deposit(
        FusionMessage memory message
    ) private {
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
        depositMessage.token.safeTransferFrom(msg.sender, address(this), depositMessage.amount);
    }

    function _stake(
        FusionMessage memory message
    ) private {
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
    }

    function _unbond(
        FusionMessage memory message
    ) private view {
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
    }

    function _pull(
        FusionMessage memory message
    ) private view {
        FusionPull memory pullMessage = abi.decode(message.data, (FusionPull));
        Pool memory pool = pools[pullMessage.poolId];
        if (address(pool.token) == address(0)) {
            revert InvalidPoolId();
        }
        if (pullMessage.amount < pool.minPullAmount) {
            revert InvalidAmount();
        }
    }

    function _withdraw(
        FusionMessage memory message
    ) private view {
        FusionWithdraw memory withdrawMessage = abi.decode(message.data, (FusionWithdraw));
        Asset memory asset = assets[withdrawMessage.token];
        if (!asset.withdrawalsEnabled) {
            revert WithdrawalsDisabled();
        }
        if (withdrawMessage.amount < asset.minWithdrawalAmount) {
            revert InvalidAmount();
        }
    }

    function _extract(
        FusionMessage memory message
    ) private view {
        FusionExtract memory extractMessage = abi.decode(message.data, (FusionExtract));
        Pool memory pool = pools[extractMessage.poolId];
        if (address(pool.token) == address(0)) {
            revert InvalidPoolId();
        }
        if (extractMessage.amount < pool.minExtractionAmount) {
            revert InvalidAmount();
        }
    }

    function _claim(
        FusionMessage memory message
    ) private view {
        FusionClaim memory claimMessage = abi.decode(message.data, (FusionClaim));
        Pool memory pool = pools[claimMessage.poolId];
        if (address(pool.token) == address(0)) {
            revert InvalidPoolId();
        }
        if (!pool.withdrawalsEnabled) {
            revert WithdrawalsDisabled();
        }
        if (claimMessage.amount < pool.minWithdrawal) {
            revert InvalidAmount();
        }
    }

    function _boost(
        FusionMessage memory message
    ) private view {
        FusionBoost memory boostMessage = abi.decode(message.data, (FusionBoost));
        Pool memory pool = pools[boostMessage.poolId];
        if (address(pool.token) == address(0)) {
            revert InvalidPoolId();
        }
        if (boostMessage.amount == 0) {
            revert InvalidAmount();
        }
    }

    function _setCompounding(
        FusionMessage memory message
    ) private view {
        FusionSetCompounding memory setCompoundingMessage = abi.decode(message.data, (FusionSetCompounding));
        Pool memory pool = pools[setCompoundingMessage.poolId];
        if (address(pool.token) == address(0)) {
            revert InvalidPoolId();
        }
    }

    function _setController(
        FusionMessage memory message
    ) private pure {
        FusionSetController memory setControllerMessage = abi.decode(message.data, (FusionSetController));
        if (setControllerMessage.controller == bytes32(0)) {
            revert InvalidController();
        }
    }

    function _onAvailMessage(bytes32 from, bytes calldata data) internal override whenNotPaused {
        if (from != fusion) {
            revert OnlyFusionPallet();
        }
        FusionMessageBundle memory bundle = abi.decode(data, (FusionMessageBundle));
        FusionMessage memory message = bundle.messages[0];
        if (
            message.messageType != FusionMessageType.Unstake
        ) {
            revert InvalidMessage();
        }
        FusionUnstake memory unstakeMessage = abi.decode(message.data, (FusionUnstake));
        Pool memory pool = pools[unstakeMessage.poolId];
        if (address(pool.token) == address(0)) {
            revert InvalidPoolId();
        }
        balances[address(pool.token)] -= unstakeMessage.amount;
        pool.token.safeTransfer(bundle.account, unstakeMessage.amount);

        emit Unstaked(unstakeMessage.poolId, bundle.account, unstakeMessage.amount);
    }
}
