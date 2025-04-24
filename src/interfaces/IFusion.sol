// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

interface IFusion {
    error ArrayLengthMismatch();
    error DepositsDisabled();
    error ExceedsGlobalLimit();
    error WithdrawalsDisabled();
    error InvalidAmount();
    error InvalidAsset();
    error InvalidBundleSize();
    error InvalidController();
    error InvalidMessage();
    error InvalidPoolId();
    error OnlyFusionPallet();
    error StakingDisabled();
    error UnbondingDisabled();

    /// @dev All events except asset withdrawals and deposits are intentions because the corresponding action is
    /// fully asynchronous and may fail
    event Executed(address indexed account, uint256 bundleSize);
    event Deposited(IERC20 indexed token, address indexed account, uint256 amount);
    event StakeIntention(bytes32 indexed poolId, address indexed account, uint256 amount);
    event UnbondIntention(bytes32 indexed poolId, address indexed account, uint256 amount);
    event PullIntention(bytes32 indexed poolId, address indexed account, uint256 amount);
    event WithdrawIntention(IERC20 indexed token, address indexed account, uint256 amount);
    event ClaimIntention(bytes32 indexed poolId, address indexed account);
    event ExtractIntention(bytes32 indexed poolId, address indexed account, uint256 amount);
    event BoostIntention(bytes32 indexed poolId, address indexed account, uint256 amount);
    event SetCompoundingIntention(bytes32 indexed poolId, address indexed account, bool toCompound);
    event SetControllerIntention(address indexed account, bytes32 controller);
    event Withdrawn(IERC20 indexed token, address indexed account, uint256 amount);

    /// @dev Enum is ordered based on most likeliest to least likeliest actions
    enum FusionMessageType {
        /// @dev Deposit assets from Ethereum to Avail
        Deposit,
        /// @dev Stake assets on Avail
        Stake,
        /// @dev Unbond assets on Avail
        Unbond,
        /// @dev Pull assets from the pool to Fusion balance
        Pull,
        /// @dev Withdraw assets from Avail to Ethereum
        Withdraw,
        /// @dev Claim rewards on Avail and send it to the controller
        Claim,
        /// @dev Withdraw assets on Avail and send it to the controller
        Extract,
        /// @dev Sets a boost allocation for the pool
        Boost,
        /// @dev Sets the compounding status for the pool
        SetCompounding,
        /// @dev Sets the controller for the pool
        SetController,
        /// @dev Claims withdrawn assets assets from Avail to Ethereum (not externally callable)
        Unstake
    }

    struct Pool {
        /// @dev The address deposited into the pool
        IERC20 token;
        /// @dev Minimum amount for each staking action
        uint256 minStakingAmount;
        /// @dev Minimum amount for each unbonding action
        uint256 minUnbondingAmount;
        /// @dev Minimum amount for each pull action
        uint256 minPullAmount;
        /// @dev Minimum amount for each extraction action
        uint256 minExtractionAmount;
        /// @dev If the pool stakings are enabled
        bool stakingEnabled;
        /// @dev If the pool unbondings are enabled
        bool unbondingEnabled;
    }

    struct Asset {
        /// @dev The global limit of the asset
        uint256 limit;
        /// @dev Minimum amount for each deposit action
        uint256 minDepositAmount;
        /// @dev Minimum amount for each withdrawal action
        uint256 minWithdrawalAmount;
        /// @dev If the asset deposits are enabled
        bool depositsEnabled;
        /// @dev If the asset withdrawals are enabled
        bool withdrawalsEnabled;
    }
    /// @dev The Fusion message bundle is sent to the Fusion pallet

    struct FusionMessageBundle {
        /// @dev The account on Ethereum that is sending the bundle
        address account;
        /// @dev The payload is encoded as an array of wrapped messages
        FusionMessage[] messages;
    }
    /// @dev A message that is sent to the Fusion pallet

    struct FusionMessage {
        /// @dev The message type
        FusionMessageType messageType;
        /// @dev The payload
        bytes data;
    }
    /// @dev Initiates a deposit to Avail as Fusion balance

    struct FusionDeposit {
        /// @dev The token being deposited
        IERC20 token;
        /// @dev The amount to deposit (in wei)
        uint256 amount;
    }

    /// @dev Initiates a stake from Fusion balance
    struct FusionStake {
        /// @dev The pool ID
        bytes32 poolId;
        /// @dev The amount to stake (in wei)
        uint256 amount;
    }

    /// @dev Initiates an unbonding from the pool
    struct FusionUnbond {
        /// @dev The pool ID
        bytes32 poolId;
        /// @dev The amount to start unbonding (in wei)
        uint256 amount;
    }

    /// @dev Initiates a pull from the pool, this action converts unbonded balance into Fusion balance
    struct FusionPull {
        /// @dev The pool ID
        bytes32 poolId;
        /// @dev The amount to pull (in wei)
        uint256 amount;
    }

    /// @dev Initiates a withdrawal from the Fusion balance to Ethereum
    struct FusionWithdraw {
        /// @dev Token address
        IERC20 token;
        /// @dev The amount to withdraw (in wei)
        uint256 amount;
    }

    /// @dev Initiates a withdrawal from the pool to the controller, this action converts unbonded balance into
    /// Fusion balance for the controller
    struct FusionExtract {
        /// @dev The pool ID
        bytes32 poolId;
        /// @dev The amount to extract (in wei)
        uint256 amount;
    }

    /// @dev Initiates a claim from the pool rewards, this action takes rewards and stores them in the Fusion balance
    struct FusionClaim {
        /// @dev The pool ID
        bytes32 poolId;
    }
    /// @dev Sets a boost allocation for the pool

    struct FusionBoost {
        /// @dev The pool ID
        bytes32 poolId;
        /// @dev The amount to boost the pool (in wei)
        uint256 amount;
    }

    /// @dev Sets the compounding status for the pool for an account
    struct FusionSetCompounding {
        /// @dev The pool ID
        bytes32 poolId;
        /// @dev Whether to set compounding on or off for the pool positions
        bool toCompound;
    }

    /// @dev Sets the controller for an account, this action allows the specified controller to manage the position
    struct FusionSetController {
        /// @dev A controller on Avail who can manage the position
        bytes32 controller;
    }

    /// @dev Returns an amount of deposited funds to the user, not callable by the user
    struct FusionUnstake {
        /// @dev The token address
        IERC20 token;
        /// @dev The amount to remove from the pool (in wei)
        uint256 amount;
    }
}
