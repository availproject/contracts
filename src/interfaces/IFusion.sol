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
    error InvalidController();
    error InvalidMessage();
    error InvalidPoolId();
    error OnlyFusionPallet();
    error StakingDisabled();
    error UnbondingDisabled();

    event Staked(bytes32 indexed poolId, address indexed account, uint256 amount);
    event Unstaked(bytes32 indexed poolId, address indexed account, uint256 amount);
    event Unbonded(bytes32 indexed poolId, address indexed account, uint256 amount);
    event Withdrawn(bytes32 indexed poolId, address indexed account, uint256 amount);
    event Claimed(bytes32 indexed poolId, address indexed account, uint256 amount);
    event CompoundingSet(bytes32 indexed poolId, address indexed account, bool toCompound);
    event ControllerSet(bytes32 indexed poolId, address indexed account, bytes32 controller);

    enum FusionMessageType {
        /// @dev Deposit assets from Ethereum to Avail
        Deposit,
        /// @dev Stake assets on Avail
        Stake,
        /// @dev Unbond assets on Avail
        Unbond,
        /// @dev Withdraw assets from Avail to Ethereum
        Withdraw,
        /// @dev Withdraw assets on Avail and send it to the controller
        Extract,
        /// @dev Claim rewards on Avail and send it to the controller
        Claim,
        /// @dev Sets a boost allocation for the pool
        Boost,
        /// @dev Sets the compounding status for the pool
        SetCompounding,
        /// @dev Sets the controller for the pool
        SetController,
        /// @dev Unstake assets from Avail to Ethereum (not externally callable)
        Unstake
    }

    struct Pool {
        /// @dev The address deposited into the pool
        IERC20 token;
        /// @dev Minimum amount for each staking action
        uint256 minStakingAmount;
        /// @dev Minimum amount for each unbonding action
        uint256 minUnbondingAmount;
        /// @dev If the pool stakings are enabled
        bool stakingEnabled;
        /// @dev If the pool unbondings are enabled
        bool unbondingEnabled;
    }

    struct Asset {
        /// @dev The limit of the asset
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

    struct FusionMessageBundle {
        /// @dev The account on Ethereum that is sending the bundle
        address account;
        /// @dev The payload is encoded as an array of wrapped messages
        FusionMessage[] messages;
    }

    struct FusionMessage {
        /// @dev The message type
        FusionMessageType messageType;
        /// @dev The payload
        bytes data;
    }

    struct FusionDeposit {
        /// @dev The token being deposited
        IERC20 token;
        /// @dev The amount to deposit (in wei)
        uint256 amount;
    }

    /// @dev Initiates a deposit to Avail and stake into the pool
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

    /// @dev Initiates a withdrawal from the Fusion balance to Ethereum
    struct FusionWithdraw {
        /// @dev Token address
        IERC20 token;
        /// @dev The amount to withdraw (in wei)
        uint256 amount;
    }

    /// @dev Initiates a withdrawal from the pool to the controller
    struct FusionExtract {
        /// @dev The pool ID
        bytes32 poolId;
        /// @dev The amount to extract (in wei)
        uint256 amount;
    }

    /// @dev Initiates a claim from the pool rewards
    struct FusionClaim {
        /// @dev The pool ID
        bytes32 poolId;
        /// @dev The amount to claim from rewards (in wei)
        uint256 amount;
    }

    /// @dev Returns an amount of locked stake to the user
    struct FusionUnstake {
        /// @dev The pool ID
        bytes32 poolId;
        /// @dev The amount to remove from the pool (in wei)
        uint256 amount;
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

    /// @dev Sets the controller for an account
    struct FusionSetController {
        /// @dev A controller on Avail who can manage the position
        bytes32 controller;
    }
}
