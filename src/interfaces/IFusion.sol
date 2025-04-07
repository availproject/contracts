// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

interface IFusion {
    error ArrayLengthMismatch();
    error DepositsDisabled();
    error WithdrawalsDisabled();
    error InvalidAmount();
    error InvalidController();
    error InvalidMessage();
    error InvalidPoolId();
    error OnlyFusionPallet();

    event Staked(bytes32 indexed poolId, address indexed account, uint256 amount);
    event Unstaked(bytes32 indexed poolId, address indexed account, uint256 amount);
    event Unbonded(bytes32 indexed poolId, address indexed account, uint256 amount);
    event Withdrawn(bytes32 indexed poolId, address indexed account, uint256 amount);
    event Claimed(bytes32 indexed poolId, address indexed account, uint256 amount);
    event CompoundingSet(bytes32 indexed poolId, address indexed account, bool toCompound);
    event ControllerSet(bytes32 indexed poolId, address indexed account, bytes32 controller);

    enum FusionMessageTypes {
        Stake,
        Unbond,
        Withdraw,
        Claim,
        Unstake,
        SetCompounding,
        SetController
    }

    struct Pool {
        /// @dev The address deposited into the pool
        IERC20 token;
        /// @dev The total amount that can be staked in the pool
        uint256 limit;
        /// @dev Minimum amount for each deposit
        uint256 minDeposit;
        /// @dev Minimum amount for each withdrawal
        uint256 minWithdrawal;
        /// @dev If the pool deposits are enabled
        bool depositsEnabled;
        /// @dev If the pool withdrawals are enabled
        bool withdrawalsEnabled;
    }

    struct FusionMessage {
        /// @dev The account on Ethereum that owns the position
        address account;
        /// @dev The message type byte
        FusionMessageTypes[] messageType;
        /// @dev Array of payloads
        bytes[] data;
    }

    /// @dev Initiates a deposit to Avail and stake into the pool
    struct FusionStake {
        /// @dev The pool ID
        bytes32 poolId;
        /// @dev The amount to deposit (in wei)
        uint256 amount;
    }

    /// @dev Initiates an unbonding from the pool
    struct FusionUnbond {
        /// @dev The pool ID
        bytes32 poolId;
        /// @dev The amount to start unbonding (in wei)
        uint256 amount;
    }

    /// @dev Initiates a withdrawal from the pool to Ethereum
    struct FusionWithdraw {
        /// @dev The pool ID
        bytes32 poolId;
        /// @dev The amount to withdraw (in wei)
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

    /// @dev Sets the compounding status for the pool for an account
    struct FusionSetCompounding {
        /// @dev The pool ID
        bytes32 poolId;
        /// @dev Whether to set compounding on or off for the pool positions
        bool toCompound;
    }

    /// @dev Sets the controller for the pool for an account
    struct FusionSetController {
        /// @dev A controller on Avail who can manage the position
        bytes32 controller;
    }
}
