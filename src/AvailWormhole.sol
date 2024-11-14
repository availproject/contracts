// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {
    ERC20Upgradeable,
    ERC20PermitUpgradeable
} from "lib/openzeppelin-contracts-upgradeable/contracts/token/ERC20/extensions/ERC20PermitUpgradeable.sol";
import {AccessControlDefaultAdminRulesUpgradeable} from
    "lib/openzeppelin-contracts-upgradeable/contracts/access/extensions/AccessControlDefaultAdminRulesUpgradeable.sol";
import {INttToken} from "src/interfaces/INttToken.sol";

/**
 * @author  @QEDK (Avail)
 * @title   Avail ERC20 token with support for Wormhole
 * @notice  An Avail token implementation for Wormhole-based bridges
 * @custom:security security@availproject.org
 */
contract AvailWormhole is AccessControlDefaultAdminRulesUpgradeable, ERC20PermitUpgradeable, INttToken {
    bytes32 private constant MINTER_ROLE = keccak256("MINTER_ROLE");

    constructor() {
        _disableInitializers();
    }

    function initialize(address governance, address minter) external initializer {
        __ERC20Permit_init("Avail (Wormhole)");
        __ERC20_init("Avail (Wormhole)", "AVAIL");
        __AccessControlDefaultAdminRules_init(0, governance);
        _grantRole(MINTER_ROLE, minter);
    }

    function mint(address account, uint256 amount) external onlyRole(MINTER_ROLE) {
        _mint(account, amount);
    }

    function burn(uint256 amount) external {
        _burn(msg.sender, amount);
    }
}
