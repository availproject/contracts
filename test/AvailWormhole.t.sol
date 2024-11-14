// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {AvailWormhole} from "src/bridged/AvailWormhole.sol";
import {TransparentUpgradeableProxy} from
    "lib/openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {IAccessControl} from "lib/openzeppelin-contracts/contracts/access/IAccessControl.sol";
import {Vm, Test} from "forge-std/Test.sol";

contract AvailWormholeTest is Test {
    AvailWormhole avail;
    address owner;
    address governance;
    address minter;
    bytes32 private constant MINTER_ROLE = keccak256("MINTER_ROLE");

    function setUp() external {
        governance = makeAddr("governance");
        minter = makeAddr("minter");
        address impl = address(new AvailWormhole());
        avail = AvailWormhole(address(new TransparentUpgradeableProxy(impl, msg.sender, "")));
        avail.initialize(governance, minter);
    }

    function testRevert_initialize(address rand) external {
        vm.expectRevert();
        avail.initialize(rand, rand);
    }

    function test_initialize() external {
        assertEq(avail.totalSupply(), 0);
        assertNotEq(avail.owner(), address(0));
        assertEq(avail.owner(), governance);
        assertNotEq(avail.name(), "");
        assertEq(avail.name(), "Avail (Wormhole)");
        assertNotEq(avail.symbol(), "");
        assertEq(avail.symbol(), "AVAIL");
    }

    function testRevertOnlyMinter_mint(address to, uint256 amount) external {
        address rand = makeAddr("rand");
        vm.assume(rand != minter);
        vm.expectRevert(
            abi.encodeWithSelector((IAccessControl.AccessControlUnauthorizedAccount.selector), rand, MINTER_ROLE)
        );
        vm.prank(rand);
        avail.mint(to, amount);
    }

    function test_mint(address to, uint256 amount) external {
        vm.assume(to != address(0));
        vm.prank(minter);
        avail.mint(to, amount);
        assertEq(avail.balanceOf(to), amount);
    }

    function test_burn(address from, uint256 amount) external {
        vm.assume(from != address(0));
        vm.prank(minter);
        avail.mint(from, amount);
        assertEq(avail.balanceOf(from), amount);
        vm.prank(from);
        avail.burn(amount);
        assertEq(avail.balanceOf(from), 0);
    }

    function test_burn2(address from, uint256 amount, uint256 amount2) external {
        vm.assume(from != address(0) && amount2 < amount);
        vm.prank(minter);
        avail.mint(from, amount);
        assertEq(avail.balanceOf(from), amount);
        vm.prank(from);
        avail.burn(amount2);
        assertEq(avail.balanceOf(from), amount - amount2);
    }
}
