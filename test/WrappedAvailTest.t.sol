// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.23;

import {WrappedAvail} from "src/WrappedAvail.sol";
import {Vm, Test} from "forge-std/Test.sol";

contract WrappedAvailTest is Test {
    WrappedAvail public avail;
    address public bridge;

    function setUp() external {
        bridge = makeAddr("bridge");
        avail = new WrappedAvail(bridge);
    }

    function testRevertOnlyAvailBridge_mint(address sender, address dest, uint256 amount) external {
        vm.assume(dest != address(0) && sender != bridge);
        vm.prank(sender);
        vm.expectRevert(WrappedAvail.OnlyAvailBridge.selector);
        avail.mint(dest, amount);
        assertEq(avail.balanceOf(dest), 0);
    }

    function test_mint(address dest, uint256 amount) external {
        vm.assume(dest != address(0));
        vm.prank(bridge);
        avail.mint(dest, amount);
        assertEq(avail.balanceOf(dest), amount);
    }

    function testRevertOnlyAvailBridge_burn(address sender, address dest, uint256 amount) external {
        vm.assume(dest != address(0) && sender != bridge);
        vm.prank(sender);
        vm.expectRevert(WrappedAvail.OnlyAvailBridge.selector);
        avail.burn(dest, amount);
        assertEq(avail.balanceOf(dest), 0);
    }

    function test_burn(address dest, uint256 mintAmount, uint256 burnAmount) external {
        vm.assume(dest != address(0) && burnAmount < mintAmount);
        vm.startPrank(bridge);
        avail.mint(dest, mintAmount);
        assertEq(avail.balanceOf(dest), mintAmount);
        avail.burn(dest, burnAmount);
        assertEq(avail.balanceOf(dest), mintAmount - burnAmount);
    }
}
