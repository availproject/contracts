// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {Avail} from "src/Avail.sol";
import {Vm, Test} from "forge-std/Test.sol";

contract AvailTest is Test {
    Avail public avail;
    address public bridge;

    function setUp() external {
        bridge = makeAddr("bridge");
        avail = new Avail(bridge);
    }

    function test_nameSymbol() external {
        assertEq(avail.name(), "Avail");
        assertEq(avail.symbol(), "AVAIL");
    }

    function testRevertOnlyAvailBridge_mint(address sender, address dest, uint256 amount) external {
        vm.assume(dest != address(0) && sender != bridge);
        vm.prank(sender);
        vm.expectRevert(Avail.OnlyAvailBridge.selector);
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
        vm.expectRevert(Avail.OnlyAvailBridge.selector);
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
