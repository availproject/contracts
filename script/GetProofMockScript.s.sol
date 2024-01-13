// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.23;

import {TransparentUpgradeableProxy} from
    "lib/openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ProxyAdmin} from "lib/openzeppelin-contracts/contracts/proxy/transparent/ProxyAdmin.sol";
import {AvailBridge} from "src/AvailBridge.sol";
import {ERC20Mock} from "src/mocks/ERC20Mock.sol";
import {IWrappedAvail} from "src/interfaces/IWrappedAvail.sol";
import {VectorxMock, IVectorx} from "src/mocks/VectorxMock.sol";
import {Script} from "forge-std/Script.sol";

contract GetProofMockScript is Script {
    function run() external {
        vm.startBroadcast();
        VectorxMock vectorx = new VectorxMock();
        ProxyAdmin admin = new ProxyAdmin(msg.sender);
        address impl = address(new AvailBridge());
        AvailBridge bridge = AvailBridge(address(new TransparentUpgradeableProxy(impl, address(admin), "")));
        ERC20Mock avail = new ERC20Mock();
        bridge.initialize(10000000000, IWrappedAvail(address(avail)), msg.sender, msg.sender, IVectorx(vectorx));
        avail.mint(msg.sender, 1 ether);
        bridge.sendAVL(bytes32(uint256(1)), 1 ether);
        vm.stopBroadcast();
    }
}
