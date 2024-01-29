// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.23;

import {TransparentUpgradeableProxy} from
    "lib/openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ProxyAdmin} from "lib/openzeppelin-contracts/contracts/proxy/transparent/ProxyAdmin.sol";
import {AvailBridge} from "src/AvailBridge.sol";
import {IAvailBridge} from "src/interfaces/IAvailBridge.sol";
import {ERC20Mock} from "src/mocks/ERC20Mock.sol";
import {IAvail} from "src/interfaces/IAvail.sol";
import {VectorxMock, IVectorx} from "src/mocks/VectorxMock.sol";
import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";

contract GetProofMockScript is Script {
    function run() external {
        vm.startBroadcast();
        VectorxMock vectorx = new VectorxMock();
        ProxyAdmin admin = new ProxyAdmin(msg.sender);
        address impl = address(new AvailBridge());
        AvailBridge bridge = AvailBridge(address(new TransparentUpgradeableProxy(impl, address(admin), "")));
        ERC20Mock avail = new ERC20Mock();
        bridge.initialize(0, msg.sender, IAvail(address(avail)), msg.sender, msg.sender, IVectorx(vectorx));
        avail.mint(msg.sender, 1 ether);
        bridge.sendAVAIL(bytes32(uint256(1)), 1 ether);
        console.logBytes32(bridge.isSent(0));
        IAvailBridge.Message memory message = IAvailBridge.Message(
            0x02,
            bytes32(bytes20(0x681257BED628425a28B469114Dc21A7c30205cFD)),
            bytes32(uint256(1)),
            2,
            1,
            abi.encode(bytes32(0), 1 ether),
            0
        );
        console.logBytes(abi.encode(message));
        console.logBytes32(keccak256(abi.encode(message)));
        vm.stopBroadcast();
    }
}
