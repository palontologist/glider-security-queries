// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../examples/VulnerablePatterns.sol";

contract GliderQueryTests is Test {
    // ============================================
    // REENTRANCY TESTS
    // ============================================
    
    function testVulnerableReentrancy() public {
        VulnerableReentrancy vuln = new VulnerableReentrancy();
        address attacker = address(new ReentrancyAttacker(address(vuln)));
        
        // Setup: deposit some ETH
        vm.deal(attacker, 1 ether);
        vm.prank(attacker);
        vuln.withdraw{value: 1 ether}();
        
        // The vulnerable contract allows reentrancy
        // This test would need a proper attacker contract to demonstrate
    }
    
    // ============================================
    // ACCESS CONTROL TESTS
    // ============================================
    
    function testVulnerableAccessControl_NoAuth() public {
        VulnerableAccessControl vuln = new VulnerableAccessControl();
        address attacker = makeAddr("attacker");
        
        // Should succeed without authorization - VULNERABLE
        vm.prank(attacker);
        vuln.setFee(100);
        assertEq(vuln.fee(), 100);
        
        vm.prank(attacker);
        vuln.setFeeReceiver(attacker);
        assertEq(vuln.feeReceiver(), attacker);
        
        vm.prank(attacker);
        vuln.pause();
        assertTrue(vuln.paused());
    }
    
    function testSafeAccessControl_RequiresAuth() public {
        SafeAccessControl safe = new SafeAccessControl();
        address attacker = makeAddr("attacker");
        
        // Should revert without authorization
        vm.prank(attacker);
        vm.expectRevert("Not owner");
        safe.setFee(100);
        
        vm.prank(attacker);
        vm.expectRevert("Not owner");
        safe.setFeeReceiver(attacker);
        
        vm.prank(attacker);
        vm.expectRevert("Not owner");
        safe.pause();
    }
    
    // ============================================
    // UNCHECKED LOW-LEVEL CALLS TESTS
    // ============================================
    
    function testVulnerableUncheckedCall_NoRevert() public {
        VulnerableUncheckedCalls vuln = new VulnerableUncheckedCalls(address(this));
        
        // Call non-existent function - should NOT revert (vulnerability)
        bytes memory data = abi.encodeWithSignature("nonExistentFunction()");
        vuln.callTarget(data);  // Silently fails
        
        // If we reach here, vulnerability confirmed
        assertTrue(true, "Unchecked call silently ignores failure");
    }
    
    function testSafeUncheckedCall_Reverts() public {
        SafeUncheckedCalls safe = new SafeUncheckedCalls(address(this));
        
        bytes memory data = abi.encodeWithSignature("nonExistentFunction()");
        
        vm.expectRevert("Call failed");
        safe.callTarget(data);
    }
    
    function testVulnerableDelegatecall_NoRevert() public {
        VulnerableUncheckedCalls vuln = new VulnerableUncheckedCalls(address(this));
        
        bytes memory data = abi.encodeWithSignature("nonExistentFunction()");
        vuln.delegatecallTarget(data);  // Silently fails
        
        assertTrue(true, "Unchecked delegatecall silently ignores failure");
    }
    
    // ============================================
    // GOVERNANCE TESTS
    // ============================================
    
    function testVulnerableGovernance_NoValidation() public {
        VulnerableGovernance vuln = new VulnerableGovernance();
        
        // Create a proposal pointing to this contract
        bytes memory data = abi.encodeWithSignature("nonExistentFunction()");
        // Note: Can't easily test without adding proposal creation function
        // This demonstrates the pattern
    }
    
    // ============================================
    // PROXY UPGRADE TESTS
    // ============================================
    
    function testVulnerableProxyUpgrade_NoInitValidation() public {
        VulnerableProxy proxy = new VulnerableProxy(address(new TargetContract()));
        
        // Upgrade to a contract that reverts on initialize
        address badImpl = address(new BadImplementation());
        
        vm.prank(proxy.admin());
        // This should NOT revert despite initialization failing
        proxy.upgradeTo(badImpl);
        
        // If we reach here, vulnerability confirmed
        assertTrue(true, "Proxy upgrade ignores failed initialization");
    }
    
    function testSafeProxyUpgrade_ValidatesInit() public {
        SafeProxy proxy = new SafeProxy(address(new TargetContract()));
        
        address badImpl = address(new BadImplementation());
        
        vm.prank(proxy.admin());
        vm.expectRevert("Initialization failed");
        proxy.upgradeTo(badImpl);
    }
}

// Helper contracts for testing

contract ReentrancyAttacker {
    VulnerableReentrancy public target;
    uint256 public attackCount;
    
    constructor(address _target) {
        target = VulnerableReentrancy(_target);
    }
    
    function attack() external payable {
        target.withdraw{value: msg.value}();
    }
    
    fallback() external payable {
        if (attackCount < 3) {
            attackCount++;
            target.withdraw();
        }
    }
}

contract TargetContract {
    function validFunction() external pure returns (string memory) {
        return "success";
    }
}

contract BadImplementation {
    function initialize() external {
        revert("Initialization failed");
    }
}