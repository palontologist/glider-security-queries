# Testing Glider Queries

This guide covers testing strategies for Glider security queries.

## Testing Levels

### 1. Syntax Validation
```bash
python scripts/validate_queries.py
```
Checks for Python syntax errors and basic Glider API usage.

### 2. Unit Testing with Foundry

Test contracts in `examples/VulnerablePatterns.sol` with tests in `tests/GliderQueryTests.t.sol`.

```bash
# Run all tests
forge test -vv

# Run specific test
forge test --match-test testVulnerableReentrancy -vv

# Run with gas reporting
forge test --gas-report
```

### 3. Integration Testing with Glider

```bash
# Run query against examples
glider run queries/category/query.py --target ./examples --format json

# Run against real contracts (requires Glider engine access)
glider run queries/category/query.py --target 0xContractAddress --chain mainnet
```

### 4. Regression Testing

```bash
# Test against known vulnerable contracts
python scripts/run_all_queries.py --target ./test-contracts --output results/
```

## Test Contract Patterns

### Vulnerable Pattern
```solidity
contract VulnerableExample {
    // CLEAR vulnerability with comment
    function vulnerableFunction() external {
        // VULNERABLE: Missing validation
        (bool success, ) = target.call(data);
        // No require(success, "...")
    }
}
```

### Safe Pattern
```solidity
contract SafeExample {
    // SAFE: Proper validation
    function safeFunction() external returns (bytes memory) {
        (bool success, bytes memory result) = target.call(data);
        require(success, "Call failed");
        return result;
    }
}
```

### Edge Cases to Test

1. **Assembly validation** - Contracts validating in inline assembly
2. **Library patterns** - OpenZeppelin `Address.verifyCallResult`
3. **Proxy patterns** - Delegatecall in fallback/upgrade functions
4. **Multi-call patterns** - Batch operations with partial validation
5. **Simulation functions** - Functions that always revert (should be filtered)
6. **Different Solidity versions** - 0.7.x vs 0.8.x behavior differences

## Writing Foundry Tests

### Basic Test Structure
```solidity
contract MyQueryTest is Test {
    VulnerableContract vuln;
    SafeContract safe;
    
    function setUp() public {
        vuln = new VulnerableContract();
        safe = new SafeContract();
    }
    
    function testVulnerablePatternDetected() public {
        // Test that vulnerable pattern exists
        vm.prank(attacker);
        vuln.vulnerableFunction();
        // If no revert, vulnerability confirmed
    }
    
    function testSafePatternNotFlagged() public {
        // Test that safe pattern works correctly
        vm.prank(user);
        safe.safeFunction();
        // Should succeed with proper validation
    }
}
```

### Testing Reentrancy
```solidity
function testReentrancyAttack() public {
    VulnerableReentrancy vuln = new VulnerableReentrancy();
    ReentrancyAttacker attacker = new ReentrancyAttacker(address(vuln));
    
    // Fund victim
    vm.deal(address(vuln), 10 ether);
    
    // Attack
    vm.prank(address(attacker));
    attacker.attack{value: 1 ether}();
    
    // Check if attacker drained more than deposited
    assertGt(address(attacker).balance, 1 ether);
}
```

### Testing Access Control
```solidity
function testMissingAccessControl() public {
    VulnerableAccessControl vuln = new VulnerableAccessControl();
    address attacker = makeAddr("attacker");
    
    // Should succeed without auth (vulnerability)
    vm.prank(attacker);
    vuln.setCriticalParameter(123);
    
    assertEq(vuln.criticalParameter(), 123);
}

function testProperAccessControl() public {
    SafeAccessControl safe = new SafeAccessControl();
    address attacker = makeAddr("attacker");
    
    // Should revert without auth
    vm.prank(attacker);
    vm.expectRevert("Not authorized");
    safe.setCriticalParameter(123);
}
```

### Testing Unchecked Calls
```solidity
function testUncheckedCallSilentlyFails() public {
    VulnerableUncheckedCalls vuln = new VulnerableUncheckedCalls(address(this));
    
    // Call non-existent function
    bytes memory data = abi.encodeWithSignature("doesNotExist()");
    
    // Should NOT revert - vulnerability
    vuln.uncheckedCall(data);
    
    // If we reach here, call silently failed
}
```

## Automated Testing Script

```python
# scripts/validate_queries.py
import subprocess
import sys
from pathlib import Path

def validate_queries():
    query_dir = Path("queries")
    errors = []
    
    for query_file in query_dir.rglob("*.py"):
        # Syntax check
        result = subprocess.run(
            ["python", "-m", "py_compile", str(query_file)],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            errors.append(f"{query_file}: {result.stderr}")
        
        # Import check
        result = subprocess.run(
            ["python", "-c", f"import sys; sys.path.insert(0, '.'); exec(open('{query_file}').read())"],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            errors.append(f"{query_file} import: {result.stderr}")
    
    if errors:
        print("VALIDATION FAILED:")
        for e in errors:
            print(f"  - {e}")
        return False
    
    print("All queries validated successfully!")
    return True

if __name__ == "__main__":
    sys.exit(0 if validate_queries() else 1)
```

## CI/CD Testing

The GitHub Actions workflow runs:
1. Syntax validation
2. Query execution against examples
3. Foundry tests
4. SARIF upload for code scanning

```yaml
# .github/workflows/glider-scan.yml
- name: Validate Queries
  run: python scripts/validate_queries.py

- name: Run Glider Queries
  run: |
    for q in queries/**/*.py; do
      glider run "$q" --target ./examples --format sarif --output "results/$(basename $q .py).sarif"
    done

- name: Run Foundry Tests
  run: forge test -vv
```

## Benchmarking

Track query performance:
```bash
# Time query execution
time glider run queries/delegatecall/unchecked_delegatecall_return.py --target ./examples

# Count results
glider run queries/delegatecall/unchecked_delegatecall_return.py --target ./examples --format json | jq length
```

## False Positive Analysis

After running on real contracts:
1. Review each result manually
2. Categorize: True Positive / False Positive / Informational
3. Update query to reduce false positives
4. Document known false positive patterns in query comments

## Testing Checklist

Before submitting query:
- [ ] Syntax validation passes
- [ ] Query runs without errors on examples
- [ ] Foundry tests pass (vulnerable detected, safe not flagged)
- [ ] Edge cases tested (assembly, libraries, proxies)
- [ ] Performance acceptable (< 30s on example set)
- [ ] False positive rate documented