# Glider Query Template

Use this template when creating new queries. Copy to appropriate category folder.

```python
from glider import *


def query():
    """
    @title: [Short descriptive title - e.g., "Unchecked delegatecall return value"]
    @description: [Detailed explanation:
                   - What vulnerability this detects
                   - Why it's dangerous
                   - What patterns are matched
                   - Any known limitations]
    @author: [Your handle/name]
    @tags: [comma, separated, relevant, tags]
    @references: 
        - https://swcregistry.io/docs/SWC-XXX/
        - https://github.com/.../audit-report
        - https://blog.example.com/vulnerability-analysis
    """

    return (
        # Start with appropriate Glider collection
        Instructions()      # For instruction-level patterns
        # Functions()      # For function-level patterns  
        # Contracts()      # For contract-level patterns
        
        # Chain filters
        .filter(lambda i: i.is_delegate_call())  # Example filter
        .exec()
        
        # Custom filters (defined below)
        .filter(filter_name_1)
        .filter(filter_name_2)
    )


# ============================================
# HELPER FUNCTIONS
# ============================================

def filter_name_1(item):
    """
    Filter description.
    Returns True to KEEP item, False to FILTER OUT.
    """
    # Your logic here
    return True  # or False


def filter_name_2(item):
    """Another filter."""
    return True


# ============================================
# COMMON UTILITY FUNCTIONS
# ============================================

def not_simulation_functions(instruction):
    """Filter out functions that always revert (simulation/test functions)."""
    return len(
        instruction
        .forward_df_recursive()
        .filter(lambda point: isinstance(point, Instruction))
        .filter(revert_instruction)
    ) == 0


def revert_instruction(instruction):
    """Check if instruction is a revert."""
    return "revert" in instruction.builtin_callee_names()


def validates_call_result(instruction):
    """Check if instruction validates a call/delegatecall result."""
    callee_names = instruction.callee_names()
    
    # Direct validation
    if "require" in callee_names or "assert" in callee_names:
        return True
    
    # OpenZeppelin patterns
    oz_validators = ["verifyCallResult", "verifyCallResultFromTarget", "_verifyCallResult"]
    if any(v in callee_names for v in oz_validators):
        return True
    
    # If/else with revert
    if instruction.is_if():
        true_branch = instruction.first_true_instruction()
        false_branch = instruction.first_false_instruction()
        if true_branch and "revert" in true_branch.builtin_callee_names():
            return True
        if false_branch and "revert" in false_branch.builtin_callee_names():
            return True
    
    # Direct revert
    if "revert" in instruction.builtin_callee_names():
        return True
    
    return False


def is_assembly(instruction):
    """Check if instruction is in assembly block."""
    return instruction.is_assembly()


def get_success_variables(instruction):
    """Extract success variable(s) from call instruction destination."""
    dest = instruction.get_dest()
    if dest is None:
        return []
    
    if isinstance(dest, VarValue):
        return [dest]
    
    # Tuple destructuring
    success_vars = []
    if hasattr(dest, 'get_components'):
        for comp in dest.get_components():
            vars = comp.get_vars()
            if vars:
                success_vars.extend(vars)
    return success_vars


# ============================================
# KNOWN LIMITATIONS (Document at bottom)
# ============================================

"""
LIMITATIONS:
- Assembly validation not tracked (Glider limitation)
- May miss validation in external library calls
- Solidity version-specific patterns may need adjustment
- False positives possible for [specific pattern]
"""
```

## Category-Specific Tips

### Delegatecall Queries
- Use `Instructions().delegate_calls_non_assembly()`
- Track success variable through data flow
- Filter `delegateCallAndRevert` functions

### Reentrancy Queries
- Use `Functions()` to analyze control flow
- Check instruction ordering (state change after call)
- Look for `nonReentrant` modifiers and mutex patterns

### Access Control Queries
- Use `Functions()` with name pattern matching
- Check modifiers AND inline `require` checks
- Consider role-based systems (AccessControl, Ownable)

### Unchecked Call Queries
- Check `call`, `delegatecall`, `staticcall`, `send`, `transfer`
- Track all return value patterns (tuple, single var, ignored)
- Consider OpenZeppelin `Address.verifyCallResult`

### Integer Overflow Queries
- Check Solidity version (`contract.solidity_version()`)
- Detect `unchecked{}` blocks
- Identify user-controlled operands

### Governance Queries
- Look for `execute`, `queue`, `propose` functions
- Check for quorum, voting period, delay validations
- Consider timelock patterns

### Proxy Queries
- Detect `upgradeTo`, `upgradeToAndCall`, `setImplementation`
- Validate initialization delegatecalls
- Check for UUPS, Transparent, Diamond patterns

### Oracle Queries
- Detect Chainlink `AggregatorV3Interface` calls
- Check for `latestRoundData`, `getPrice`, etc.
- Validate TWAP, deviation, heartbeat, multiple sources