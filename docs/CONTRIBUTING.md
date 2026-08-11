# Contributing to Glider Security Queries

Thank you for contributing! This guide will help you add high-quality security queries to the repository.

## Query Development Process

### 1. Identify Vulnerability Pattern

Before writing a query:
- Research the vulnerability (SWC, CVE, audit reports)
- Understand the code patterns that indicate the vulnerability
- Identify false positive sources
- Determine if Glider can express the detection logic

### 2. Choose Category

Place query in appropriate folder:
- `queries/delegatecall/` - Delegatecall related
- `queries/reentrancy/` - Reentrancy patterns
- `queries/access-control/` - Authorization issues
- `queries/unchecked-calls/` - Low-level call validation
- `queries/integer-overflow/` - Arithmetic issues
- `queries/governance/` - Governance/timelock issues
- `queries/proxy-patterns/` - Upgradeable contract issues
- `queries/oracle-manipulation/` - Oracle/price feed issues

### 3. Write Query

Use the template in `docs/QUERY_TEMPLATE.md`.

**Required elements:**
```python
def query():
    """
    @title: Short descriptive title
    @description: Detailed explanation of what this detects
    @tags: comma, separated, tags
    @references: https://swcregistry.io/docs/SWC-XXX/, other references
    """
    
    return (
        # Glider API chain
        Instructions()  # or Functions(), Contracts()
        .filter(...)
        .exec()
        .filter(custom_filter_function)
    )

def custom_filter_function(item):
    """Filter logic with clear name"""
    # Implementation
    return boolean_result
```

### 4. Add Test Cases

In `examples/VulnerablePatterns.sol`:
- Add vulnerable contract demonstrating the issue
- Add safe version showing correct pattern
- Include comments explaining the vulnerability

### 5. Add Foundry Tests

In `tests/GliderQueryTests.t.sol`:
- Test that vulnerable pattern is detected
- Test that safe pattern is NOT flagged
- Use `vm.expectRevert` for expected failures

### 6. Validate

```bash
# Syntax validation
python scripts/validate_queries.py

# Run against examples
glider run queries/category/query.py --target ./examples

# Run Foundry tests
forge test --match-contract GliderQueryTests -vv
```

## Query Quality Standards

### Documentation

Every query MUST have:
- [ ] Clear title describing the vulnerability
- [ ] Description explaining what it detects and why it matters
- [ ] Tags for categorization
- [ ] References (SWC, CVE, blog posts, audit reports)
- [ ] Author attribution (optional)

### Code Quality

- [ ] Type hints where applicable
- [ ] Descriptive function/variable names
- [ ] Comments for complex logic
- [ ] Known limitations documented
- [ ] No hardcoded contract addresses/names (use patterns)

### Detection Accuracy

- [ ] Minimizes false positives
- [ ] Handles common variations (library patterns, assembly, etc.)
- [ ] Filters out simulation/test functions
- [ ] Accounts for Solidity version differences

### Testing

- [ ] At least 1 vulnerable example
- [ ] At least 1 safe example
- [ ] Foundry test confirming detection
- [ ] Edge cases covered

## Common Patterns

### Filtering Simulation Functions

```python
def not_simulation_functions(instruction):
    return len(
        instruction
        .forward_df_recursive()
        .filter(lambda point: isinstance(point, Instruction))
        .filter(revert_instruction)
    ) == 0
```

### Checking for Validation Patterns

```python
def validates_success(instruction):
    return (
        calls_validation_function(instruction) or
        contains_guard_check(instruction)
    )

def calls_validation_function(instruction):
    validating_functions = [
        "verifyCallResult",
        "verifyCallResultFromTarget",
        "_verifyCallResult"
    ]
    return any(func in instruction.callee_names() for func in validating_functions)
```

### Handling Assembly Limitations

```python
# NOTE: Assembly validation not tracked - may cause false positives
# TODO: Update when Glider supports assembly data flow
```

## Submission Checklist

Before submitting PR:

- [ ] Query follows template
- [ ] All required documentation present
- [ ] Test cases added to examples
- [ ] Foundry tests pass
- [ ] Validation script passes
- [ ] No syntax errors
- [ ] Query runs without errors on examples
- [ ] PR description explains the vulnerability and detection approach

## Review Process

1. Automated checks (syntax, tests)
2. Code review for accuracy and style
3. Testing against real contracts (if possible)
4. Merge and release

## Getting Help

- [Glider Documentation](https://glide.gitbook.io/main/)
- [Glider Discord](https://discord.gg/glider)
- [GitHub Issues](https://github.com/palontologist/glider-security-queries/issues)