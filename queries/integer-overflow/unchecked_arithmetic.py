from glider import *


def query():
    """
    @title: Integer overflow/underflow in arithmetic operations
    @description: Detects arithmetic operations without overflow protection.
                  Covers +, -, *, /, % operations on uint/int types.
                  Note: Solidity 0.8+ has built-in checks, but older versions and unchecked{} blocks are vulnerable.
    @tags: integer-overflow, arithmetic, solidity-version
    @references: https://swcregistry.io/docs/SWC-101/, https://docs.soliditylang.org/en/latest/types.html#integers
    """

    return (
        Instructions()
        .filter(lambda i: i.is_binary_operation())
        .filter(uses_vulnerable_arithmetic)
        .exec()
    )


def uses_vulnerable_arithmetic(inst):
    """Check if arithmetic operation is vulnerable to overflow"""
    operator = inst.get_operator()
    vulnerable_ops = ["+", "-", "*", "/", "%", "**"]
    
    if operator not in vulnerable_ops:
        return False
    
    # Check if in unchecked block
    if inst.is_in_unchecked_block():
        return True
    
    # Check Solidity version - contracts < 0.8.0 are vulnerable
    contract = inst.get_parent_contract()
    if contract and contract.solidity_version():
        version = contract.solidity_version()
        if version_lt(version, "0.8.0"):
            return True
    
    # Check if operands are user-controlled (not constants)
    left = inst.get_left_operand()
    right = inst.get_right_operand()
    
    left_user_controlled = is_user_controlled(left)
    right_user_controlled = is_user_controlled(right)
    
    return left_user_controlled or right_user_controlled


def version_lt(version, target):
    """Compare version strings"""
    v_parts = [int(x) for x in version.replace("^", "").replace("~", "").split(".")]
    t_parts = [int(x) for x in target.split(".")]
    return v_parts < t_parts


def is_user_controlled(operand):
    """Check if operand comes from user input"""
    if operand is None:
        return False
    
    if isinstance(operand, Constant):
        return False
    
    # Check if derived from function parameters, calldata, or storage
    sources = operand.backward_df_recursive().exec()
    for src in sources:
        if isinstance(src, (FunctionParameter, CalldataLoad, StorageLoad)):
            return True
    
    return False