from glider import *


def query():
    """
    @title: Unchecked low-level call return values
    @description: Detects call, delegatecall, staticcall without return value validation.
                  Covers call, delegatecall, and staticcall patterns.
    @tags: unchecked-calls, low-level-calls, return-values
    @references: https://swcregistry.io/docs/SWC-104/, https://swcregistry.io/docs/SWC-112/
    """

    return (
        Instructions()
        .filter(lambda i: i.is_call() or i.is_delegate_call() or i.is_static_call())
        .exec()
        .filter(not_assembly)
        .filter(missing_return_validation)
    )


def not_assembly(inst):
    """Filter out assembly blocks"""
    return not inst.is_assembly()


def missing_return_validation(inst):
    """Check if call return value is not validated"""
    dest = inst.get_dest()
    
    if dest is None:
        # No assignment - return value ignored entirely
        return True
    
    # Check if success variable is used in validation
    success_vars = []
    if isinstance(dest, VarValue):
        success_vars = [dest]
    elif hasattr(dest, 'get_components'):
        # Tuple destructuring: (bool success, bytes memory data) = ...
        for comp in dest.get_components():
            vars = comp.get_vars()
            if vars:
                success_vars.extend(vars)
    
    if not success_vars:
        return True
    
    # Track data flow from success variables
    for var in success_vars:
        usages = var.forward_df_recursive().filter(lambda p: isinstance(p, Instruction)).exec()
        for usage in usages:
            if validates_call_result(usage):
                return False
    
    return True


def validates_call_result(inst):
    """Check if instruction validates a call result"""
    callee_names = inst.callee_names()
    
    # Direct validation patterns
    if "require" in callee_names or "assert" in callee_names:
        return True
    
    # OpenZeppelin patterns
    oz_validators = ["verifyCallResult", "verifyCallResultFromTarget", "_verifyCallResult"]
    if any(v in callee_names for v in oz_validators):
        return True
    
    # If/else with revert
    if inst.is_if():
        true_branch = inst.first_true_instruction()
        false_branch = inst.first_false_instruction()
        if true_branch and "revert" in true_branch.builtin_callee_names():
            return True
        if false_branch and "revert" in false_branch.builtin_callee_names():
            return True
    
    # Direct revert
    if "revert" in inst.builtin_callee_names():
        return True
    
    return False