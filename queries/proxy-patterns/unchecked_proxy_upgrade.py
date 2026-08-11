from glider import *


def query():
    """
    @title: Proxy upgrade without initialization validation
    @description: Detects proxy upgrade functions that don't validate initialization delegatecalls.
                  Critical for UUPS, Transparent, and Diamond proxy patterns.
    @tags: proxy, upgradeable, initialization, delegatecall
    @references: https://docs.openzeppelin.com/contracts/4.x/api/proxy, https://eips.ethereum.org/EIPS/eip-1822
    """

    return (
        Instructions()
        .filter(lambda i: i.is_function_definition())
        .filter(lambda i: any(kw in i.get_parent_function().name.lower() for kw in ["upgrade", "setimplementation", "changeimplementation", "setfacet"]))
        .exec()
        .filter(missing_initialization_validation)
    )


def missing_initialization_validation(inst):
    """Check if proxy upgrade validates initialization"""
    func = inst.get_parent_function()
    has_delegatecall = False
    has_init_validation = False
    
    for fn_inst in func.instructions().exec():
        if fn_inst.is_delegate_call():
            has_delegatecall = True
            dest = fn_inst.get_dest()
            
            # Track if delegatecall return is validated
            if dest:
                success_vars = []
                if isinstance(dest, VarValue):
                    success_vars = [dest]
                elif hasattr(dest, 'get_components'):
                    for comp in dest.get_components():
                        vars = comp.get_vars()
                        if vars:
                            success_vars.extend(vars)
                
                for var in success_vars:
                    usages = var.forward_df_recursive().filter(lambda p: isinstance(p, Instruction)).exec()
                    for usage in usages:
                        if validates_call_result(usage):
                            has_init_validation = True
                            break
    
    # If there's a delegatecall but no validation, it's vulnerable
    return has_delegatecall and not has_init_validation


def validates_call_result(inst):
    callee_names = inst.callee_names()
    if "require" in callee_names or "assert" in callee_names:
        return True
    oz_validators = ["verifyCallResult", "verifyCallResultFromTarget", "_verifyCallResult"]
    if any(v in callee_names for v in oz_validators):
        return True
    if inst.is_if():
        true_branch = inst.first_true_instruction()
        false_branch = inst.first_false_instruction()
        if true_branch and "revert" in true_branch.builtin_callee_names():
            return True
        if false_branch and "revert" in false_branch.builtin_callee_names():
            return True
    if "revert" in inst.builtin_callee_names():
        return True
    return False


def query_diamond_facet():
    """
    @title: Diamond facet replacement without validation
    @description: Detects diamondCut/facet replacement without proper validation
    @tags: diamond, proxy, facet, eip2535
    """
    return (
        Instructions()
        .filter(lambda i: i.is_function_definition())
        .filter(lambda i: "diamondcut" in i.get_parent_function().name.lower() or "setfacet" in i.get_parent_function().name.lower() or "replacefacet" in i.get_parent_function().name.lower())
        .exec()
        .filter(missing_facet_validation)
    )


def missing_facet_validation(inst):
    """Check if diamond facet change validates facet address"""
    func = inst.get_parent_function()
    has_validation = False
    
    for fn_inst in func.instructions().exec():
        # Check for address validation (non-zero, valid facet)
        if fn_inst.is_if():
            for var in fn_inst.vars_read():
                if "facet" in var.name.lower() or "address" in var.name.lower():
                    # Check if comparing to zero address
                    if "0x0" in str(fn_inst) or "address(0)" in str(fn_inst):
                        has_validation = True
    
    return not has_validation