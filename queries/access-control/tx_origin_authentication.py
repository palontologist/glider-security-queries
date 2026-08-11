from glider import *


def query():
    """
    @title: tx.origin used for authentication
    @description: Detects contracts using tx.origin for authorization checks.
                  Vulnerable to phishing attacks - tx.origin returns the original EOA caller,
                  allowing malicious contracts to impersonate users.
    @tags: tx-origin, authentication, phishing, access-control
    @references: https://swcregistry.io/docs/SWC-115/, https://consensys.github.io/smart-contract-best-practices/attacks/tx-origin/
    """

    return (
        Instructions()
        .exec()
        .filter(lambda i: "tx.origin" in str(i))
        .filter(is_authentication_check)
        .filter(not_in_constructor)
    )


def is_authentication_check(inst):
    """Check if tx.origin is used in an authentication/authorization context"""
    code_str = str(inst)
    
    # Check if it's a comparison/assignment involving tx.origin
    if any(op in code_str for op in ["==", "!=", "=", "<", ">"]):
        return True
    
    # Check if used in require/assert condition
    if "require" in inst.callee_names() or "assert" in inst.callee_names():
        return True
    
    # Check if used in if condition
    if inst.is_if():
        return True
    
    # Check if assigned to state variable
    if inst.is_storage_write():
        for var in inst.vars_written():
            if any(kw in var.name.lower() for kw in ["owner", "admin", "auth"]):
                return True
    
    return False


def not_in_constructor(inst):
    """Filter out constructor usage (sometimes acceptable)"""
    func = inst.get_parent()
    return func is not None and not func.is_constructor()


def query_simple():
    """
    @title: Simple tx.origin detection
    @description: Finds any use of tx.origin in contracts
    @tags: tx-origin
    """
    return (
        Instructions()
        .exec()
        .filter(lambda i: "tx.origin" in str(i))
    )