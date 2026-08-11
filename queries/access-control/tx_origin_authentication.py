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
    # Check for comparison operations
    code_str = str(inst)
    
    # Direct comparisons: tx.origin == owner, tx.origin != owner, etc.
    auth_patterns = [
        "tx.origin ==",
        "tx.origin !=",
        "tx.origin =",
        "tx.origin <",
        "tx.origin >",
    ]
    
    if any(pattern in code_str for pattern in auth_patterns):
        return True
    
    # Check if used in require/assert condition
    if "require" in inst.callee_names() or "assert" in inst.callee_names():
        return True
    
    # Check if used in if condition
    if inst.is_if():
        return True
    
    # Check if assigned to state variable (owner = tx.origin)
    if inst.is_storage_write():
        for var in inst.vars_written():
            if "owner" in var.name.lower() or "admin" in var.name.lower() or "auth" in var.name.lower():
                return True
    
    return False


def not_in_constructor(inst):
    """Filter out constructor usage (sometimes acceptable)"""
    func = inst.get_parent()
    return func is not None and func.is_constructor() is False


def query_msg_sender_usage():
    """
    @title: Prefer msg.sender over tx.origin
    @description: Finds contracts using tx.origin where msg.sender should be used
    @tags: tx-origin, msg-sender, best-practice
    """
    return (
        Instructions()
        .exec()
        .filter(lambda i: "tx.origin" in str(i))
        .filter(lambda i: "msg.sender" not in str(i))  # Only flag if msg.sender NOT also used
    )