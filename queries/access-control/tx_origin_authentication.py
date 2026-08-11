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

    # Use Functions() to find functions containing tx.origin - more efficient
    return (
        Functions()
        .exec()
        .filter(function_uses_tx_origin_for_auth)
    )


def function_uses_tx_origin_for_auth(func):
    """Check if function uses tx.origin in auth context"""
    code = str(func)
    if "tx.origin" not in code:
        return False
    
    # Check for auth patterns in function
    auth_patterns = [
        "tx.origin ==",
        "tx.origin !=",
        "tx.origin =",
        "require(",
        "assert(",
    ]
    
    return any(pattern in code for pattern in auth_patterns)


def not_in_constructor(func):
    """Filter out constructor"""
    return not func.is_constructor()


def query_simple():
    """
    @title: Simple tx.origin detection
    @description: Finds any use of tx.origin in contracts
    @tags: tx-origin
    """
    return (
        Functions()
        .exec()
        .filter(lambda f: "tx.origin" in str(f))
    )