from glider import *


def query():
    """
    @title: Missing access control on sensitive functions
    @description: Detects functions that modify critical state without proper access control.
                  Checks for missing onlyOwner, onlyRole, or custom authorization checks.
    @tags: access-control, authorization, privilege-escalation
    @references: https://swcregistry.io/docs/SWC-105/, https://consensys.github.io/smart-contract-best-practices/attacks/access-control/
    """

    sensitive_functions = [
        "setOwner", "transferOwnership", "renounceOwnership",
        "setAdmin", "addAdmin", "removeAdmin",
        "setFees", "setFeeReceiver", "withdrawFees",
        "pause", "unpause", "emergencyWithdraw",
        "upgradeTo", "upgradeToAndCall", "changeImplementation",
        "setImplementation", "setProxyAdmin",
        "mint", "burn", "setMinter",
        "setSigner", "addSigner", "removeSigner",
        "setThreshold", "setGuardian"
    ]

    return (
        Instructions()
        .filter(lambda i: i.is_storage_write())  # Start with state changes only
        .filter(lambda i: i.get_parent() is not None)  # Has parent function
        .filter(lambda i: any(sensitive in i.get_parent().name for sensitive in sensitive_functions))
        .exec()
        .filter(missing_access_control)
    )


def missing_access_control(inst):
    """Check if function lacks proper access control"""
    func = inst.get_parent()
    
    # Quick check: modifiers first (fastest)
    for m in func.modifiers():
        name = m.name
        if any(am in name for am in ["onlyOwner", "onlyAdmin", "onlyRole", "onlyGovernance",
                                      "onlyGuardian", "onlyPauser", "onlyUpgrader",
                                      "authorized", "restricted", "authenticated"]):
            return False  # Has access control modifier
    
    # Check for inline require/if checks - only scan function once
    for fn_inst in func.instructions().exec():
        if "require" in fn_inst.callee_names() or "assert" in fn_inst.callee_names() or fn_inst.is_if():
            for var in fn_inst.vars_read():
                vname = var.name.lower()
                if ("owner" in vname or "admin" in vname or "role" in vname) and \
                   ("msg.sender" in str(fn_inst) or "sender" in vname):
                    return False  # Has inline authorization check
    
    return True  # No access control found