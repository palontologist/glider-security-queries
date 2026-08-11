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
        Functions()
        .filter(lambda f: any(sensitive in f.name for sensitive in sensitive_functions))
        .exec()
        .filter(missing_access_control)
    )


def missing_access_control(func):
    """Check if function lacks proper access control"""
    modifiers = [m.name for m in func.modifiers()]
    
    # Common access control modifiers
    access_modifiers = [
        "onlyOwner", "onlyAdmin", "onlyRole", "onlyGovernance",
        "onlyGuardian", "onlyPauser", "onlyUpgrader",
        "authorized", "restricted", "authenticated"
    ]
    
    has_modifier = any(any(am in m for am in access_modifiers) for m in modifiers)
    
    # Check for inline require checks
    has_inline_check = False
    for inst in func.instructions().exec():
        if inst.is_if() or "require" in inst.callee_names():
            # Check if condition involves msg.sender and owner/admin
            for var in inst.vars_read():
                if "owner" in var.name.lower() or "admin" in var.name.lower() or "role" in var.name.lower():
                    if "msg.sender" in str(inst) or "sender" in var.name.lower():
                        has_inline_check = True
                        break
    
    return not (has_modifier or has_inline_check)