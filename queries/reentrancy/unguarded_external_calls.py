from glider import *


def query():
    """
    @title: Reentrancy via unguarded external calls
    @description: Detects functions making external calls without reentrancy guards.
                  Vulnerable to reentrancy attacks when state changes occur after external calls.
    @tags: reentrancy, external-calls, state-changes
    @references: https://swcregistry.io/docs/SWC-107/, https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/
    """

    return (
        Functions()
        .with_callee_names(["call", "transfer", "send", "delegatecall", "staticcall"])
        .exec()
        .filter(has_state_change_after_external_call)
        .filter(not_protected_by_reentrancy_guard)
    )


def has_state_change_after_external_call(func):
    """Check if function has state changes after external calls"""
    external_calls = (
        func
        .instructions()
        .filter(lambda i: i.is_call() or i.is_delegate_call() or i.is_static_call())
        .exec()
    )
    
    state_changes = (
        func
        .instructions()
        .filter(lambda i: i.is_storage_write() or i.is_event_emission())
        .exec()
    )
    
    # Check if any state change occurs after an external call
    for call in external_calls:
        for change in state_changes:
            if change.get_line() > call.get_line():
                return True
    return False


def not_protected_by_reentrancy_guard(func):
    """Check if function lacks reentrancy protection"""
    # Check for OpenZeppelin ReentrancyGuard modifier
    modifiers = func.modifiers()
    has_nonreentrant = any("nonReentrant" in m.name for m in modifiers)
    
    # Check for custom mutex pattern
    has_mutex = False
    for var in func.state_variables_read():
        if "mutex" in var.name.lower() or "lock" in var.name.lower() or "reentrancy" in var.name.lower():
            has_mutex = True
            break
    
    return not (has_nonreentrant or has_mutex)