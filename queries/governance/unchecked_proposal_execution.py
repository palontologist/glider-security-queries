from glider import *


def query():
    """
    @title: Governance proposal execution without validation
    @description: Detects governance execute functions that don't validate proposal results.
                  Checks for missing quorum checks, voting period validation, and execution delays.
    @tags: governance, proposal-execution, timelock
    @references: https://github.com/OpenZeppelin/openzeppelin-contracts/tree/master/contracts/governance
    """

    return (
        Functions()
        .filter(lambda f: "execute" in f.name.lower() or "queue" in f.name.lower())
        .filter(lambda f: "proposal" in str(f.parameters()).lower() or "target" in str(f.parameters()).lower())
        .exec()
        .filter(missing_governance_validation)
    )


def missing_governance_validation(func):
    """Check if governance execution lacks proper validation"""
    validations_found = {
        "quorum": False,
        "voting_period": False,
        "execution_delay": False,
        "proposal_state": False,
        "signature_verification": False
    }
    
    for inst in func.instructions().exec():
        callee_names = inst.callee_names()
        vars_read = [v.name for v in inst.vars_read()]
        
        # Check for quorum validation
        if any("quorum" in v.lower() for v in vars_read):
            validations_found["quorum"] = True
        
        # Check for voting period validation
        if any("voting" in v.lower() and ("start" in v.lower() or "end" in v.lower() or "period" in v.lower()) for v in vars_read):
            validations_found["voting_period"] = True
            
        # Check for timelock/delay
        if any("delay" in v.lower() or "timelock" in v.lower() or "eta" in v.lower() for v in vars_read):
            validations_found["execution_delay"] = True
            
        # Check for proposal state validation
        if any("state" in v.lower() and "proposal" in v.lower() for v in vars_read):
            validations_found["proposal_state"] = True
            
        # Check for signature verification (for off-chain voting)
        if any("verify" in c.lower() and "signature" in c.lower() for c in callee_names):
            validations_found["signature_verification"] = True
    
    # At minimum should have quorum and proposal state checks
    return not (validations_found["quorum"] and validations_found["proposal_state"])