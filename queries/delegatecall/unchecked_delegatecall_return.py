from glider import *


def query():
    """
      @title: Low-level delegatecall return value not validated
      @description: Functions that call other contracts via delegatecall should validate the success return value.
                    Failing to do so risks unintended consequences as a failed delegatecall is not accounted for by the caller.
      @author: Hexens team
      @tags: call patterns
      @references: https://swcregistry.io/docs/SWC-112/, https://coinsbench.com/common-vulnerabilities-unchecked-external-calls-7eea119138b2
    """

    return (
        Instructions()
        .delegate_calls_non_assembly()
        .exec()  # CHANGEME: 1000
        # delegateCallAndRevert is a common function used to handle delegatecall reverts. We ignore these functions.
        .filter(lambda instruction: instruction.get_parent().name != "delegateCallAndRevert")
        # Simulation functions (a function that always reverts) are filtered out
        .filter(not_simulation_functions)
        .filter(missing_call_success_validations)
    )




# This function checks if the instruction's function is a simulation function that always results in a revert.
def not_simulation_functions(instruction):
    return len(
        instruction
        .forward_df_recursive()
        .filter(lambda point : isinstance(point, Instruction))
        .filter(revert_instruction)
     ) == 0




# This function checks if the delegatecall success is not validated.
def missing_call_success_validations(instruction):
    if validates_success(instruction):
        return False


    # IMPROVEMENT: There is an issue with this query. Currently extended_forward_df() does not include assembly instructions.
    #              Many delegatecall success variables are validated via assembly. Therefore, we will experience a large number of
    #              false positives in this query. Once this Glider is bug is fixed, we can update this query to handle cases
    #              where the success variable is validated via assembly.


    dest = instruction.get_dest()


    # For some Kovan contracts, the return value is just the success variable due to how delegatecall in Solidity <0.5 returned just the success variable. 
    if isinstance(dest, VarValue):
        success_var = instruction.get_dest()
    else:
        # dest represents a TupleExpression
        success_var = instruction.get_dest().get_component(0).get_vars()
 
    instructions_interacting_with_success_var = (
        success_var
        .forward_df_recursive()
        .filter(lambda point : isinstance(point, Instruction))
        .filter(validates_success)
    )
    # If the success variable is validated, then the delegatecall is properly handled and we can exclude it from the results.
    return len(instructions_interacting_with_success_var) == 0




# This function checks if the instruction validates the success variable.
def validates_success(instruction):
    return (
        calls_validation_function(instruction) or
        contains_guard_check(instruction)
    )




# This function checks if the instruction calls another function to validate success.
def calls_validation_function(instruction):
    # These are common functions used to validate a call result sourced from OpenZeppelin's Address library.
    validating_functions = [
        "verifyCallResult",
        "verifyCallResultFromTarget",
        "_verifyCallResult"
    ]


    return any(func in instruction.callee_names() for func in validating_functions)




# Checks if a given object is None.
def is_none(obj):
    return obj is None or isinstance(obj, NoneObject)




# This function checks if a given instruction can lead to a potential revert.
def contains_guard_check(instruction):
    return (
        contains_potential_revert(instruction) or
        contains_if_guard_check(instruction)
    )




# This function checks if the instruction contains any potential reverts
def contains_potential_revert(instruction):
    return (
        "require" in instruction.callee_names() or
        "assert" in instruction.callee_names() or
        revert_instruction(instruction)
    )




# This function checks if a given instruction is a revert instruction.
def revert_instruction(instruction):
    return "revert" in instruction.builtin_callee_names()




# This function checks if a given instruction applies an if statement with a revert in either control flow branch.
def contains_if_guard_check(instruction):
    return (
        instruction.is_if() and
        if_blocks_contain_potential_revert(instruction)
    )




# This function checks if any instructions inside of the if blocks contain assertion checks.
def if_blocks_contain_potential_revert(if_instruction):
    return (
        len(if_instruction.first_true_instruction().next_instructions().filter(revert_instruction)) > 0 or
        len(if_instruction.first_false_instruction().next_instructions().filter(revert_instruction)) > 0 or
        revert_instruction(if_instruction.first_true_instruction()) or
        revert_instruction(if_instruction.first_false_instruction())
    )