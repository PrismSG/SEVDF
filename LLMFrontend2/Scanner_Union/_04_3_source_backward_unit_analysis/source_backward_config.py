# Source-side backward reasoning for Scanner-Union Logic Units.

from typing import Dict, Any
import logging
import textwrap
from colorama import Fore
from datetime import datetime
from BaseMachine.state_machine import StateMachine
from BaseMachine.action_utils import create_chat_action, create_new_chat_action, create_chat_action_with_tools
from BaseMachine.model_config import get_model_name
import json

from .source_backward_context import SourceBackwardFlowContext, Step, Point, InlineCondition, FeasibilityResult
from .source_backward_tools import (
    extract_constraints_for_backward_flow,
    analyze_flow_path,
    format_flow_summary,
    extract_and_set_constraints
)
from ..utils.semantic_label_utils import format_variable_for_narrative

# Helper functions moved to source_backward_tools.py

# Define actions
def init_context_action(machine):
    """handle the context"""
    return None

def process_config_action(machine) -> None:
    """1. handle the config"""
    source_backward_config = machine.cwe_cot_config['source_backward']
    
    machine.source_backward_config = {
        'backward_behavior_desc': source_backward_config.get('backward_behavior_desc', 'default behavior description'),
        'backward_behavior_rules': source_backward_config.get('backward_behavior_rules', []),
        'purpose_desc': source_backward_config.get('purpose_desc', 'default purpose description'),
        'purpose_rules': source_backward_config.get('purpose_rules', [])
    }

    # Collect context variables
    machine.outer_backward_behavior_variable = machine.context.steps[-1].toPoint.variable
    machine.outer_backward_behavior_function_name = machine.context.steps[-1].toPoint.functionName
    machine.outer_backward_behavior_line_code = machine.context.steps[-1].toPoint.lineCode
    machine.outer_backward_behavior_line_number = machine.context.steps[-1].toPoint.line

    machine.outer_backward_semantic_label = getattr(machine.context.steps[-1].toPoint, 'semanticLabel', None)

    """2. format the config"""
    machine.shared_variables = {
        'outer_backward_behavior_variable': machine.outer_backward_behavior_variable,
        'outer_backward_behavior_function_name': machine.outer_backward_behavior_function_name,
        'outer_backward_behavior_line_code': machine.outer_backward_behavior_line_code,
        'outer_backward_behavior_line_number': machine.outer_backward_behavior_line_number,
        'outer_backward_semantic_label': machine.outer_backward_semantic_label or machine.outer_backward_behavior_variable
    }
    
    # Format all content that needs to be formatted
    machine.formatted_backward_behavior_desc = str(
        machine.source_backward_config['backward_behavior_desc']
    ).format(**machine.shared_variables)
    
    machine.formatted_rules = '\n'.join([
        f'{i+1}. {rule.format(**machine.shared_variables)}' 
        for i, rule in enumerate(machine.source_backward_config['backward_behavior_rules'])
    ])
    
    machine.formatted_purpose_desc = str(
        machine.source_backward_config['purpose_desc']
    ).format(**machine.shared_variables)
    
    # Handle both old format (string) and new format (object with title and rule)
    formatted_rules = []
    for i, item in enumerate(machine.source_backward_config['purpose_rules']):
        if isinstance(item, dict):
            # New format with title and rule
            title = item['title']
            rule = item['rule'].format(**machine.shared_variables)
            formatted_rules.append(f'{i+1}. **{title}**: {rule}')
        else:
            # Old format - just a string
            formatted_rules.append(f'{i+1}. {item.format(**machine.shared_variables)}')
    
    machine.formatted_purpose_rules = '\n'.join(formatted_rules)

    return None

def fill_behavior_details_action(machine) -> None:

    machine.outer_backward_behavior_line_code = machine.context.steps[-1].toPoint.lineCode
    machine.outer_backward_behavior_line_number = machine.context.steps[-1].toPoint.line
    machine.outer_backward_behavior_function_name = machine.context.steps[-1].toPoint.functionName
    machine.outer_backward_behavior_variable = machine.context.steps[-1].toPoint.variable
    
    machine.call_chain = ''
    machine.all_related_code = ''
    
    # If there are no steps, add default information
    if not machine.context.steps:
        machine.call_chain = 'No steps in data flow'
        machine.all_related_code = f'No related code available'
        return None
    
    # Track added code snippets to avoid duplication
    added_code_segments = set()
    
    # Draw the call chain, using the steps_relationships dictionary
    index = 0
    for step in reversed(machine.context.steps):
        if step.toPoint.relatedCode == step.fromPoint.relatedCode:
            continue
            
        # Get relationship type from steps_relationships dictionary
        step_key = (step.fromPoint.file, step.fromPoint.line,
                    step.toPoint.file, step.toPoint.line, step.flowstep)
        steps_relationships = getattr(machine.context, 'steps_relationships', {})
        relation = steps_relationships.get(step_key, "NULL")
        relation_desc = ""
        
        # opposite of the forward analysis
        if relation == "RETURN":
            relation_desc = "called"
        elif relation == "CALL":
            relation_desc = "returned to"
        else:
            relation_desc = "propagated to"
            
        tabs = '\t' * index
        if index == 0:
            machine.call_chain += f'{tabs}{step.toPoint.functionName} -> {step.fromPoint.functionName} // {step.toPoint.functionName} {relation_desc} {step.fromPoint.functionName}\n'
            
            # Only add code when the code snippet is encountered for the first time
            if step.toPoint.relatedCode not in added_code_segments:
                added_code_segments.add(step.toPoint.relatedCode)
                machine.all_related_code += f'// Code in function {step.toPoint.functionName}\n{tabs}{step.toPoint.relatedCode}\n\n'
            
            if step.fromPoint.relatedCode not in added_code_segments:
                added_code_segments.add(step.fromPoint.relatedCode)
                machine.all_related_code += f'// Code in function {step.fromPoint.functionName}\n{tabs}{step.fromPoint.relatedCode}\n\n'
        else:
            machine.call_chain += f'{tabs}{step.toPoint.functionName} -> {step.fromPoint.functionName} // then {step.toPoint.functionName} {relation_desc} {step.fromPoint.functionName}\n'
            
            # Only add code when the code snippet is encountered for the first time
            if step.fromPoint.relatedCode not in added_code_segments:
                added_code_segments.add(step.fromPoint.relatedCode)
                machine.all_related_code += f'// Code in function {step.fromPoint.functionName}\n{tabs}{step.fromPoint.relatedCode}\n\n'
        
        index += 1
    
    # Ensure all_related_code is not empty
    if not machine.all_related_code.strip():
        # If no code has been added (perhaps because all steps are in the same function or there is only one step)
        # Add the toPoint code of the first step and the fromPoint code of the last step
        if machine.context.steps:
            first_step = machine.context.steps[0]
            last_step = machine.context.steps[-1]
            
            machine.all_related_code = f"// Last point (in {last_step.toPoint.functionName})\n"
            machine.all_related_code += f"{last_step.toPoint.relatedCode}\n\n"
            
            # If the first point is different from the last point, add it as well
            if first_step.fromPoint.relatedCode != last_step.toPoint.relatedCode:
                machine.all_related_code += f"// First point (in {first_step.fromPoint.functionName})\n"
                machine.all_related_code += f"{first_step.fromPoint.relatedCode}\n"
    
    # Construct a full prompt with the call chain from the last steps to the first steps with related code
    call_chain_section = ''
    if machine.call_chain.strip():
        call_chain_section = f"""
The call chain of this line is as follows:

{machine.call_chain}
"""

    backward_behavior_details = f"""
This line in `{machine.outer_backward_behavior_function_name}` is a {machine.formatted_backward_behavior_desc}:
```
Line {machine.outer_backward_behavior_line_number}:{machine.outer_backward_behavior_line_code}
```
{call_chain_section}
In detail, the DataFlow is as follows:

"""
    # Convert steps to list for easier handling
    steps = list(reversed(machine.context.steps))

    # Detect virtual single-point steps (created by virtual_step_enrichment when
    # no real backward segment exists).  Virtual steps have fromPoint == toPoint.
    _is_all_virtual = (
        len(steps) == 1
        and steps[0].fromPoint.file == steps[0].toPoint.file
        and steps[0].fromPoint.line == steps[0].toPoint.line
    )
    if _is_all_virtual:
        vpt = steps[0].fromPoint
        backward_behavior_details += f"""This is the origin point of the data flow. No backward propagation path exists — the analysis begins directly at this point in `{vpt.functionName}` at line {vpt.line}:
```
Line {vpt.line}:{vpt.lineCode}
```
"""
        # Append variant details if this unit has propagation variants
        from ..utils.variant_description import build_variant_behavior_section
        variant_section = build_variant_behavior_section(
            getattr(machine, 'variant_details', None), 'backward')
        if variant_section:
            backward_behavior_details += variant_section

        machine.backward_behavior_details = backward_behavior_details
        logging.debug(Fore.BLUE + f'[BACKWARD] Behavior (virtual): {machine.backward_behavior_details}')
        extract_and_set_constraints(machine)
        return None

    # Track continuous code segments
    current_segment_start = 0
    in_continuous_segment = False
    prefix = "First"

    # Process each step
    for i, step in enumerate(steps):
        to_function = step.toPoint.functionName
        from_function = step.fromPoint.functionName
        to_variable = format_variable_for_narrative(step.toPoint)
        
        # Get relationship type from steps_relationships dictionary
        step_key = (step.fromPoint.file, step.fromPoint.line,
                    step.toPoint.file, step.toPoint.line, step.flowstep)
        steps_relationships = getattr(machine.context, 'steps_relationships', {})
        relation = steps_relationships.get(step_key, "NULL")

        # Check if this is a parameter passing (identical code) step
        is_identical_code = step.toPoint.relatedCode == step.fromPoint.relatedCode
        
        # Start of a new continuous segment of identical code
        if is_identical_code and not in_continuous_segment:
            current_segment_start = i
            in_continuous_segment = True
            
            # For the first step in a continuous segment, it's parameter passing
            # have the possibility to be not started from parameter passing.
            backward_behavior_details += f"""
{prefix} in `{to_function}` line {step.toPoint.line}, {to_variable} is propagated within the same function (SAME function relationship). This is an internal data flow where the variable moves from one point to another in function `{to_function}`, reaching line {step.fromPoint.line}:
```
Line {step.fromPoint.line}:{step.fromPoint.lineCode}
```
"""
        
        # Continuation of a continuous segment
        elif is_identical_code and in_continuous_segment:
            # This is a propagation within the segment
            backward_behavior_details += f"""
{prefix} in `{to_function}` line {step.toPoint.line}, {to_variable} continues its propagation path within the same function (SAME function relationship). The data flow remains in function `{to_function}`, moving to line {step.fromPoint.line}:
```
Line {step.fromPoint.line}:{step.fromPoint.lineCode}
```
"""
        
        # End of a continuous segment, or not in a segment
        elif not is_identical_code:
            in_continuous_segment = False

            # Add an assertion: when the two pieces of code are different, the relation must be CALL or RETURN
            assert relation in ["CALL", "RETURN"], f"When code segments differ, relation must be CALL or RETURN, got {relation}"

            # Generate different description statements according to the relation type
            if relation == "RETURN": # since its backward, so it must be return
                # Call relationship: the current function calls another function
                backward_behavior_details += f"""
{prefix} in `{to_function}` line {step.toPoint.line}, {to_variable} is passed as a parameter from caller `{to_function}` to callee `{from_function}` (CALL relationship). The variable is then used at line {step.fromPoint.line} in `{from_function}`: 
```
Line {step.fromPoint.line}:{step.fromPoint.lineCode}
``` 
"""
            else:  # relation must be "RETURN"
                # Return relationship: return from the called function to the calling function
                backward_behavior_details += f"""
{prefix} in `{to_function}` line {step.toPoint.line}, {to_variable} is returned from callee `{to_function}` back to caller `{from_function}` (RETURN relationship). The returned value is received at line {step.fromPoint.line} in `{from_function}`: 
```
Line {step.fromPoint.line}:{step.fromPoint.lineCode}
``` 
"""
        
        prefix = "then"
    
    # Append variant details if this unit has propagation variants
    from ..utils.variant_description import build_variant_behavior_section
    variant_section = build_variant_behavior_section(
        getattr(machine, 'variant_details', None), 'backward')
    if variant_section:
        backward_behavior_details += variant_section

    machine.backward_behavior_details = backward_behavior_details

    logging.debug(Fore.BLUE + f'[BACKWARD] Behavior of {machine.formatted_backward_behavior_desc} : {machine.backward_behavior_details}')

    # Extract constraints
    extract_and_set_constraints(machine)

    return None

def one_step_action(machine):

    machine.messages = [
        {
            "role": "system",
            "content": f'You are a C/C++ static analysis expert in analyzing {machine.formatted_backward_behavior_desc}',
        }
    ]

    # Define expected fields for the JSON response
    # Note: We do NOT ask for false positive determination here because
    # source backward analysis alone doesn't have enough context.
    # False positive determination should be done at a higher level
    # after combining multiple analyses.
    expected_fields = [
        'reachability',  # "REACHABLE" or "UNREACHABLE"
        'reachability_explanation',
        'required_conditions',
        'reachability_confidence',
        'rule_checks',
        'overall_assessment'
    ]
    
    # Create the action function (but don't call it yet)
    analysis_action = create_chat_action_with_tools(
        prompt_template=textwrap.dedent('''
            You are analyzing {backward_behavior_desc}.
            {call_chain_header}
            Detailed flow:
            {backward_behavior_details}

            {constraint_section}

            Analyze this vulnerability and provide a structured JSON response.

            Rules to check for reachability:
            {rules}

            Purpose and rules for false positive detection:
            {purpose_desc}

            Checklist for detailed analysis:
            {purpose}

            IMPORTANT: You MUST check ALL {num_rules} rules above and include each one in the rule_checks array. Use the exact rule title (e.g., "Verify Exact Pointer Identity", "Check Post-Free Nullification", etc.) as the rule_text field.

            Related code:
            {all_related_code}

            {macro_section}

            CRITICAL: Follow the JSON structure EXACTLY as specified. Do NOT create new fields or nest objects.
        ''').strip(),
        save_option='both',
        # model_name='qwq-32b',
        model_name=get_model_name(),
        # model_name='qwq-32b',
        debug=True,
        expected_fields=expected_fields,
        purpose_rules=machine.source_backward_config['purpose_rules'],
        context_label='SourceBackward'
    )

    # Prepare constraint section (independent)
    constraint_section = ""
    if hasattr(machine, 'constraint_text_for_prompt') and machine.constraint_text_for_prompt:
        constraint_section = machine.constraint_text_for_prompt

    # Prepare macro section (independent, preloaded via use-def)
    macro_section = ""
    if hasattr(machine, 'macro_text_for_prompt') and machine.macro_text_for_prompt:
        macro_section = machine.macro_text_for_prompt

    # Now call the action with the machine and parameters
    one_step_analysis = analysis_action(machine,
        rules=machine.formatted_rules,
        backward_behavior_desc=machine.formatted_backward_behavior_desc,
        backward_behavior_details=machine.backward_behavior_details,
        outer_backward_behavior_function_name=machine.outer_backward_behavior_function_name,
        call_chain_header=f"\nCall chain to analyze:\n{machine.call_chain}\n" if machine.call_chain.strip() else "",
        purpose_desc=machine.formatted_purpose_desc,
        purpose=machine.formatted_purpose_rules,
        all_related_code=machine.all_related_code,
        constraint_section=constraint_section,
        macro_section=macro_section,
        num_rules=len(machine.source_backward_config['purpose_rules']))
    
    machine.one_step_analysis = one_step_analysis
    logging.debug(Fore.BLUE + f'[BACKWARD] One Step Analysis (JSON): {json.dumps(one_step_analysis, indent=2)}')
    pass

def summary_action(machine):
    # Extract structured data from the JSON response
    from .source_backward_context import DetailedAnalysisResult, RuleCheckResult
    
    # The one_step_analysis is now a JSON object with all fields
    json_result = machine.one_step_analysis
    
    # Validate required fields exist
    required_fields = ['reachability', 'reachability_explanation', 'required_conditions', 'rule_checks']
    missing_fields = [field for field in required_fields if field not in json_result]
    if missing_fields:
        logging.warning(f"Missing required fields in JSON response: {missing_fields}")
    
    # Debug log for overall_assessment
    if 'overall_assessment' in json_result:
        logging.debug(f"overall_assessment type: {type(json_result['overall_assessment'])}, value: {json_result['overall_assessment']}")
    
    # Ensure overall_assessment is a string or None
    overall_assessment_value = json_result.get('overall_assessment')
    if isinstance(overall_assessment_value, list):
        # If it's a list, join the items into a single string
        logging.warning(f"overall_assessment is a list, converting to string: {overall_assessment_value}")
        overall_assessment_value = ' '.join(str(item) for item in overall_assessment_value)
    elif overall_assessment_value is not None and not isinstance(overall_assessment_value, str):
        # For other non-string types (except None), convert to string
        logging.warning(f"overall_assessment is not a string: type={type(overall_assessment_value)}, value={overall_assessment_value}")
        overall_assessment_value = str(overall_assessment_value)
    
    # Create DetailedAnalysisResult from the JSON fields
    # Note: We do NOT ask for false positive determination here because this analysis alone
    # doesn't have enough context to make that determination
    detailed_summary = DetailedAnalysisResult(
        feasibility=(json_result.get('reachability', 'UNREACHABLE') == 'REACHABLE'),
        feasibility_reason=json_result.get('reachability_explanation', 'No explanation provided'),
        required_conditions_code=json_result.get('required_conditions', []),
        purpose_rule_checks=[
            RuleCheckResult(
                rule_text=rule.get('rule_text', ''),
                check_result=rule.get('findings', ''),
                code_references=[rule.get('what_checked', '')]
            ) for rule in json_result.get('rule_checks', [])
        ],
        overall_assessment=overall_assessment_value,
        # Don't set false positive fields - let higher level analysis decide
        is_false_positive=None,  # Will be determined by higher-level analysis
        false_positive_confidence=None  # Will be determined by higher-level analysis
    )
    
    machine.detailed_summary = detailed_summary
    # No need for separate summary - detailed_summary already has all fields
    machine.raw_result = json.dumps(json_result)
    
    # Store rule checks and false positive assessment directly on machine for later access
    machine.backward_rule_checks = getattr(detailed_summary, 'purpose_rule_checks', [])
    machine.backward_false_positive = getattr(detailed_summary, 'is_false_positive', None)
    machine.backward_false_positive_confidence = getattr(detailed_summary, 'false_positive_confidence', None)
    
    logging.debug(Fore.GREEN + f'[BACKWARD] Detailed Summary: {detailed_summary}')
    pass

def exit_action(_machine):
    logging.info(Fore.GREEN + '[BACKWARD] Exiting source backward subpath analysis.')
    return None

# Define state machine configurations for source backward subpath analysis
state_definitions = {
    'InitContext': {
        'action': init_context_action,
        'next_state_func': lambda _result, _machine: 'ProcessConfig',
    },
    'ProcessConfig': {
        'action': process_config_action,
        'next_state_func': lambda _result, _machine: 'FillBehaviorDetails',
    },
    'FillBehaviorDetails': {
        'action': fill_behavior_details_action,
        'next_state_func': lambda _result, _machine: 'OneStepAnalysis',
    },
    'OneStepAnalysis': {
        'action': one_step_action,
        'next_state_func': lambda _result, _machine: 'Summary',
    },
    'Summary': {
        'action': summary_action,
        'next_state_func': lambda _result, _machine: 'Exit',
    },
    'Exit': {
        'action': exit_action,
        'next_state_func': None,
    },
}
