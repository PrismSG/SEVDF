from typing import Dict, Any
import logging
import textwrap
from colorama import Fore
from datetime import datetime
from BaseMachine.state_machine import StateMachine
from BaseMachine.action_utils import create_chat_action, create_new_chat_action, create_chat_action_with_tools
from BaseMachine.model_config import get_model_name
import json

from .forward_to_sink_context import ForwardToSinkFlowContext, Step, Point, InlineCondition, FeasibilityResult
from ..utils.semantic_label_utils import format_variable_for_narrative

def init_context_action(machine):
    """handle the context"""

def process_config_action(machine):
    """1. handle the config"""
    forward_to_sink_config = machine.cwe_cot_config['forward_to_sink']
    machine.forward_to_sink_config = {
        'forward_behavior_desc': forward_to_sink_config.get('forward_behavior_desc', 'default behavior'),
        'forward_behavior_rules': forward_to_sink_config.get('forward_behavior_rules', []),
        'purpose_desc': forward_to_sink_config.get('purpose_desc', 'default purpose'),
        'purpose_rules': forward_to_sink_config.get('purpose_rules', [])
    }
    
    # collect the context variables
    # LCA call point – where the forward analysis starts
    machine.outer_forward_behavior_line_code = machine.context.steps[0].fromPoint.lineCode
    machine.outer_forward_behavior_line_number = machine.context.steps[0].fromPoint.line
    machine.outer_forward_behavior_function_name = machine.context.steps[0].fromPoint.functionName
    machine.outer_forward_behavior_variable = machine.context.steps[0].fromPoint.variable
    machine.outer_forward_semantic_label = getattr(machine.context.steps[0].fromPoint, 'semanticLabel', None)

    # Sink point – the actual endpoint of forward analysis
    sink = machine.context.steps[-1].toPoint
    machine.sink_line_code = sink.lineCode
    machine.sink_line_number = sink.line
    machine.sink_function_name = sink.functionName
    machine.sink_variable = sink.variable
    machine.last_visit_code = sink.lineCode

    """2. format the config"""
    machine.shared_variables = {
        'last_visit_code': machine.last_visit_code.replace('{', '{').replace('}', '}}'),
        'outer_forward_behavior_variable': machine.outer_forward_behavior_variable,
        'outer_forward_behavior_function_name': machine.outer_forward_behavior_function_name,
        'outer_forward_behavior_line_code': machine.outer_forward_behavior_line_code,
        'outer_forward_behavior_line_number': machine.outer_forward_behavior_line_number,
        'outer_forward_semantic_label': machine.outer_forward_semantic_label or machine.outer_forward_behavior_variable,
        'sink_line_code': machine.sink_line_code,
        'sink_line_number': machine.sink_line_number,
        'sink_function_name': machine.sink_function_name,
        'sink_variable': machine.sink_variable,
    }
    
    # Format all content that needs to be formatted
    machine.formatted_forward_behavior_desc = str(
        machine.forward_to_sink_config['forward_behavior_desc']
    ).format(**machine.shared_variables)
    
    machine.formatted_rules = '\n'.join([
        f'{i+1}. {rule.format(**machine.shared_variables)}' 
        for i, rule in enumerate(machine.forward_to_sink_config['forward_behavior_rules'])
    ])
    
    machine.formatted_purpose_desc = str(
        machine.forward_to_sink_config['purpose_desc']
    ).format(**machine.shared_variables)
    
    # Handle both old format (string) and new format (object with title and rule)
    formatted_rules = []
    for i, item in enumerate(machine.forward_to_sink_config['purpose_rules']):
        if isinstance(item, dict):
            # New format with title and rule
            title = item['title']
            rule = item['rule'].format(**machine.shared_variables)
            formatted_rules.append(f'{i+1}. **{title}**: {rule}')
        else:
            # Old format - just a string
            formatted_rules.append(f'{i+1}. {item.format(**machine.shared_variables)}')
    
    machine.formatted_purpose_rules = '\n'.join(formatted_rules)

def fill_behavior_details_action(machine):
    # Now use the formatted configuration
    forward_behavior_desc = machine.formatted_forward_behavior_desc

    # LCA call point (forward analysis start)
    machine.outer_forward_behavior_line_code = machine.context.steps[0].fromPoint.lineCode
    machine.outer_forward_behavior_line_number = machine.context.steps[0].fromPoint.line
    machine.outer_forward_behavior_function_name = machine.context.steps[0].fromPoint.functionName
    machine.outer_forward_behavior_variable = machine.context.steps[0].fromPoint.variable

    # Sink point (forward analysis end)
    sink = machine.context.steps[-1].toPoint
    machine.sink_line_code = sink.lineCode
    machine.sink_line_number = sink.line
    machine.sink_function_name = sink.functionName
    machine.sink_variable = sink.variable
    
    # Extract constraints for forward flow
    try:
        from .forward_to_sink_tools import analyze_forward_flow_with_constraints
        analyze_forward_flow_with_constraints(machine)
    except Exception as e:
        logging.warning(f"Failed to extract constraints for forward flow: {e}")
    
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
    for step in machine.context.steps:
        if step.toPoint.relatedCode == step.fromPoint.relatedCode:
            continue
            
        # Get relationship type from steps_relationships dictionary
        step_key = (step.fromPoint.file, step.fromPoint.line,
                    step.toPoint.file, step.toPoint.line, step.flowstep)
        steps_relationships = getattr(machine.context, 'steps_relationships', {})
        relation = steps_relationships.get(step_key, "NULL")
        relation_desc = ""

        if relation == "CALL":
            relation_desc = "called"
        elif relation == "RETURN":
            relation_desc = "returned to"
        else:
            relation_desc = "propagated to"

        tabs = '\t' * index
        if index == 0:
            machine.call_chain += f'{tabs}{step.fromPoint.functionName} -> {step.toPoint.functionName} // {step.fromPoint.functionName} {relation_desc} {step.toPoint.functionName} [{relation}]\n'
            
            # Only add code when the code snippet is encountered for the first time
            if step.fromPoint.relatedCode not in added_code_segments:
                added_code_segments.add(step.fromPoint.relatedCode)
                machine.all_related_code += f'// Code in function {step.fromPoint.functionName}\n{tabs}{step.fromPoint.relatedCode}\n\n'
            
            if step.toPoint.relatedCode not in added_code_segments:
                added_code_segments.add(step.toPoint.relatedCode)
                machine.all_related_code += f'// Code in function {step.toPoint.functionName}\n{tabs}{step.toPoint.relatedCode}\n\n'
        else:
            machine.call_chain += f'{tabs}{step.fromPoint.functionName} -> {step.toPoint.functionName} // then {step.fromPoint.functionName} {relation_desc} {step.toPoint.functionName} [{relation}]\n'
            
            # Only add code when the code snippet is encountered for the first time
            if step.toPoint.relatedCode not in added_code_segments:
                added_code_segments.add(step.toPoint.relatedCode)
                machine.all_related_code += f'// Code in function {step.toPoint.functionName}\n{tabs}{step.toPoint.relatedCode}\n\n'
        index += 1
    
    # Ensure all_related_code is not empty
    if not machine.all_related_code.strip():
        # If no code has been added (perhaps because all steps are in the same function or there is only one step)
        # Add the fromPoint code of the first step and the toPoint code of the last step
        if machine.context.steps:
            first_step = machine.context.steps[0]
            last_step = machine.context.steps[-1]
            
            machine.all_related_code = f"// First point (in {first_step.fromPoint.functionName})\n"
            machine.all_related_code += f"{first_step.fromPoint.relatedCode}\n\n"
            
            # If the last point is different from the first point, add it as well
            if last_step.toPoint.relatedCode != first_step.fromPoint.relatedCode:
                machine.all_related_code += f"// Last point (in {last_step.toPoint.functionName})\n"
                machine.all_related_code += f"{last_step.toPoint.relatedCode}\n"
    
    call_chain_section = ''
    if machine.call_chain.strip():
        call_chain_section = f"""
The call chain of this line is as follows:

{machine.call_chain}
"""

    # Determine whether the LCA call point differs from the sink point.
    # When they differ, the header should describe both so the LLM knows the
    # analysis scope (LCA -> sink) instead of mislabelling the LCA entry as
    # the sink operation.
    _lca_is_sink = (
        machine.outer_forward_behavior_function_name == machine.sink_function_name
        and machine.outer_forward_behavior_line_number == machine.sink_line_number
    )

    if _lca_is_sink:
        # Single-point or same-function: the call point IS the sink
        forward_behavior_details = f"""
This line in `{machine.outer_forward_behavior_function_name}` is a {forward_behavior_desc}:
```
Line {machine.outer_forward_behavior_line_number}:{machine.outer_forward_behavior_line_code}
```
{call_chain_section}
In detail, the DataFlow is as follows:

"""
    else:
        # Cross-function: LCA call point is the analysis start, sink is at the end
        forward_behavior_details = f"""
Analyze the forward call chain from `{machine.outer_forward_behavior_function_name}` to the sink ({forward_behavior_desc}).

Starting point (in `{machine.outer_forward_behavior_function_name}`):
```
Line {machine.outer_forward_behavior_line_number}:{machine.outer_forward_behavior_line_code}
```

Sink point — {forward_behavior_desc} (in `{machine.sink_function_name}`):
```
Line {machine.sink_line_number}:{machine.sink_line_code}
```
{call_chain_section}
In detail, the DataFlow is as follows:

"""
    # Convert steps to list for easier handling
    steps = machine.context.steps

    # Detect virtual single-point steps (created by virtual_step_enrichment when
    # no real forward segment exists).  Virtual steps have fromPoint == toPoint.
    _is_all_virtual = (
        len(steps) == 1
        and steps[0].fromPoint.file == steps[0].toPoint.file
        and steps[0].fromPoint.line == steps[0].toPoint.line
    )
    if _is_all_virtual:
        vpt = steps[0].fromPoint
        forward_behavior_details += f"""This is the endpoint of the data flow. No forward propagation path exists — the analysis ends directly at this point in `{vpt.functionName}` at line {vpt.line}:
```
Line {vpt.line}:{vpt.lineCode}
```
"""
        # Append variant details if this unit has propagation variants
        from ..utils.variant_description import build_variant_behavior_section
        variant_section = build_variant_behavior_section(
            getattr(machine, 'variant_details', None), 'forward')
        if variant_section:
            forward_behavior_details += variant_section

        machine.forward_behavior_details = forward_behavior_details
        logging.debug(Fore.BLUE + f'[FORWARD] Behavior (virtual): {forward_behavior_details}')
        return None

    # Track continuous code segments
    current_segment_start = 0
    in_continuous_segment = False
    prefix = "First"

    # Process each step
    for i, step in enumerate(steps):
        from_function = step.fromPoint.functionName
        to_function = step.toPoint.functionName
        from_variable = format_variable_for_narrative(step.fromPoint)
        
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
            forward_behavior_details += f"""{prefix} in `{from_function}` line {step.fromPoint.line}, {from_variable} is propagated within the same function (SAME relationship). This is an internal data flow where the variable moves from one point to another in function `{from_function}`, reaching line {step.toPoint.line}:
```
Line {step.toPoint.line}:{step.toPoint.lineCode}
```
"""
        
        # Continuation of a continuous segment
        elif is_identical_code and in_continuous_segment:
            # This is a propagation within the segment
            forward_behavior_details += f"""{prefix} in `{from_function}` line {step.fromPoint.line}, {from_variable} continues its propagation path within the same function (SAME relationship). The data flow remains in function `{from_function}`, moving to line {step.toPoint.line}:
```
Line {step.toPoint.line}:{step.toPoint.lineCode}
```
"""
        
        # End of a continuous segment, or not in a segment
        elif not is_identical_code:
            in_continuous_segment = False

            # Add an assertion: when the two pieces of code are different, the relation must be CALL or RETURN
            assert relation in ["CALL", "RETURN"], f"When code segments differ, relation must be CALL or RETURN, got {relation}"

            # Generate different description statements according to the relation type
            if relation == "CALL":
                # Call relationship: the current function calls another function
                forward_behavior_details += f"""{prefix} in `{from_function}` line {step.fromPoint.line}, {from_variable} is passed as a parameter from caller `{from_function}` to callee `{to_function}` (CALL relationship). The variable is then used at line {step.toPoint.line} in `{to_function}`: 
```
Line {step.toPoint.line}:{step.toPoint.lineCode}
``` 
"""
            else:  # relation must be "RETURN"
                # Return relationship: return from the called function to the calling function
                forward_behavior_details += f"""{prefix} in `{from_function}` line {step.fromPoint.line}, {from_variable} is returned from callee `{from_function}` back to caller `{to_function}` (RETURN relationship). The returned value is received at line {step.toPoint.line} in `{to_function}`: 
```
Line {step.toPoint.line}:{step.toPoint.lineCode}
``` 
"""
        
        prefix = "then"
    
    # Append variant details if this unit has propagation variants
    from ..utils.variant_description import build_variant_behavior_section
    variant_section = build_variant_behavior_section(
        getattr(machine, 'variant_details', None), 'forward')
    if variant_section:
        forward_behavior_details += variant_section

    machine.forward_behavior_details = forward_behavior_details

    logging.debug(Fore.BLUE + f'[FORWARD] Behavior of {forward_behavior_desc}: {forward_behavior_details}')
    return None

def one_step_analysis_action(machine):

    forward_behavior_desc = machine.formatted_forward_behavior_desc
    machine.messages = [
        {
            "role": "system",
            "content": f'You are a C/C++ static analysis expert in analyzing {forward_behavior_desc}',
        }
    ]

    # Define expected fields for the JSON response
    # Note: We do NOT ask for false positive determination here because
    # forward-to-sink analysis only sees a segment of the path.
    # False positive determination should be done by intermediate transition
    # analysis which has the complete path view.
    expected_fields = [
        'reachability',  # "REACHABLE" or "UNREACHABLE"
        'reachability_explanation',
        'required_conditions',
        'reachability_confidence',
        'rule_checks',
        'overall_assessment'
    ]
    
    # Prepare constraint section (independent)
    constraint_section = ""
    if hasattr(machine, 'constraint_text_for_prompt') and machine.constraint_text_for_prompt:
        constraint_section = machine.constraint_text_for_prompt

    # Prepare macro section (independent, preloaded via use-def)
    macro_section = ""
    if hasattr(machine, 'macro_text_for_prompt') and machine.macro_text_for_prompt:
        macro_section = machine.macro_text_for_prompt

    prompt_template = textwrap.dedent('''
        You are analyzing {forward_behavior_desc}.

        {forward_behavior_details}

        {constraint_section}

        Analyze this vulnerability and provide a structured JSON response.

        {call_chain_header}
        Rules to check for reachability:
        {rules}

        Purpose and rules for false positive detection:
        {purpose_desc}

        Checklist for detailed analysis:
        {purpose_rules}

        IMPORTANT: You MUST check ALL {num_rules} rules above and include each one in the rule_checks array. Use the exact rule title (e.g., "Trace Final Dereference", "Validate Security Check Presence", etc.) as the rule_text field.

        Related code:
        {all_related_code}

        {macro_section}

        CRITICAL: Follow the JSON structure EXACTLY as specified. Do NOT create new fields or nest objects.
    ''').strip()

    one_step_analysis = create_chat_action_with_tools(
        prompt_template=prompt_template,
        save_option='both',
        # model_name='deepseek-r1',
        # model_name='qwq-32b',
        # model_name='qwq-32b',
        model_name=get_model_name(),
        debug=True,
        expected_fields=expected_fields,
        purpose_rules=machine.forward_to_sink_config['purpose_rules'],
        context_label='ForwardToSink'
    )(machine,
      forward_behavior_desc=machine.formatted_forward_behavior_desc,
      forward_behavior_details=machine.forward_behavior_details,
      call_chain_header=f"\nThe call chain is as follows:\n{machine.call_chain}\n" if machine.call_chain.strip() else "",
      all_related_code=machine.all_related_code,
      rules=machine.formatted_rules,
      purpose_desc=machine.formatted_purpose_desc,
      purpose_rules=machine.formatted_purpose_rules,
      constraint_section=constraint_section,
      macro_section=macro_section,
      num_rules=len(machine.forward_to_sink_config['purpose_rules'])
    )
    machine.one_step_analysis = one_step_analysis
    logging.debug(Fore.BLUE + f'[FORWARD] One Step Analysis (JSON): {json.dumps(one_step_analysis, indent=2)}')

def summary_action(machine):
    # Extract structured data from the JSON response
    from .forward_to_sink_context import DetailedAnalysisResult, RuleCheckResult
    
    # The one_step_analysis is now a JSON object with all fields
    json_result = machine.one_step_analysis
    
    # Validate required fields exist
    required_fields = ['reachability', 'reachability_explanation', 'required_conditions', 'rule_checks']
    missing_fields = [field for field in required_fields if field not in json_result]
    if missing_fields:
        logging.warning(f"Missing required fields in JSON response: {missing_fields}")
    
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
    # Note: We don't set is_false_positive here because this analysis alone
    # doesn't have the complete path context to make that determination
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
        # Don't set false positive fields - let intermediate transition analysis decide
        is_false_positive=None,  # Will be determined by intermediate transition analysis
        false_positive_confidence=None  # Will be determined by intermediate transition analysis
    )
    
    machine.detailed_summary = detailed_summary
    # No need for separate summary - detailed_summary already has all fields
    machine.raw_result = json.dumps(json_result)
    
    # Store rule checks and false positive assessment directly on machine for later access
    machine.forward_rule_checks = getattr(detailed_summary, 'purpose_rule_checks', [])
    machine.forward_false_positive = getattr(detailed_summary, 'is_false_positive', None)
    machine.forward_false_positive_confidence = getattr(detailed_summary, 'false_positive_confidence', None)
    
    logging.debug(Fore.GREEN + f'[FORWARD] Detailed Summary: {detailed_summary}')
    return None

def exit_action(machine):
    return None

# Modify the state machine configuration to add a formatting step
state_definitions = {
    'InitContext': {
        'action': init_context_action,
        'next_state_func': lambda result, machine: 'ProcessConfig',
    },
    'ProcessConfig': {
        'action': process_config_action,
        'next_state_func': lambda result, machine: 'FillBehaviorDetails',
    },
    'FillBehaviorDetails': {
        'action': fill_behavior_details_action,
        'next_state_func': lambda result, machine: 'OneStepAnalysis',
    },
    'OneStepAnalysis': {
        'action': one_step_analysis_action,
        'next_state_func': lambda result, machine: 'Summary',
    },
    'Summary': {
        'action': summary_action,
        'next_state_func': lambda result, machine: 'Exit',
    },
    'Exit': {
        'action': exit_action,
        'next_state_func': None,
    }
}