# Intermediate propagation reasoning for Scanner-Union Logic Units.
import logging
import textwrap
from colorama import Fore
from datetime import datetime
from BaseMachine.state_machine import StateMachine
from BaseMachine.action_utils import create_chat_action, create_new_chat_action, create_chat_action_with_tools
from BaseMachine.model_config import get_model_name
import json

from .intermediate_transition_context import IntermediateTransitionFlowContext, Step, Point, InlineCondition, FeasibilityResult, UAFResult
from ..utils.semantic_label_utils import format_variable_for_narrative

# Import validation utilities
from ..utils.data_validation import (
    validate_json_string,
    validate_rule_checks,
    extract_rule_checks_from_result,
    log_data_transmission,
    create_fallback_rule_check,
    clean_analysis_result_for_display
)

# Helper functions for handling rule check results
def parse_rule_checks(json_result):
    """Parse rule check results from JSON string with validation"""
    try:
        if not json_result:
            log_data_transmission("parse_rule_checks", "empty input", False)
            return []
            
        # Use the validation utility to extract rule checks
        rule_checks = extract_rule_checks_from_result(json_result)
        
        if rule_checks:
            log_data_transmission("parse_rule_checks", "rule extraction", True, 
                                f"Extracted {len(rule_checks)} rule checks")
        else:
            log_data_transmission("parse_rule_checks", "rule extraction", False, 
                                "No rule checks found")
            
        return rule_checks
    except Exception as e:
        logging.warning(f"Failed to parse rule checks: {e}")
        log_data_transmission("parse_rule_checks", "exception", False, str(e))
        return []

def format_rule_checks(rule_checks):
    """Format rule check results for display in prompts with validation"""
    if not rule_checks:
        return "No rule checks available from previous analysis."
    
    # Validate rule checks structure
    if not validate_rule_checks(rule_checks):
        logging.warning("Invalid rule checks structure, using fallback format")
        return "Rule checks available but format is invalid."
    
    formatted = []
    for i, check in enumerate(rule_checks, 1):
        # Safely get values with defaults
        rule_text = check.get('rule_text', 'Unknown rule')
        check_result = check.get('check_result', 'No result available')
        code_refs = check.get('code_references', [])
        
        formatted.append(f"""
Rule {i}: {rule_text}
Result: {check_result}
Code References: {'; '.join(code_refs) if code_refs else 'None'}
""")
    return '\n'.join(formatted)

def init_context_action(machine):
    """handle the context"""
    machine.from_line = machine.context.steps[0].fromPoint.line
    machine.from_line_code = machine.context.steps[0].fromPoint.lineCode
    machine.from_function_name = machine.context.steps[0].fromPoint.functionName
    machine.to_line = machine.context.steps[-1].toPoint.line
    machine.to_line_code = machine.context.steps[-1].toPoint.lineCode
    machine.to_function_name = machine.context.steps[-1].toPoint.functionName
    machine.related_code = machine.context.steps[0].relatedCode
    machine.same_function = machine.context.steps[0].sameFunction
    machine.function_name = machine.context.steps[0].fromPoint.functionName
    machine.variable = machine.context.steps[0].fromPoint.variable

    machine.source_backward_result = machine.context.source_backward_result
    machine.forward_sink_result = machine.context.forward_sink_result
    machine.forward_empty = machine.context.forward_empty
    machine.backward_empty = machine.context.backward_empty
    
    # Parse detailed rule check results
    machine.source_backward_checks = parse_rule_checks(machine.source_backward_result)
    machine.forward_sink_checks = parse_rule_checks(machine.forward_sink_result)

    return None

def process_config_action(machine):
    """1. handle the config"""
    cwe_cot_config = machine.cwe_cot_config
    intermediate_config = cwe_cot_config['intermediate_transition']
    source_backward_config = cwe_cot_config['source_backward']
    forward_to_sink_config = cwe_cot_config['forward_to_sink']

    machine.intermediate_config = {
        'bug_type': intermediate_config.get('bug_type', ''),
        'inter_propagation_behavior_details': intermediate_config.get('inter_propagation_behavior_details', ''),
        'transition_rules': intermediate_config.get('transition_rules', [])
    }

    machine.source_backward_config = {
        'backward_behavior_desc': source_backward_config.get('backward_behavior_desc', ''),
        'backward_behavior_rules': source_backward_config.get('backward_behavior_rules', []),
        'purpose_desc': source_backward_config.get('purpose_desc', ''),
        'purpose_rules': source_backward_config.get('purpose_rules', [])
    }

    machine.forward_to_sink_config = {
        'forward_behavior_desc': forward_to_sink_config.get('forward_behavior_desc', ''),
        'forward_behavior_rules': forward_to_sink_config.get('forward_behavior_rules', []),
        'purpose_desc': forward_to_sink_config.get('purpose_desc', ''),
        'purpose_rules': forward_to_sink_config.get('purpose_rules', [])
    }

    """2. format the config"""
    # the only place to initialize the shared_variables
    machine.shared_variables = {
        'last_visit_code': machine.context.steps[0].toPoint.lineCode,
        'from_function_name': machine.context.steps[0].fromPoint.functionName,
        'from_line': machine.context.steps[0].fromPoint.line,
        'from_line_code': machine.context.steps[0].fromPoint.lineCode,
        'to_function_name': machine.context.steps[-1].toPoint.functionName,
        'to_line': machine.context.steps[-1].toPoint.line,
        'to_line_code': machine.context.steps[-1].toPoint.lineCode,
        'variable': machine.context.steps[0].fromPoint.variable,
        'outer_backward_behavior_variable': machine.context.steps[0].fromPoint.variable,
        'outer_backward_behavior_function_name': machine.context.steps[0].fromPoint.functionName,
        'outer_backward_behavior_line_code': machine.context.steps[0].fromPoint.lineCode,
        'outer_backward_behavior_line_number': machine.context.steps[0].fromPoint.line,
        'outer_backward_semantic_label': getattr(machine.context.steps[0].fromPoint, 'semanticLabel', None) or machine.context.steps[0].fromPoint.variable,
        'outer_forward_behavior_variable': machine.context.steps[-1].toPoint.variable,
        'outer_forward_behavior_function_name': machine.context.steps[-1].toPoint.functionName,
        'outer_forward_behavior_line_code': machine.context.steps[-1].toPoint.lineCode,
        'outer_forward_behavior_line_number': machine.context.steps[-1].toPoint.line,
        'outer_forward_semantic_label': getattr(machine.context.steps[-1].toPoint, 'semanticLabel', None) or machine.context.steps[-1].toPoint.variable
    }
    
    # format all the content that needs to be formatted
    machine.formatted_backward_behavior_desc = str(
        machine.source_backward_config['backward_behavior_desc']
    ).format(**machine.shared_variables)
    
    machine.formatted_forward_behavior_desc = str(
        machine.forward_to_sink_config['forward_behavior_desc']
    ).format(**machine.shared_variables)
    
    # format the inter_propagation_behavior_details
    machine.formatted_intermediate_behavior_details = str(
        machine.intermediate_config['inter_propagation_behavior_details']
    ).format(**machine.shared_variables)
    
    transition_rules = machine.intermediate_config['transition_rules']
    # Handle both old format (string) and new format (object with title and rule)
    formatted_rules = []
    for i, item in enumerate(transition_rules):
        if isinstance(item, dict):
            # New format with title and rule
            title = item['title']
            rule = item['rule'].format(**machine.shared_variables)
            formatted_rules.append(f'{i+3}. **{title}**: {rule}')
        else:
            # Old format - just a string
            formatted_rules.append(f'{i+3}. {item.format(**machine.shared_variables)}')
    
    machine.formatted_rules = '\n'.join(formatted_rules)

    # Format purpose_desc and purpose_rules for backward analysis
    machine.formatted_backward_purpose_desc = str(
        machine.source_backward_config['purpose_desc']
    ).format(**machine.shared_variables)

    # Handle both old format (string) and new format (object with title and rule)
    formatted_backward_rules = []
    for i, item in enumerate(machine.source_backward_config['purpose_rules']):
        if isinstance(item, dict):
            # New format with title and rule
            title = item['title']
            rule = item['rule'].format(**machine.shared_variables)
            formatted_backward_rules.append(f'{i+1}. **{title}**: {rule}')
        else:
            # Old format - just a string
            formatted_backward_rules.append(f'{i+1}. {item.format(**machine.shared_variables)}')
    
    machine.formatted_backward_purpose_rules = '\n'.join(formatted_backward_rules)

    # Format purpose_desc and purpose_rules for forward analysis
    machine.formatted_forward_purpose_desc = str(
        machine.forward_to_sink_config['purpose_desc']
    ).format(**machine.shared_variables)

    # Handle both old format (string) and new format (object with title and rule)
    formatted_forward_rules = []
    for i, item in enumerate(machine.forward_to_sink_config['purpose_rules']):
        if isinstance(item, dict):
            # New format with title and rule
            title = item['title']
            rule = item['rule'].format(**machine.shared_variables)
            formatted_forward_rules.append(f'{i+1}. **{title}**: {rule}')
        else:
            # Old format - just a string
            formatted_forward_rules.append(f'{i+1}. {item.format(**machine.shared_variables)}')
    
    machine.formatted_forward_purpose_rules = '\n'.join(formatted_forward_rules)
    
    machine.formatted_forward_behavior_desc = str(
        machine.forward_to_sink_config['forward_behavior_desc']
    ).format(**machine.shared_variables)

    machine.bug_type = machine.intermediate_config['bug_type']

    return None

def fill_behavior_details_action(machine):
    # Extract constraints for intermediate transitions
    try:
        from .intermediate_transition_tools import analyze_intermediate_transitions_with_constraints
        analyze_intermediate_transitions_with_constraints(machine)
    except Exception as e:
        logging.warning(f"Failed to extract constraints for intermediate transitions: {e}")
    
    # Construct detailed step analysis
    machine.call_chain = '' 
    machine.all_related_code = ''
    
    # If there are no steps, add default information
    if not machine.context.steps:
        machine.call_chain = 'No steps in data flow'
        machine.all_related_code = f'No related code available'
        return None

    # Check if we're using a virtual intermediate step
    steps_relationships = getattr(machine.context, 'steps_relationships', {})
    is_virtual_step = any(
        steps_relationships.get(
            (step.fromPoint.file, step.fromPoint.line,
             step.toPoint.file, step.toPoint.line, step.flowstep), ''
        ) == 'VIRTUAL'
        for step in machine.context.steps
    )

    # Track added code snippets to avoid duplication
    added_code_segments = set()

    # Draw the call chain, using steps_relationships dictionary
    index = 0
    for step in machine.context.steps:
        # Get relationship type from steps_relationships dictionary
        step_key = (step.fromPoint.file, step.fromPoint.line,
                    step.toPoint.file, step.toPoint.line, step.flowstep)
        relation = steps_relationships.get(step_key, "NULL")
        relation_desc = ""
        
        if relation == "CALL":
            relation_desc = "called"
        elif relation == "RETURN":
            relation_desc = "returned to"
        else:
            relation_desc = "propagated to"
            
        tabs = '\t' * index
        
        # When the code is the same, only add the internal propagation information of the call chain
        if step.toPoint.relatedCode == step.fromPoint.relatedCode:
            # Only add code when the code snippet is encountered for the first time
            if step.fromPoint.relatedCode not in added_code_segments:
                added_code_segments.add(step.fromPoint.relatedCode)
                machine.all_related_code += f'// Code in function {step.fromPoint.functionName}\n{tabs}{step.fromPoint.relatedCode}\n\n'
            
            # Add the call chain propagated in the function
            machine.call_chain += f'{tabs}{step.fromPoint.functionName} [internal propagation] // Variable propagated internally within {step.fromPoint.functionName}\n'
            continue
            
        # Handle inter-function calls
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
            
            # Only add code when the target code snippet is encountered for the first time
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
    
    # Construct a detailed analysis of the intermediate step
    intermediate_steps_details = f"""
Intermediate Steps Data Flow Analysis:
-------------------------------------

"""
    # Process the data flow of each step
    steps = machine.context.steps
    
    # Track continuous code segments
    current_segment_start = 0
    in_continuous_segment = False
    prefix = "First"
    
    # Handle virtual intermediate step specially
    if is_virtual_step:
        intermediate_steps_details += f"""
Note: This is a single source point analysis - the tainted data originates directly at the source location.
No intermediate propagation steps are involved.
"""
    else:
        # Process each step
        for i, step in enumerate(steps):
            from_function = step.fromPoint.functionName
            to_function = step.toPoint.functionName
            from_variable = format_variable_for_narrative(step.fromPoint)
            
            # Get relationship type from steps_relationships dictionary
            step_key = (step.fromPoint.file, step.fromPoint.line,
                        step.toPoint.file, step.toPoint.line, step.flowstep)
            relation = steps_relationships.get(step_key, "NULL")

            # Check if this is a parameter passing (identical code) step
            is_identical_code = step.toPoint.relatedCode == step.fromPoint.relatedCode
            
            # Start of a new continuous segment of identical code
            if is_identical_code and not in_continuous_segment:
                current_segment_start = i
                in_continuous_segment = True
                
                # For the first step in a continuous segment, it's parameter passing
                # have the possibility to be not started from parameter passing.
                intermediate_steps_details += f"""
{prefix} in `{from_function}` line {step.fromPoint.line}, {from_variable} is propagated within the same function (SAME relationship). This is an internal data flow where the variable moves from one point to another in function `{from_function}`, reaching line {step.toPoint.line}:
```
Line {step.toPoint.line}:{step.toPoint.lineCode}
```
"""
            
            # Continuation of a continuous segment
            elif is_identical_code and in_continuous_segment:
                # This is a propagation within the segment
                intermediate_steps_details += f"""
{prefix} in `{from_function}` line {step.fromPoint.line}, {from_variable} continues its propagation path within the same function (SAME relationship). The data flow remains in function `{from_function}`, moving to line {step.toPoint.line}:
```
Line {step.toPoint.line}:{step.toPoint.lineCode}
```
"""
            
            # End of a continuous segment, or not in a segment
            elif not is_identical_code:
                in_continuous_segment = False

                # Assertion: When the two pieces of code are different, the relation must be CALL or RETURN
                if relation not in ["CALL", "RETURN"]:
                    logging.warning(f"Warning: When code segments differ, relation should be CALL or RETURN, got {relation}")
                    relation = "CALL"  # Default to CALL to avoid interrupting execution

                # Generate different description statements according to the relation type
                if relation == "CALL":
                    # Call relationship: the current function calls another function
                    intermediate_steps_details += f"""
{prefix} in `{from_function}` line {step.fromPoint.line}, {from_variable} is passed as a parameter from caller `{from_function}` to callee `{to_function}` (CALL relationship). The variable is then used at line {step.toPoint.line} in `{to_function}`: 
```
Line {step.toPoint.line}:{step.toPoint.lineCode}
``` 
"""
                else:  # relation must be "RETURN"
                    # Return relationship: return from the called function to the calling function
                    intermediate_steps_details += f"""
{prefix} in `{from_function}` line {step.fromPoint.line}, {from_variable} is returned from callee `{from_function}` back to caller `{to_function}` (RETURN relationship). The returned value is received at line {step.toPoint.line} in `{to_function}`: 
```
Line {step.toPoint.line}:{step.toPoint.lineCode}
``` 
"""
            
            prefix = "then"
    
    # Append variant details if this unit has propagation variants
    from ..utils.variant_description import build_variant_behavior_section
    variant_section = build_variant_behavior_section(
        getattr(machine, 'variant_details', None), 'intermediate')
    if variant_section:
        intermediate_steps_details += variant_section

    # Check for loops - compare the line numbers of the first and last elements
    loop_warning = ""
    # Skip loop detection for virtual intermediate steps
    if not is_virtual_step and steps and len(steps) > 1:
        first_line = steps[0].fromPoint.line
        last_line = steps[-1].toPoint.line
        
        # If the last line number is less than or equal to the first line number, there may be a loop
        if last_line <= first_line:
            loop_warning = f"""

**Warning: Potential Loop Detected**
The data flow may have gone through a loop - the last line number ({last_line}) is less than or equal to the first line number ({first_line}). Pay extra attention to the control flow structure as this could indicate iterative processing or cyclic dependencies.
"""
            logging.info(f"Loop detected in intermediate behavior: first line={first_line}, last line={last_line}")
    
    # Add loop warning to intermediate_steps_details
    if loop_warning:
        intermediate_steps_details += loop_warning
    
    # Now build the final behavior details description, considering that backward and forward may be empty
    backward_section = ""
    if not machine.backward_empty:
        # Result from full source_backward subpath analysis
        cleaned_backward_result = clean_analysis_result_for_display(machine.source_backward_result)

        backward_section = f"""
1. First, The following line in `{machine.from_function_name}` is a {machine.formatted_backward_behavior_desc}:
```
Line {machine.from_line}:{machine.from_line_code}
```
Previous analysis result (you don't need to re-analyze this operation):
{cleaned_backward_result}
"""
    else:
        backward_section = f"""
1. First, The following line in `{machine.from_function_name}` is a {machine.formatted_backward_behavior_desc}:
```
Line {machine.from_line}:{machine.from_line_code}
```

"""

    forward_section = ""
    if not machine.forward_empty:
        # Result from full forward_to_sink subpath analysis
        cleaned_forward_result = clean_analysis_result_for_display(machine.forward_sink_result)

        forward_section = f"""
3. and this line {machine.to_line} in `{machine.to_function_name}` is a {machine.formatted_forward_behavior_desc}:
```
Line {machine.to_line}:{machine.to_line_code}
```
Previous analysis result (you don't need to re-analyze this operation):
{cleaned_forward_result}
"""
    else:
        forward_section = f"""
3. and this line {machine.to_line} in `{machine.to_function_name}` is a {machine.formatted_forward_behavior_desc}:
```
Line {machine.to_line}:{machine.to_line_code}
```

"""
    
    # Combine all parts
    inter_propagation_behavior_details = f"""

{backward_section}
2. Then, the variable `{machine.variable}`'s data flow propagation process in function `{machine.from_function_name}` is as follows:
{intermediate_steps_details}

{forward_section}
This propagation happens in function `{machine.from_function_name}` from {machine.formatted_backward_behavior_desc} to {machine.formatted_forward_behavior_desc} is called intermediate propagation.

"""
    
    machine.intermediate_transition_behavior_details = inter_propagation_behavior_details

    return None

def one_step_analysis_action(machine):
    bug_type = machine.bug_type
    machine.messages = [
        {
            "role": "system",
            "content": "You are a C/C++ static analysis expert in analyzing " + bug_type + " bug reports",
        }
    ]
    
    # Prepare constraint section (independent)
    constraint_section = ""
    if hasattr(machine, 'constraint_text_for_prompt') and machine.constraint_text_for_prompt:
        constraint_section = machine.constraint_text_for_prompt

    # Prepare macro section (independent, preloaded via use-def)
    macro_section = ""
    if hasattr(machine, 'macro_text_for_prompt') and machine.macro_text_for_prompt:
        macro_section = machine.macro_text_for_prompt

    # Define expected fields for the JSON response
    expected_fields = [
        'reachability',  # "REACHABLE" or "UNREACHABLE"
        'reachability_explanation',
        'required_conditions',
        'reachability_confidence',
        'transition_checks',  # Using transition_checks instead of rule_checks for intermediate
        'is_false_positive',
        'false_positive_confidence',
        'overall_assessment'
    ]
    
    # Build prompt with constraint information
    prompt_with_constraints = textwrap.dedent('''
        You are analyzing the propagation path of a potential {bug_type} vulnerability.

        **Your PRIMARY GOAL**: Determine if this is a FALSE POSITIVE by finding evidence that the vulnerability does NOT propagate successfully.

        ## PROPAGATION PATH OVERVIEW:
        - Source: {backward_behavior_desc} at `{from_function_name}:{from_line}`
        - Sink: {forward_behavior_desc} at `{to_function_name}:{to_line}`
        - Variable tracked: `{variable}`

        ## DETAILED PROPAGATION ANALYSIS:
        {intermediate_transition_behavior_details}

        ## YOUR TASK HAS TWO DIMENSIONS:

        **DIMENSION 1: Propagation Feasibility**
        Analyze if the propagation chain is REACHABLE under real-world conditions:
        1. Check CONDITIONS that allow execution from {from_function_name} to reach line {from_line}, then propagate to line {to_line}
        2. Look for conflicting conditions that might prevent this propagation
        3. Analyze return values and control flow that could break the chain

        Apply these rules:
        {rules}

        **DIMENSION 2: False Positive Detection**
        Based on the previous analysis results (shown above), look for evidence that this is NOT a real vulnerability:

        1. **Source Safety Checks**: Did the source analysis find any immediate safety measures?
        2. **Sink Protection**: Did the sink analysis find any exploitation barriers?
        3. **Propagation Interruption**: Are there sanitization or validation steps in the propagation?
        4. **Semantic Disconnection**: Does the variable lose its dangerous properties during propagation?

        Pay special attention to:
        - Any significant findings in the rule checks above
        - Safety measures identified at source or sink
        - Transformations that neutralize the threat

        ## RELEVANT CODE:
        {all_related_code}
    ''').strip()

    # Add constraint section if available
    if constraint_section:
        prompt_with_constraints += '\n\n{constraint_section}'

    # Add macro section if available (independent from constraints)
    if macro_section:
        prompt_with_constraints += '\n\n{macro_section}'

    # Add section separator before IMPORTANT
    prompt_with_constraints += '\n\n' + '=' * 40 + '\n'
    prompt_with_constraints += textwrap.dedent('''
**IMPORTANT**: Focus on finding reasons why this propagation does NOT result in a real vulnerability. Consider both the feasibility of the propagation AND the safety measures identified in previous analyses.

Analyze the propagation and provide a structured JSON response.

CRITICAL: Follow the JSON structure EXACTLY as specified. Do NOT create new fields or nest objects.
''').strip()
    
    one_step_analysis = create_chat_action_with_tools(
        prompt_template=prompt_with_constraints,
        save_option='both',
        model_name=get_model_name(),
        # model_name='qwq-32b',
        debug=True,
        expected_fields=expected_fields,
        transition_rules=machine.intermediate_config['transition_rules'],
        context_label='Intermediate'
    )(
        machine,
        from_function_name=machine.from_function_name,
        from_line=machine.from_line,
        from_line_code=machine.from_line_code,
        to_function_name=machine.to_function_name,
        to_line=machine.to_line,
        to_line_code=machine.to_line_code,
        variable=machine.variable,
        intermediate_transition_behavior_details=machine.intermediate_transition_behavior_details,  # Pass in the formatted value
        all_related_code=machine.all_related_code,  # Use the newly added all_related_code variable
        rules=machine.formatted_rules,
        forward_behavior_desc=machine.formatted_forward_behavior_desc,
        backward_behavior_desc=machine.formatted_backward_behavior_desc,
        bug_type=machine.bug_type,
        constraint_section=constraint_section,
        macro_section=macro_section
    )
    # Ensure raw_result is always a string for cache storage
    if isinstance(one_step_analysis, dict):
        # Store the complete JSON structure as a string, consistent with other raw_results
        machine.intermediate_transition_raw_result = json.dumps(one_step_analysis)
        machine.intermediate_transition_json_result = one_step_analysis
    else:
        # Fallback for non-dict responses
        machine.intermediate_transition_raw_result = str(one_step_analysis)
        machine.intermediate_transition_json_result = {'analysis': str(one_step_analysis)}

    logging.debug(Fore.BLUE + f'[INTERMEDIATE] {machine.bug_type} Analysis: {json.dumps(one_step_analysis, indent=2) if isinstance(one_step_analysis, dict) else one_step_analysis}')
    return None

def summary_action(machine):
    # Extract structured data from the JSON response
    json_result = machine.intermediate_transition_json_result
    
    # Check if it's a dictionary (full JSON result)
    if isinstance(json_result, dict):
        # The intermediate analysis focuses on propagation, so we look at transition_checks
        # and overall assessment to determine if it's a valid bug
        is_valid_bug = not json_result.get('is_false_positive', False)
        
        # Create a simple UAFResult for backward compatibility
        machine.json_result = UAFResult(valid_uaf=is_valid_bug)
        
        # Store detailed results for later access
        machine.intermediate_feasibility = (json_result.get('reachability', 'UNREACHABLE') == 'REACHABLE')
        machine.intermediate_transition_checks = json_result.get('transition_checks', [])
        machine.intermediate_false_positive = json_result.get('is_false_positive', None)
        machine.intermediate_assessment = json_result.get('overall_assessment', '')
    else:
        # Fallback for old format or error cases
        summary = create_new_chat_action(
            prompt_template='''
            Please summarize the analysis results to give the boolean result of whether this is a possible {bug_type} bug in the real world execution.
            Read the analysis result carefully and give me True if it is a possible {bug_type} bug, otherwise give me False.
             
            Please Note: If some critical information like specific function definition(s) is missing in the analysis result, you should give me False.

            The analysis result is as follows:
            {intermediate_transition_raw_result}
            ''',
            save_option='both',
            response_parser=UAFResult,
            debug=False
        )(
            machine,
            intermediate_transition_raw_result=machine.intermediate_transition_raw_result,
            bug_type=machine.bug_type
        )
        machine.json_result = summary
    
    logging.debug(Fore.CYAN + '[INTERMEDIATE] Intermediate analysis complete')
    
    return None

def exit_action(machine):
    return None

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
