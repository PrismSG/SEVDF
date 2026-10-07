"""
Cross-subpath vulnerability determination state machine.

6 states: InitContext -> ProcessConfig -> FillBehaviorDetails
       -> VulnerabilityDetermination -> Summary -> Exit

Used when intermediate transition steps are empty and the backward/forward
analysis results must be combined directly.
"""

import logging
import json
import textwrap
from colorama import Fore

from BaseMachine.action_utils import create_chat_action_with_tools
from BaseMachine.model_config import get_model_name
from ..utils.data_validation import clean_analysis_result_for_display

from .cross_subpath_tools import (
    build_shared_variables,
    format_transition_rules,
    extract_source_sink_info,
    collect_related_code,
)


# ---------------------------------------------------------------------------
# State actions
# ---------------------------------------------------------------------------

def init_context_action(machine):
    """Copy context fields to machine attributes."""
    machine.source_backward_result = machine.context.source_backward_result
    machine.forward_sink_result = machine.context.forward_sink_result
    machine.backward_steps = machine.context.backward_steps
    machine.forward_steps = machine.context.forward_steps
    return None


def process_config_action(machine):
    """Read cwe_cot_config sections, build shared_variables, format transition rules."""
    cwe_cot_config = machine.cwe_cot_config
    intermediate_config = cwe_cot_config.get('intermediate_transition', {})
    source_backward_config = cwe_cot_config.get('source_backward', {})
    forward_to_sink_config = cwe_cot_config.get('forward_to_sink', {})

    machine.bug_type = intermediate_config.get('bug_type', 'unknown')
    machine.backward_desc = source_backward_config.get('backward_behavior_desc', 'source operation')
    machine.forward_desc = forward_to_sink_config.get('forward_behavior_desc', 'sink operation')
    machine.transition_rules = intermediate_config.get('transition_rules', [])

    machine.shared_variables = build_shared_variables(
        machine.backward_steps, machine.forward_steps
    )
    machine.formatted_rules_text = format_transition_rules(
        machine.transition_rules, machine.shared_variables
    )
    return None


def fill_behavior_details_action(machine):
    """Extract source/sink locations, collect related code, clean results for display."""
    source_function, source_line, sink_function, sink_line = extract_source_sink_info(
        machine.backward_steps, machine.forward_steps
    )
    machine.source_function = source_function
    machine.source_line = source_line
    machine.sink_function = sink_function
    machine.sink_line = sink_line

    machine.all_related_code = collect_related_code(
        machine.backward_steps, machine.forward_steps
    )

    machine.cleaned_backward = (
        clean_analysis_result_for_display(machine.source_backward_result)
        if machine.source_backward_result
        else 'No backward analysis result available.'
    )
    machine.cleaned_forward = (
        clean_analysis_result_for_display(machine.forward_sink_result)
        if machine.forward_sink_result
        else 'No forward analysis result available.'
    )
    return None


def vulnerability_determination_action(machine):
    """Set machine.messages, build prompt, call create_chat_action_with_tools()."""
    logging.info(
        Fore.CYAN
        + f'[CrossSubpath] Starting vulnerability determination (no intermediate steps)'
    )
    logging.info(
        Fore.CYAN
        + f'[CrossSubpath] Source: {machine.source_function}:{machine.source_line}, '
        + f'Sink: {machine.sink_function}:{machine.sink_line}'
    )

    machine.messages = [
        {
            "role": "system",
            "content": f"You are a C/C++ static analysis expert in analyzing {machine.bug_type} bug reports",
        }
    ]

    expected_fields = [
        'transition_checks',
        'is_false_positive',
        'false_positive_confidence',
        'overall_assessment',
    ]

    prompt_template = textwrap.dedent('''
        You are analyzing a potential {bug_type} vulnerability where the source and sink are directly connected (no intermediate propagation steps).

        **Your PRIMARY GOAL**: Determine if this is a FALSE POSITIVE by finding evidence that the vulnerability does NOT exist.

        ## PATH OVERVIEW:
        - Source: {backward_desc} at `{source_function}:{source_line}`
        - Sink: {forward_desc} at `{sink_function}:{sink_line}`

        ## SOURCE ANALYSIS (from backward subpath analysis):
        {cleaned_backward}

        ## SINK ANALYSIS (from forward subpath analysis):
        {cleaned_forward}

        ## VULNERABILITY DETERMINATION RULES:
        {formatted_rules}

        ## RELEVANT CODE:
        {all_related_code}

        ## YOUR TASK:
        Since there are no intermediate propagation steps between source and sink, you must determine vulnerability status
        by combining the source and sink analysis results:

        1. **Source Validity**: Does the source analysis confirm that untrusted data enters at the source point?
        2. **Sink Reachability**: Does the sink analysis confirm the data can reach a dangerous operation?
        3. **Direct Connection**: Given the source and sink are in the same function or closely connected,
           is there any sanitization, validation, or transformation between them that would prevent exploitation?
        4. **Rule Checks**: Apply each transition rule to determine if the vulnerability is real.

        **IMPORTANT**: Focus on finding reasons why this does NOT result in a real vulnerability.
        Consider both the validity of the source/sink and any safety measures identified in the analyses.

        Analyze and provide a structured JSON response.

        CRITICAL: Follow the JSON structure EXACTLY as specified. Do NOT create new fields or nest objects.
    ''').strip()

    try:
        result = create_chat_action_with_tools(
            prompt_template=prompt_template,
            save_option='both',
            model_name=get_model_name(),
            debug=True,
            expected_fields=expected_fields,
            transition_rules=machine.transition_rules,
            context_label='CrossSubpath',
        )(
            machine,
            bug_type=machine.bug_type,
            backward_desc=machine.backward_desc,
            forward_desc=machine.forward_desc,
            source_function=machine.source_function,
            source_line=machine.source_line,
            sink_function=machine.sink_function,
            sink_line=machine.sink_line,
            cleaned_backward=machine.cleaned_backward,
            cleaned_forward=machine.cleaned_forward,
            formatted_rules=machine.formatted_rules_text,
            all_related_code=machine.all_related_code,
        )

        if isinstance(result, dict):
            logging.info(
                Fore.GREEN
                + f'[CrossSubpath] Vulnerability determination complete: '
                + f'is_false_positive={result.get("is_false_positive")}'
            )
            machine.cross_subpath_raw_result = result
        else:
            logging.warning(
                Fore.YELLOW
                + f'[CrossSubpath] Unexpected result type: {type(result)}'
            )
            machine.cross_subpath_raw_result = {
                'is_false_positive': True,
                'overall_assessment': str(result),
            }

    except Exception as e:
        logging.error(Fore.RED + f'[CrossSubpath] Vulnerability determination failed: {e}')
        import traceback
        traceback.print_exc()
        machine.cross_subpath_raw_result = None

    return None


def summary_action(machine):
    """Parse LLM result, set machine.is_false_positive and machine.cross_subpath_raw_result."""
    result = getattr(machine, 'cross_subpath_raw_result', None)
    if result and isinstance(result, dict):
        machine.is_false_positive = result.get('is_false_positive', True)
    else:
        machine.is_false_positive = True
    return None


def exit_action(machine):
    """Log completion."""
    logging.info(Fore.GREEN + '[CrossSubpath] Sub-machine complete')
    return None


# ---------------------------------------------------------------------------
# State definitions
# ---------------------------------------------------------------------------

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
        'next_state_func': lambda result, machine: 'VulnerabilityDetermination',
    },
    'VulnerabilityDetermination': {
        'action': vulnerability_determination_action,
        'next_state_func': lambda result, machine: 'Summary',
    },
    'Summary': {
        'action': summary_action,
        'next_state_func': lambda result, machine: 'Exit',
    },
    'Exit': {
        'action': exit_action,
        'next_state_func': None,
    },
}
