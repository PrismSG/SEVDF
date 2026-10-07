"""
Cross-subpath vulnerability determination helper utilities.

When intermediate transition steps are empty (no intermediate analysis was performed),
these helpers support the cross-subpath sub-machine by extracting source/sink info,
collecting related code, building shared variables, and formatting transition rules.
"""


def build_shared_variables(backward_steps, forward_steps):
    """
    Build shared_variables dict from backward/forward steps for template formatting.

    Returns:
        dict with outer_backward_behavior_* and outer_forward_behavior_* keys.
    """
    source_function = 'unknown'
    source_line = '?'
    sink_function = 'unknown'
    sink_line = '?'

    if backward_steps:
        first_backward = backward_steps[0]
        source_function = first_backward.fromPoint.functionName
        source_line = first_backward.fromPoint.line

    if forward_steps:
        last_forward = forward_steps[-1]
        sink_function = last_forward.toPoint.functionName
        sink_line = last_forward.toPoint.line

    return {
        'outer_backward_behavior_variable': backward_steps[0].fromPoint.variable if backward_steps else 'unknown',
        'outer_backward_behavior_function_name': source_function,
        'outer_backward_behavior_line_code': backward_steps[0].fromPoint.lineCode if backward_steps else '',
        'outer_backward_behavior_line_number': source_line,
        'outer_forward_behavior_variable': forward_steps[-1].toPoint.variable if forward_steps else 'unknown',
        'outer_forward_behavior_function_name': sink_function,
        'outer_forward_behavior_line_code': forward_steps[-1].toPoint.lineCode if forward_steps else '',
        'outer_forward_behavior_line_number': sink_line,
    }


def format_transition_rules(transition_rules, shared_variables):
    """
    Format transition rules text using shared_variables for template substitution.

    Args:
        transition_rules: List of rule dicts or strings from cwe_cot_config.
        shared_variables: Dict for .format() substitution.

    Returns:
        Formatted rules as a single string, one rule per line.
    """
    formatted_rules = []
    for i, item in enumerate(transition_rules):
        if isinstance(item, dict):
            title = item['title']
            try:
                rule = item['rule'].format(**shared_variables)
            except KeyError:
                rule = item['rule']
            formatted_rules.append(f'{i+1}. **{title}**: {rule}')
        else:
            try:
                formatted_rules.append(f'{i+1}. {item.format(**shared_variables)}')
            except KeyError:
                formatted_rules.append(f'{i+1}. {item}')
    return '\n'.join(formatted_rules)


def extract_source_sink_info(backward_steps, forward_steps):
    """
    Extract source and sink function name + line from steps.

    Returns:
        (source_function, source_line, sink_function, sink_line)
    """
    source_function = 'unknown'
    source_line = '?'
    sink_function = 'unknown'
    sink_line = '?'

    if backward_steps:
        first_backward = backward_steps[0]
        source_function = first_backward.fromPoint.functionName
        source_line = first_backward.fromPoint.line

    if forward_steps:
        last_forward = forward_steps[-1]
        sink_function = last_forward.toPoint.functionName
        sink_line = last_forward.toPoint.line

    return source_function, source_line, sink_function, sink_line


def collect_related_code(backward_steps, forward_steps):
    """
    Collect deduplicated related code snippets from backward and forward steps.

    Returns:
        Concatenated code string with function-name annotations.
    """
    all_related_code = ''
    added_code = set()

    for step in (backward_steps or []):
        if step.fromPoint.relatedCode and step.fromPoint.relatedCode not in added_code:
            added_code.add(step.fromPoint.relatedCode)
            all_related_code += f'// Code in function {step.fromPoint.functionName}\n{step.fromPoint.relatedCode}\n\n'
        if step.toPoint.relatedCode and step.toPoint.relatedCode not in added_code:
            added_code.add(step.toPoint.relatedCode)
            all_related_code += f'// Code in function {step.toPoint.functionName}\n{step.toPoint.relatedCode}\n\n'

    for step in (forward_steps or []):
        if step.fromPoint.relatedCode and step.fromPoint.relatedCode not in added_code:
            added_code.add(step.fromPoint.relatedCode)
            all_related_code += f'// Code in function {step.fromPoint.functionName}\n{step.fromPoint.relatedCode}\n\n'
        if step.toPoint.relatedCode and step.toPoint.relatedCode not in added_code:
            added_code.add(step.toPoint.relatedCode)
            all_related_code += f'// Code in function {step.toPoint.functionName}\n{step.toPoint.relatedCode}\n\n'

    return all_related_code
