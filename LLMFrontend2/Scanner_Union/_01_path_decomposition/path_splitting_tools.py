"""
Path Splitting Tools for Scanner-Union

Core functions for splitting CodeQL taint flow paths into backward/intermediate/forward
segments based on CFL-Reachability decomposition (CALL/RETURN analysis).

These functions were originally in _04_1_analysis_scheduling/analysis_scheduling_tools.py
and are the canonical implementation consumed by path_decomposition_tools.py.
"""
import json
import logging
from colorama import Fore

from .path_decomposition_context import FlowStepDivide, Step, Point


def parse_json_to_flow_step_divide(machine: str) -> FlowStepDivide:
    # Parse the JSON string
    main_data = json.loads(machine.strip())

    # Extract the propagation path
    propagation_path = main_data.get("propagation path", [])

    logging.debug(Fore.BLUE + f'Propagation Path: {propagation_path}')

    steps = []
    # Maximum size for relatedCode to prevent OOM with huge functions (sqlite3.c, etc.)
    MAX_RELATED_CODE_SIZE = 10000  # ~10KB per code block (about 200 lines)

    for step_data in propagation_path:
        from_point_data = step_data["from"]
        to_point_data = step_data["to"]

        # Truncate relatedCode to prevent memory issues
        from_related_code = from_point_data.get("relatedCode", "")
        to_related_code = to_point_data.get("relatedCode", "")

        if len(from_related_code) > MAX_RELATED_CODE_SIZE:
            from_related_code = from_related_code[:MAX_RELATED_CODE_SIZE] + "\n... [truncated, original size: {} bytes]".format(len(from_related_code))
        if len(to_related_code) > MAX_RELATED_CODE_SIZE:
            to_related_code = to_related_code[:MAX_RELATED_CODE_SIZE] + "\n... [truncated, original size: {} bytes]".format(len(to_related_code))

        from_point = Point(
            file=from_point_data["file_path"],
            line=from_point_data["line"],
            lineCode=from_point_data["lineCode"],
            variable=from_point_data["variable"],
            relatedCode=from_related_code,
            functionName=from_point_data.get("functionName", ""),
            startColumn=from_point_data.get("startColumn"),
            endColumn=from_point_data.get("endColumn"),
            semanticLabel=from_point_data.get("semanticLabel")
        )

        to_point = Point(
            file=to_point_data["file_path"],
            line=to_point_data["line"],
            lineCode=to_point_data["lineCode"],
            variable=to_point_data["variable"],
            relatedCode=to_related_code,
            functionName=to_point_data.get("functionName", ""),
            startColumn=to_point_data.get("startColumn"),
            endColumn=to_point_data.get("endColumn"),
            semanticLabel=to_point_data.get("semanticLabel")
        )

        # Check if the step is within the same function
        # Based on related code to handle same-name functions with different implementations
        same_function = (from_point.relatedCode == to_point.relatedCode)

        # Construct related code
        if same_function:
            related_code = from_point.relatedCode
        else:
            related_code = from_point.relatedCode + "\n" + to_point.relatedCode

        step = Step(
            flowstep=step_data["propagation step"],
            fromPoint=from_point,
            toPoint=to_point,
            relatedCode=related_code.strip(),
            sameFunction=same_function
        )
        steps.append(step)

    return FlowStepDivide(steps=steps)


def classify_steps(steps):
    """
    Classify steps into same-function and cross-function categories.

    Args:
        steps: List of Step objects to be classified

    Returns:
        tuple: (same_function_steps, cross_function_steps)
    """
    same_function_steps = []
    cross_function_steps = []

    # Classify steps without verbose logging
    for i, step in enumerate(steps, start=1):
        # Check if the step is within the same function
        if step.sameFunction:
            step_type = "SAME FUNCTION"
            same_function_steps.append(step)
        else:
            step_type = "CROSS FUNCTION"
            cross_function_steps.append(step)

    # Log only the summary results
    logging.info(Fore.BLUE + f'Step classification: {len(steps)} total, {len(same_function_steps)} same-function, {len(cross_function_steps)} cross-function')

    # Log more details if all steps are same-function
    if len(cross_function_steps) == 0 and len(steps) > 0:
        logging.warning("No cross-function steps found!")
        for i, step in enumerate(steps[:3]):  # Show first 3 steps
            logging.info(f"  Step {i+1}: {step.fromPoint.functionName} -> {step.toPoint.functionName} (sameFunction={step.sameFunction})")
        if len(steps) > 3:
            logging.info(f"  ... and {len(steps) - 3} more steps")

    return same_function_steps, cross_function_steps


def analyze_call_relationships(cross_function_steps, config_path, codeql_db_path):
    """
    Analyze call relationships for cross-function steps.

    Args:
        cross_function_steps: List of cross-function steps
        config_path: Configuration path for StateMachine
        codeql_db_path: Path to CodeQL database for static analysis

    Returns:
        tuple: (call_relationships, step_types)
    """
    from .call_type_analysis.subpath_type_config import state_definitions as subpath_type_state_definitions
    from .call_type_analysis.subpath_type_context import SubpathTypeFlowContext
    from BaseMachine.state_machine import StateMachine

    if not cross_function_steps:
        return [], []

    logging.info(Fore.YELLOW + f'Analyzing Cross-Function Call Relationships:')
    call_relationships = []
    step_types = []

    for i, step in enumerate(cross_function_steps, start=1):
        # Create SubpathTypeFlowContext for analysis
        sub_context = SubpathTypeFlowContext(
            fromCode=step.fromPoint.lineCode,
            fromLocation=f"{step.fromPoint.file}:{step.fromPoint.line}",
            toCode=step.toPoint.lineCode,
            toLocation=f"{step.toPoint.file}:{step.toPoint.line}",
            relatedCode=step.relatedCode,
            codeql_db_path=codeql_db_path,
            toFunctionName=step.toPoint.functionName,
            fromFunctionName=step.fromPoint.functionName
        )

        # Create and process StateMachine for call relationship analysis
        sub_machine = StateMachine(
            context=sub_context,
            state_definitions=subpath_type_state_definitions,
            initial_state='InitializeSystemPrompt',
            config_path=config_path
        )
        sub_machine.process()

        # Get call relationship (to_call_from attribute indicates if it's a call or return)
        is_call = getattr(sub_machine, 'to_call_from', None)
        if hasattr(sub_machine, 'to_call_from') and hasattr(sub_machine.to_call_from, 'to_call_from'):
            is_call = sub_machine.to_call_from.to_call_from
        else:
            is_call = False  # Default if attribute not found

        call_relationships.append(is_call)
        relationship_type = "RETURN" if is_call else "CALL"
        step_types.append(relationship_type)

        # Log the call relationship
        from_func = step.fromPoint.functionName
        to_func = step.toPoint.functionName
        from_loc = f"{step.fromPoint.file}:{step.fromPoint.line}"
        to_loc = f"{step.toPoint.file}:{step.toPoint.line}"

        logging.debug(Fore.YELLOW + f'  Transition {i}: {from_func} ({from_loc}) -> {to_func} ({to_loc}) - {relationship_type}')

    return call_relationships, step_types


def calculate_call_depth(cross_function_steps, step_types):
    """
    Calculate call depth for each function in the call path.

    Args:
        cross_function_steps: List of cross-function steps
        step_types: List of step types (CALL or RETURN)

    Returns:
        tuple: (call_depth, min_depth_func, min_depth, min_depth_func_id)
            - call_depth: Dictionary mapping function identifiers to their call depths
            - min_depth_func: Function with the shallowest (minimum) call depth
            - min_depth: The minimum call depth value
            - min_depth_func_id: The specific function ID with the minimum depth
    """
    if not cross_function_steps:
        return {}, None, 0

    logging.info(Fore.MAGENTA + f'Calculating Call Depth:')

    def create_function_id(point):
        """Create unique function identifier using name and file."""
        return f"{point.functionName}@{point.file}"

    def get_function_name(func_id):
        """Extract function name from function identifier."""
        return func_id.split('@')[0]

    # Initialize call depth for all function positions
    call_depth = {}
    function_name_to_ids = {}  # Maps function names to their unique IDs

    for step in cross_function_steps:
        from_id = create_function_id(step.fromPoint)
        to_id = create_function_id(step.toPoint)

        call_depth[from_id] = 0
        call_depth[to_id] = 0

        # Track function name mappings for later analysis
        from_name = step.fromPoint.functionName
        to_name = step.toPoint.functionName

        if from_name not in function_name_to_ids:
            function_name_to_ids[from_name] = set()
        if to_name not in function_name_to_ids:
            function_name_to_ids[to_name] = set()

        function_name_to_ids[from_name].add(from_id)
        function_name_to_ids[to_name].add(to_id)

    # Track the current depth as we process steps
    current_depth = 0

    # Process steps in sequence to calculate depth
    for i, (step, step_type) in enumerate(zip(cross_function_steps, step_types)):
        from_id = create_function_id(step.fromPoint)
        to_id = create_function_id(step.toPoint)

        if step_type == "CALL":
            # Forward: increase depth
            current_depth += 1
            call_depth[to_id] = current_depth
        else:  # RETURN
            # Backward: decrease depth
            call_depth[from_id] = current_depth
            current_depth -= 1
            call_depth[to_id] = current_depth

    # Find the function with the minimum (shallowest) call depth
    min_depth = float('inf')
    min_depth_func_id = None
    min_depth_func_ids = []

    # First pass: find the minimum depth
    for func_id, depth in call_depth.items():
        if depth < min_depth:
            min_depth = depth

    # Second pass: collect all function IDs with the minimum depth
    for func_id, depth in call_depth.items():
        if depth == min_depth:
            min_depth_func_ids.append(func_id)

    # If multiple function positions have the same minimum depth, prefer the one that appears first
    if len(min_depth_func_ids) > 1:
        logging.warning(Fore.YELLOW + f'Multiple function positions have the same shallowest depth {min_depth}: {min_depth_func_ids}')
        # Use the first one that appears in the steps
        for step in cross_function_steps:
            from_id = create_function_id(step.fromPoint)
            to_id = create_function_id(step.toPoint)
            if from_id in min_depth_func_ids:
                min_depth_func_id = from_id
                break
            if to_id in min_depth_func_ids:
                min_depth_func_id = to_id
                break
        if not min_depth_func_id:
            min_depth_func_id = min_depth_func_ids[0]
    else:
        min_depth_func_id = min_depth_func_ids[0] if min_depth_func_ids else None

    # Convert back to function name for compatibility
    min_depth_func = get_function_name(min_depth_func_id) if min_depth_func_id else None

    if min_depth_func:
        logging.info(Fore.RED + f'Function with shallowest depth: {min_depth_func} (ID: {min_depth_func_id}, Depth: {min_depth})')
    else:
        logging.info(Fore.RED + f'No function found')
        min_depth = 0

    # Log functions grouped by depth, showing both name and position
    depth_categories = {}  # Maps depth to list of function IDs
    for func_id, depth in call_depth.items():
        if depth not in depth_categories:
            depth_categories[depth] = []
        depth_categories[depth].append(func_id)

    # Log functions grouped by depth
    logging.info(Fore.MAGENTA + f'Functions Grouped by Call Depth:')
    for depth in sorted(depth_categories.keys()):
        func_ids = depth_categories[depth]
        depth_label = "Neutral" if depth == 0 else "Forward" if depth > 0 else "Backward"
        if depth == min_depth:
            # Highlight the minimum depth level
            logging.debug(Fore.RED + f'Depth {depth} ({depth_label}) [SHALLOWEST]: {", ".join([get_function_name(fid) for fid in func_ids])}')
            for fid in func_ids:
                logging.debug(Fore.RED + f'  - {fid}')
        else:
            logging.debug(Fore.MAGENTA + f'Depth {depth} ({depth_label}): {", ".join([get_function_name(fid) for fid in func_ids])}')
            for fid in func_ids:
                logging.debug(Fore.MAGENTA + f'  - {fid}')

    # For backward compatibility, also create a simplified call_depth with just function names
    # But warn about potential issues with same-named functions
    simplified_call_depth = {}
    for func_name, func_ids in function_name_to_ids.items():
        if len(func_ids) > 1:
            logging.warning(Fore.YELLOW + f'Function "{func_name}" appears at multiple positions: {func_ids}')
            # Use the minimum depth among all positions of this function
            depths = [call_depth[fid] for fid in func_ids]
            simplified_call_depth[func_name] = min(depths)
            logging.warning(Fore.YELLOW + f'Using minimum depth {min(depths)} for function "{func_name}"')
        else:
            func_id = next(iter(func_ids))
            simplified_call_depth[func_name] = call_depth[func_id]

    return simplified_call_depth, min_depth_func, min_depth, min_depth_func_id


def split_call_path(steps, cross_function_steps, step_types, min_depth_func, min_depth_func_id=None):
    """
    Split the call path into backward, intermediate, and forward parts.

    Args:
        steps: List of all steps
        cross_function_steps: List of cross-function steps
        step_types: List of step types for cross-function steps
        min_depth_func: Function with the shallowest (minimum) call depth
        min_depth_func_id: Specific function ID with the minimum depth

    Returns:
        tuple: (all_backward_steps, all_intermediate_steps, all_true_forward_steps,
                backward_steps, backward_types, forward_steps, forward_types,
                transition_index, all_steps_transition_index)
    """
    if not cross_function_steps or not min_depth_func:
        return [], [], steps, [], [], cross_function_steps, step_types, -1, -1

    logging.info(Fore.CYAN + f'Splitting Call Path at Shallowest Function: {min_depth_func}')

    def create_function_id(point):
        """Create unique function identifier using name and file."""
        return f"{point.functionName}@{point.file}"

    def get_function_name(func_id):
        """Extract function name from function identifier."""
        return func_id.split('@')[0]

    # Use the specific shallowest function ID if provided, otherwise find it
    if min_depth_func_id:
        shallowest_func_id = min_depth_func_id
        logging.info(Fore.CYAN + f'Using provided shallowest function ID: {shallowest_func_id}')
    else:
        # Fallback: find the shallowest function position (legacy behavior)
        shallowest_func_id = None

        # Check all cross-function steps to find the shallowest function position that appears first
        for step in cross_function_steps:
            from_id = create_function_id(step.fromPoint)
            to_id = create_function_id(step.toPoint)

            if (get_function_name(from_id) == min_depth_func):
                shallowest_func_id = from_id
                logging.debug(Fore.CYAN + f'Found shallowest function position: {shallowest_func_id}')
                break
            elif (get_function_name(to_id) == min_depth_func):
                shallowest_func_id = to_id
                logging.debug(Fore.CYAN + f'Found shallowest function position: {shallowest_func_id}')
                break

        if not shallowest_func_id:
            logging.warning(Fore.YELLOW + f'Could not find specific position for shallowest function {min_depth_func}')
            shallowest_func_id = f"{min_depth_func}@unknown"  # Fallback

    # Check if the data flow starts from the shallowest function
    first_step = steps[0] if steps else None
    starts_from_shallowest = (first_step and
                             create_function_id(first_step.fromPoint) == shallowest_func_id)

    if starts_from_shallowest:
        logging.info(Fore.YELLOW + f'Data flow starts from shallowest function position {shallowest_func_id}. No backward path needed.')

        # If data flow starts from shallowest function, there's no backward path
        all_backward_steps = []
        backward_steps = []
        backward_types = []

        # Split the steps into intermediate (within shallowest function) and forward (from shallowest to others)
        all_intermediate_steps = []
        all_true_forward_steps = []
        forward_steps = []
        forward_types = []

        # Find the first cross-function call FROM the specific shallowest function position
        first_cross_call_index = -1
        for i, step in enumerate(steps):
            if (create_function_id(step.fromPoint) == shallowest_func_id and
                not step.sameFunction):
                first_cross_call_index = i
                logging.debug(Fore.GREEN + f'Found first cross-function call from {shallowest_func_id} at step {i+1}: {step.fromPoint.functionName} -> {step.toPoint.functionName}')
                break

        if first_cross_call_index >= 0:
            # Steps before the first cross-function call are intermediate
            all_intermediate_steps = steps[:first_cross_call_index]
            # Steps from the first cross-function call onwards are forward
            all_true_forward_steps = steps[first_cross_call_index:]

            # Also split cross-function steps for consistency
            # Find the corresponding cross-function step
            for i, step in enumerate(cross_function_steps):
                if (create_function_id(step.fromPoint) == shallowest_func_id and
                    not step.sameFunction):
                    forward_steps = cross_function_steps[i:]
                    forward_types = step_types[i:]
                    logging.debug(Fore.GREEN + f'Cross-function forward starts at step {i+1}: {step.fromPoint.functionName} -> {step.toPoint.functionName}')
                    break
        else:
            # If no cross-function call from shallowest function, all steps are intermediate
            all_intermediate_steps = steps
            all_true_forward_steps = []
            forward_steps = []
            forward_types = []

        logging.debug(Fore.CYAN + f'Adjusted split for shallowest-start flow:')
        logging.debug(Fore.CYAN + f'  - Backward steps: {len(all_backward_steps)}')
        logging.debug(Fore.CYAN + f'  - Intermediate steps: {len(all_intermediate_steps)}')
        logging.debug(Fore.CYAN + f'  - Forward steps: {len(all_true_forward_steps)}')

        return (all_backward_steps, all_intermediate_steps, all_true_forward_steps,
                backward_steps, backward_types, forward_steps, forward_types,
                -1, first_cross_call_index)

    # Original logic for cases where data flow doesn't start from shallowest function
    # Find the first return from the shallowest function as the split point
    transition_index = -1 # Initialize to -1 (not found)
    has_found_deepest = False

    # First: Find where the specific shallowest function position first appears (either as source or target)
    deepest_func_first_idx = -1
    for i, step in enumerate(cross_function_steps):
        from_id = create_function_id(step.fromPoint)
        to_id = create_function_id(step.toPoint)

        if (from_id == shallowest_func_id or to_id == shallowest_func_id):
            deepest_func_first_idx = i
            has_found_deepest = True
            # Include the first occurrence in backward part, so the transition is this step
            transition_index = i
            logging.debug(Fore.YELLOW + f'First occurrence of {shallowest_func_id} at step {i+1}')
            logging.debug(Fore.YELLOW + f'Using step {i+1} as split point - this step is backward, subsequent steps are forward')
            break

    # If we couldn't find the shallowest function, there's nothing to split
    if not has_found_deepest:
        logging.warning(Fore.YELLOW + f'Could not find the shallowest function position {shallowest_func_id} in the cross-function steps')
        logging.info(f'Available functions in cross-function steps:')
        for i, step in enumerate(cross_function_steps[:5]):
            from_id = create_function_id(step.fromPoint)
            to_id = create_function_id(step.toPoint)
            logging.info(f'  Step {i+1}: {from_id} -> {to_id}')

    # Now process the split - Split cross_function_steps
    if transition_index >= 0:
        # Backward part: from beginning to the transition point (inclusive)
        backward_steps = cross_function_steps[:transition_index+1]
        backward_types = step_types[:transition_index+1]

        # Forward part: from after the transition point to the end
        forward_steps = cross_function_steps[transition_index+1:]
        forward_types = step_types[transition_index+1:]
    else:
        # If the shallowest function is not found, everything is forward
        backward_steps = []
        backward_types = []
        forward_steps = cross_function_steps
        forward_types = step_types

    # Now also split all steps (including same-function steps)
    # Find the corresponding step in the original steps list
    all_steps_transition_index = -1
    if transition_index >= 0:
        # Find which step in the full steps list corresponds to our transition point
        transition_cross_step = cross_function_steps[transition_index]

        # Find the same step in the full steps list
        for i, step in enumerate(steps):
            if (step.fromPoint.file == transition_cross_step.fromPoint.file and
                step.fromPoint.line == transition_cross_step.fromPoint.line and
                step.toPoint.file == transition_cross_step.toPoint.file and
                step.toPoint.line == transition_cross_step.toPoint.line):
                all_steps_transition_index = i
                logging.debug(Fore.YELLOW + f'Found corresponding transition point in full steps list at step {i+1}')
                break

    # Split all steps based on the transition index
    if all_steps_transition_index >= 0:
        all_backward_steps = steps[:all_steps_transition_index+1]
        all_forward_steps = steps[all_steps_transition_index+1:]

        # Further split the forward portion into intermediate and true forward parts
        all_intermediate_steps = []
        all_true_forward_steps = []

        if all_forward_steps:
            # First find all cross-function calls from the specific shallowest function position to other functions
            shallowest_func_to_other_steps = []
            for i, step in enumerate(all_forward_steps):
                from_id = create_function_id(step.fromPoint)
                to_id = create_function_id(step.toPoint)

                # Check: if this is a cross-function call from the specific shallowest function position to another function
                if from_id == shallowest_func_id and not step.sameFunction:
                    shallowest_func_to_other_steps.append((i, step))
                    logging.debug(Fore.YELLOW + f'Found potential forward start step: {from_id} -> {to_id} at index {i}')

            # If found cross-function calls from the shallowest function, use the last one as the starting point for the forward path
            if shallowest_func_to_other_steps:
                # Get the last such step
                last_transition_idx, last_transition_step = shallowest_func_to_other_steps[-1]

                # Log the last cross-function call found
                from_id = create_function_id(last_transition_step.fromPoint)
                to_id = create_function_id(last_transition_step.toPoint)
                logging.debug(Fore.GREEN + f'Using the LAST cross-function call from {shallowest_func_id} as forward start: {from_id} -> {to_id} at index {last_transition_idx}')

                # Split steps: before this step (including same-function steps) are intermediate, this step and after are forward
                all_intermediate_steps = all_forward_steps[:last_transition_idx]
                all_true_forward_steps = all_forward_steps[last_transition_idx:]

                # Check if there are steps from the shallowest function in the intermediate part
                for i, step in enumerate(all_intermediate_steps):
                    from_id = create_function_id(step.fromPoint)
                    to_id = create_function_id(step.toPoint)
                    if from_id == shallowest_func_id and step.sameFunction:
                        logging.debug(Fore.YELLOW + f'Identified intermediate step (within {shallowest_func_id}): {from_id} -> {to_id}')
                    else:
                        logging.debug(Fore.YELLOW + f'Identified extra intermediate step: {from_id} -> {to_id}')

                # Log the first step in the forward part
                if all_true_forward_steps:
                    from_id = create_function_id(all_true_forward_steps[0].fromPoint)
                    to_id = create_function_id(all_true_forward_steps[0].toPoint)
                    logging.debug(Fore.GREEN + f'First true forward step is: {from_id} -> {to_id}')
            else:
                # If no cross-function call found, check if there are same-function steps within the shallowest function
                for step in all_forward_steps:
                    from_id = create_function_id(step.fromPoint)
                    to_id = create_function_id(step.toPoint)

                    # Check: if this is a same-function step within the specific shallowest function position, it's intermediate
                    if from_id == shallowest_func_id and step.sameFunction:
                        all_intermediate_steps.append(step)
                        logging.debug(Fore.YELLOW + f'Identified intermediate step (within {shallowest_func_id}): {from_id} -> {to_id}')
                    # No cross-function call found, other steps are also classified as intermediate
                    else:
                        all_intermediate_steps.append(step)
                        logging.debug(Fore.YELLOW + f'Identified extra intermediate step: {from_id} -> {to_id}')

                # If no cross-function call from the shallowest function found, all steps are considered intermediate
                logging.debug(Fore.YELLOW + f'No cross-function call from {shallowest_func_id} found, classifying all as intermediate')

        logging.debug(Fore.CYAN + f'Further splitting forward steps:')
        logging.debug(Fore.CYAN + f'  - Intermediate steps: {len(all_intermediate_steps)}')
        logging.debug(Fore.CYAN + f'  - True forward steps (after last cross function call from {shallowest_func_id}): {len(all_true_forward_steps)}')
    else:
        all_backward_steps = []
        all_intermediate_steps = []
        all_true_forward_steps = []
        # If no split point found, handle special cases
        if min_depth_func:
            # If shallowest function exists but not found, check if there are any steps from it
            shallowest_func_steps = []
            other_steps = []

            for step in steps:
                from_id = create_function_id(step.fromPoint)
                to_id = create_function_id(step.toPoint)
                if from_id == shallowest_func_id or to_id == shallowest_func_id:
                    shallowest_func_steps.append(step)
                else:
                    other_steps.append(step)

            # If there are steps from the shallowest function, consider them intermediate, others forward
            if shallowest_func_steps:
                all_intermediate_steps = shallowest_func_steps
                all_true_forward_steps = other_steps
            else:
                # No steps from the shallowest function, consider all as forward
                all_true_forward_steps = steps
        else:
            # No shallowest function, all steps are considered forward
            all_true_forward_steps = steps

    return (all_backward_steps, all_intermediate_steps, all_true_forward_steps,
            backward_steps, backward_types, forward_steps, forward_types,
            transition_index, all_steps_transition_index)
