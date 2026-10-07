"""
Tools for source backward flow analysis with constraint extraction
"""
import os
from typing import List, Dict, Any, Optional, Tuple
import logging
from colorama import Fore

from AdvancedTools.ConstraintAnalysis.constraint_extractor_interface import ConstraintExtractor
from AdvancedTools.ConstraintAnalysis.constraint_extractor_core import ProgramPoint
from AdvancedTools.ConstraintAnalysis.constraint_formatter import format_constraints_natural_language
from AdvancedTools.CodeSearch.symbol_lookup import get_function_start_line_from_csv
from ..utils.code_utils import is_function_parameter_position


# =============================================================================
# Helper Functions
# =============================================================================

def _get_function_start_line(func_name: str, file_path: str, extractor: ConstraintExtractor,
                              log_prefix: str = "[BACKWARD]") -> Optional[int]:
    """
    Get function start line from database or CSV.

    Args:
        func_name: Name of the function
        file_path: Path to the source file
        extractor: ConstraintExtractor instance with cfg_db
        log_prefix: Prefix for log messages

    Returns:
        Function start line number, or None if not found
    """
    func_start = None

    # Try database first
    if extractor.cfg_db:
        try:
            functions = extractor.cfg_db.get_function_info(func_name, file_path)
            if functions:
                func_start = int(functions[0][2])
                logging.debug(f"{log_prefix} Found function start line from database: {func_name} starts at {func_start}")
        except Exception as e:
            logging.debug(f"Error getting function start line: {e}")

    # Fall back to CSV
    if func_start is None:
        logging.debug(f"{log_prefix} Trying to get function start line from CSV for {func_name}")
        func_start = get_function_start_line_from_csv(func_name, file_path)
        if func_start:
            logging.debug(f"{log_prefix} Found function start line from CSV: {func_name} starts at {func_start}")

    return func_start


def _collect_points_by_function(context) -> Dict[str, List[Tuple]]:
    """
    Collect all points from backward flow steps and group by function.

    Args:
        context: SourceBackwardFlowContext with steps

    Returns:
        Dict mapping function_name -> [(step_idx, point_type, point)]
    """
    function_points = {}

    for step_idx, step in enumerate(context.steps):
        # Process fromPoint - skip if it's a function parameter position
        if not is_function_parameter_position(step.fromPoint):
            func_name = step.fromPoint.functionName
            if func_name not in function_points:
                function_points[func_name] = []
            function_points[func_name].append((step_idx, 'from', step.fromPoint))
        else:
            logging.debug(f"Skipping function parameter position: {step.fromPoint.functionName}:{step.fromPoint.line}")

        # Process toPoint - skip if it's a function parameter position
        if not is_function_parameter_position(step.toPoint):
            func_name = step.toPoint.functionName
            if func_name not in function_points:
                function_points[func_name] = []
            function_points[func_name].append((step_idx, 'to', step.toPoint))
        else:
            logging.debug(f"Skipping function parameter position: {step.toPoint.functionName}:{step.toPoint.line}")

    return function_points


def _merge_identical_points(target_points: List, point_info: List,
                            func_name: str, file_path: str,
                            extractor: ConstraintExtractor) -> Tuple[List, List]:
    """
    Merge consecutive identical points in the same basic block.

    When multiple taint flow steps pass through the same program location,
    we merge them into a single point for constraint analysis.

    Args:
        target_points: List of ProgramPoint objects
        point_info: List of point info dictionaries
        func_name: Function name
        file_path: File path
        extractor: ConstraintExtractor instance

    Returns:
        Tuple of (merged_target_points, merged_point_info)
    """
    if len(target_points) <= 1:
        return target_points, point_info

    # Get function start line for block lookup
    func_start = _get_function_start_line(func_name, file_path, extractor)
    if not func_start:
        return target_points, point_info

    # Get function CFG
    function_cfg = extractor.cfg_manager.get_cached_function(func_name, file_path, func_start)
    if not function_cfg:
        return target_points, point_info

    # Find which block each point belongs to
    point_blocks = []
    for point in target_points:
        block = None
        for bb in function_cfg.basic_blocks:
            if extractor.core_extractor._program_point_overlaps_with_block(point, bb):
                if not extractor.core_extractor._is_reversed_block(bb):
                    block = bb
                    break
        point_blocks.append(block)

    # Merge consecutive points in the same block
    new_target_points = []
    new_point_info = []
    merged_indices = set()

    i = 0
    while i < len(target_points):
        if i in merged_indices:
            i += 1
            continue

        current_block = point_blocks[i]
        merged_count = 1

        # Look for consecutive identical points
        j = i + 1
        while j < len(target_points):
            if point_blocks[j] == current_block and current_block is not None:
                merged_indices.add(j)
                merged_count += 1
                j += 1
            else:
                break

        # Add the merged point
        new_target_points.append(target_points[i])
        info = point_info[i].copy()
        if merged_count > 1:
            info['merged_count'] = merged_count
        new_point_info.append(info)

        i += 1

    logging.debug(f"After merging: {len(target_points)} points reduced to {len(new_target_points)} points")
    return new_target_points, new_point_info


def _format_constraint_results(results_by_function: Dict) -> Tuple[str, Optional[str]]:
    """
    Format constraint analysis results into readable output.

    Args:
        results_by_function: Dict mapping function_name -> analysis result

    Returns:
        Tuple of (full_analysis_output, constraint_text_for_prompt)
    """
    output_lines = ["\n=== [BACKWARD] Constraint Analysis Summary ===\n"]

    for func_name, result in results_by_function.items():
        output_lines.append(f"Function: {func_name}")

        # Show points in this function
        output_lines.append(f"  Points in execution order:")
        for point in result['points']:
            # Format location with column info if available
            location = f"Line {point['line']}"
            if point.get('start_column') is not None and point.get('end_column') is not None:
                location = f"Line {point['line']}:{point['start_column']}-{point['end_column']}"

            # Check if this is a merged point
            if point.get('merged_count', 1) > 1:
                location = f"{location} (merged {point['merged_count']} identical points)"

            output_lines.append(f"    Step {point['step']}: {location} ({point['point_type']}) - {point['variable']}")
            output_lines.append(f"      Code: {point['line_code']}")

        if result['success']:
            if len(result['points']) > 1:
                output_lines.append(f"\n  Path analysis: {result['paths_found']} paths found through all {len(result['points'])} points")
            else:
                output_lines.append(f"\n  Path analysis: {result['paths_found']} paths found")

            # Show constraints in natural language
            if result['dominator_constraints']:
                output_lines.append("\n  Branch conditions that MUST be taken to reach this code:")
                output_lines.extend(format_constraints_natural_language(result['dominator_constraints'], "must-satisfy"))
            else:
                if len(result['points']) > 1 and result['paths_found'] > 0:
                    output_lines.append("\n  No specific branch requirements - multiple paths exist with different conditions")
                else:
                    if result.get('optional_constraints'):
                        output_lines.append("\n  No mandatory branch requirements - different paths take different branches")
                    else:
                        output_lines.append("\n  No branch decisions needed - straight-line execution path")

            # Show optional constraints for reference
            if result.get('optional_constraints'):
                shown = result['optional_constraints'][:3]
                if shown:
                    output_lines.append("\n  Branch choices that vary across paths:")
                    output_lines.extend(format_constraints_natural_language(shown, "optional"))
                    if len(result['optional_constraints']) > 3:
                        output_lines.append(f"    - ... and {len(result['optional_constraints']) - 3} more")
        else:
            output_lines.append(f"  Analysis failed: {result.get('error', 'Unknown error')}")

        output_lines.append("")  # Empty line between functions

    # Generate full analysis output
    full_output = '\n'.join(output_lines)

    # Generate constraint text for prompt
    constraint_lines = []
    constraint_lines.append("=== Control Flow Constraints ===")
    constraint_lines.append("")

    has_constraints = False

    for func_name, result in results_by_function.items():
        if result['success'] and result['dominator_constraints']:
            has_constraints = True
            constraint_lines.append(f"Function {func_name}:")
            constraint_lines.append("  Branch conditions that MUST be taken to reach this code:")
            constraint_lines.extend(format_constraints_natural_language(result['dominator_constraints'], "must-satisfy"))
            constraint_lines.append("")

    constraint_text_for_prompt = '\n'.join(constraint_lines) if has_constraints else None

    return (full_output, constraint_text_for_prompt)


def extract_constraints_for_backward_flow(context, project_name: str = "default",
                                          cache_dir: Optional[str] = None) -> Tuple[str, Optional[str]]:
    """
    Extract constraints for all relevant points in a backward flow analysis.

    For multiple points in the same function, finds paths through all points
    and computes cross-path dominator constraints.

    Args:
        context: SourceBackwardFlowContext with steps
        project_name: Project name for caching
        cache_dir: Optional cache directory

    Returns:
        Tuple of (full_analysis_output, formatted_constraint_text_for_prompt)
    """
    if not context or not context.steps:
        return ("No steps available for constraint analysis", None)

    # Initialize constraint extractor
    try:
        extractor = ConstraintExtractor(project_name=project_name, cache_dir=cache_dir)
    except Exception as e:
        logging.info(f"Failed to initialize ConstraintExtractor: {e}")
        return (f"Constraint analysis initialization failed: {e}", None)

    # Step 1: Collect all points and group by function
    function_points = _collect_points_by_function(context)

    # Step 2: For each function, analyze constraints
    results_by_function = {}

    for func_name, points_list in function_points.items():
        # Sort by step index to maintain time order
        points_list.sort(key=lambda x: x[0])

        # Get function info from first point
        first_point = points_list[0][2]
        file_path = first_point.file

        # Resolve file path
        if not os.path.isabs(file_path):
            ai_analysis_dir = os.environ.get('AI_ANALYSIS_DIR', '')
            if ai_analysis_dir:
                possible_path = os.path.join(ai_analysis_dir, 'sourcecode', file_path)
                if os.path.exists(possible_path):
                    file_path = possible_path

        # Create ProgramPoint objects and filter
        target_points = []
        point_info = []

        for step_idx, point_type, point in points_list:
            # Check that point is within function body
            if extractor.is_point_in_function_body(point.functionName, file_path, point.line):
                # Create program point with column info if available
                if hasattr(point, 'startColumn') and point.startColumn is not None and \
                   hasattr(point, 'endColumn') and point.endColumn is not None:
                    program_point = ProgramPoint.from_location(
                        start_line=point.line,
                        start_column=point.startColumn,
                        end_line=point.line,
                        end_column=point.endColumn
                    )
                else:
                    program_point = ProgramPoint.from_line(point.line)

                target_points.append(program_point)
                point_info.append({
                    'step': step_idx + 1,
                    'point_type': point_type,
                    'line': point.line,
                    'variable': point.variable,
                    'line_code': point.lineCode.strip(),
                    'start_column': getattr(point, 'startColumn', None),
                    'end_column': getattr(point, 'endColumn', None)
                })
            else:
                logging.debug(f"Filtering out declaration line point: {func_name}:{point.line}")

        # Skip this function if no valid points remain
        if not target_points:
            logging.debug(f"No valid body points for function {func_name}, skipping")
            continue

        # Merge adjacent identical points
        if len(target_points) > 1:
            try:
                target_points, point_info = _merge_identical_points(
                    target_points, point_info, func_name, file_path, extractor
                )
            except Exception as e:
                logging.debug(f"Error during point merging: {e}")

        # Get function start line
        func_start = _get_function_start_line(func_name, file_path, extractor)
        if func_start is None:
            logging.error(f"[BACKWARD] Cannot find function start line for {func_name}. Skipping.")
            results_by_function[func_name] = {
                'success': False,
                'points': point_info,
                'error': 'Function not found in database or CSV'
            }
            continue

        # Use the new interface method for constraint analysis
        try:
            result = extractor.extract_constraints_for_points(
                target_points=target_points,
                function_name=func_name,
                file_path=file_path,
                function_start_line=func_start,
                verbose=False
            )

            results_by_function[func_name] = {
                'success': result['success'],
                'points': point_info,
                'paths_found': result.get('paths_found', 0),
                'dominator_constraints': result.get('dominator_constraints', []),
                'optional_constraints': result.get('optional_constraints', []),
                'error': result.get('error')
            }
        except Exception as e:
            logging.error(f"[BACKWARD] Constraint analysis failed for {func_name}: {e}")
            results_by_function[func_name] = {
                'success': False,
                'points': point_info,
                'error': str(e)
            }

    # Format and return results
    return _format_constraint_results(results_by_function)


# =============================================================================
# Flow Analysis Functions
# =============================================================================

def analyze_flow_path(context):
    """
    Analyze the flow path and organize points by:
    1. Time sequence (execution order)
    2. Function grouping

    Args:
        context: SourceBackwardFlowContext with steps

    Returns:
        tuple: (time_ordered_points, points_by_function)
            - time_ordered_points: List of points in execution order
            - points_by_function: Dict mapping function names to their points
    """
    time_ordered_points = []
    points_by_function = {}
    seen_points = set()  # To avoid duplicates

    # Process steps in reverse order (since backward flow is reversed)
    for step in reversed(context.steps):
        # Process toPoint first (execution flows from to -> from in backward analysis)
        for point in [step.toPoint, step.fromPoint]:
            # Create unique identifier for the point
            point_id = (point.functionName, point.line, point.variable)

            # Skip if we've already processed this exact point
            if point_id not in seen_points:
                seen_points.add(point_id)

                # Add to time-ordered list
                point_info = {
                    'function': point.functionName,
                    'line': point.line,
                    'variable': point.variable,
                    'code': point.lineCode.strip(),
                    'file': point.file
                }
                time_ordered_points.append(point_info)

                # Add to function grouping
                if point.functionName not in points_by_function:
                    points_by_function[point.functionName] = []
                points_by_function[point.functionName].append(point_info)

    return time_ordered_points, points_by_function


def format_flow_summary(time_ordered_points, points_by_function):
    """
    Format a human-readable summary of the flow path.

    Args:
        time_ordered_points: List of points in execution order
        points_by_function: Dict mapping function names to their points

    Returns:
        str: Formatted summary
    """
    lines = []

    # Time sequence summary
    lines.append("=== Execution Flow Time Sequence ===")
    sequence_parts = []
    for i, point in enumerate(time_ordered_points):
        func_name = point['function']
        line_num = point['line']
        func_abbrev = func_name[0].upper() if len(func_name) > 0 else 'X'
        point_label = f"{func_abbrev}{line_num}"
        sequence_parts.append(point_label)

    lines.append(" → ".join(sequence_parts))
    lines.append("")

    # Function grouping summary
    lines.append("=== Points Grouped by Function ===")
    for func_name, points in sorted(points_by_function.items()):
        point_lines = [f"Line {p['line']}" for p in points]
        lines.append(f"{func_name}: [{', '.join(point_lines)}]")

    lines.append("")

    # Detailed point information
    lines.append("=== Detailed Point Information ===")
    for func_name, points in sorted(points_by_function.items()):
        lines.append(f"\nFunction: {func_name}")
        for point in points:
            lines.append(f"  Line {point['line']}: {point['code']}")

    return '\n'.join(lines)


# =============================================================================
# Main Entry Point
# =============================================================================

def extract_and_set_constraints(machine):
    """
    Extract constraints for the backward flow and set them in the machine state.

    This function analyzes the flow path, organizes it by function and time sequence,
    then extracts static constraint analysis results for the data flow path.

    When pre-computed merged constraints are available (from variant merging),
    they are used directly instead of re-extracting from single-variant steps.

    Args:
        machine: State machine instance with context and configuration
    """
    # Use pre-computed merged constraints when available (only for multi-variant units)
    merged = getattr(machine, 'merged_constraints', None)
    if merged and getattr(machine, 'has_propagation_variants', False):
        from ..utils.variant_description import format_merged_constraints
        formatted = format_merged_constraints(merged)
        if formatted is not None:
            machine.constraint_text_for_prompt = formatted
            logging.info(Fore.CYAN + '[BACKWARD] Using pre-computed merged constraints from variant analysis')
        else:
            # Merged constraints exist but are empty — fall through to independent extraction
            merged = None
    else:
        # Single-variant or no merged constraints — ensure independent extraction runs
        merged = None

    try:
        # First analyze the flow path
        time_ordered_points, points_by_function = analyze_flow_path(machine.context)

        # Store the analysis results in machine for reference
        machine.flow_time_sequence = time_ordered_points
        machine.flow_points_by_function = points_by_function

        # Create and store formatted summary
        machine.flow_summary = format_flow_summary(time_ordered_points, points_by_function)

        # Log the flow analysis
        logging.info(Fore.CYAN + f'Flow analysis: {len(time_ordered_points)} points across {len(points_by_function)} functions')
        for func_name, points in points_by_function.items():
            logging.info(f'  {func_name}: {len(points)} points')

        # Optionally log the full flow summary
        logging.info(Fore.GREEN + f'Flow Summary:\n{machine.flow_summary}')

        # Get project name and cache dir from context if available
        project_name = getattr(machine, 'project_name', 'default')
        cache_dir = getattr(machine, 'cache_dir', None)

        # Skip independent constraint extraction if merged constraints were already set
        if not merged:
            # Use the new constraint analysis function
            full_analysis, constraint_text_for_prompt = extract_constraints_for_backward_flow(
                machine.context,
                project_name=project_name,
                cache_dir=cache_dir
            )

            machine.constraint_analysis = full_analysis
            machine.constraint_text_for_prompt = constraint_text_for_prompt

            # Log summary at INFO level
            num_functions = len(points_by_function)
            has_constraints = constraint_text_for_prompt is not None
            logging.info(Fore.CYAN + f'[BACKWARD] Constraint analysis completed: {num_functions} functions analyzed, constraints found: {has_constraints}')
        else:
            machine.constraint_analysis = "Using pre-computed merged constraints"
            logging.info(Fore.CYAN + f'[BACKWARD] Skipped independent constraint extraction (using merged constraints)')

        # Preload macro definitions using use-def relationship
        try:
            from AdvancedTools.CodeSearch.macro_preloader import extract_and_format_macros_for_prompt
            macros, macro_text_for_prompt = extract_and_format_macros_for_prompt(
                machine.context,
                cache_dir=cache_dir
            )
            machine.preloaded_macros = macros
            machine.macro_text_for_prompt = macro_text_for_prompt
            # Add preloaded macros to definition_pool for subsequent use-site extraction
            if not hasattr(machine, 'definition_pool'):
                machine.definition_pool = []
            for name, info in macros.items():
                machine.definition_pool.append({
                    'file_path': info.get('file_path', ''),
                    'start_line': info.get('start_line', 0),
                    'end_line': info.get('start_line', 0),
                    'code': info.get('body', '')
                })
            logging.info(Fore.CYAN + f'[BACKWARD] Macro preload completed: {len(macros)} macros found via use-def')
        except Exception as e:
            logging.debug(f"Macro preload failed (optional): {e}")
            machine.preloaded_macros = {}
            machine.macro_text_for_prompt = None

    except Exception as e:
        logging.info(f"Constraint analysis failed: {e}")
        import traceback
        traceback.print_exc()
        machine.constraint_analysis = "Constraint analysis unavailable due to error."
        machine.constraint_text_for_prompt = None
        machine.flow_time_sequence = []
        machine.flow_points_by_function = {}
        machine.flow_summary = "Flow analysis unavailable due to error."
