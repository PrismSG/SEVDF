"""
Tools for forward-to-sink path analysis with constraint extraction.

This module provides constraint extraction capabilities for forward data flow analysis,
similar to the backward analysis but traversing paths from source to sink.
"""

import logging
from typing import List, Dict, Any, Optional, Tuple
import os

# Import constraint extractor if available
try:
    from AdvancedTools.ConstraintAnalysis.constraint_extractor_interface import ConstraintExtractor
    from AdvancedTools.ConstraintAnalysis.constraint_extractor_core import ProgramPoint
    CONSTRAINT_EXTRACTOR_AVAILABLE = True
except ImportError:
    CONSTRAINT_EXTRACTOR_AVAILABLE = False
    logging.debug(f"[FORWARD] ConstraintExtractor not available. Constraint analysis will be skipped.")

from .forward_to_sink_context import (
    ForwardToSinkFlowContext, Step, Point
)

from AdvancedTools.ConstraintAnalysis.constraint_formatter import format_constraints_natural_language
from ..utils.code_utils import is_function_parameter_position

try:
    from AdvancedTools.CodeSearch.symbol_lookup import get_function_start_line_from_csv
except ImportError:
    logging.warning("SymbolLookup not available. Function start line lookup will use database only.")
    get_function_start_line_from_csv = None


def extract_constraints_for_forward_flow(
    context: ForwardToSinkFlowContext, 
    project_name: str = "default",
    cache_dir: Optional[str] = None,
    verbose: bool = True
) -> Tuple[str, Optional[str]]:
    """
    Extract path-based constraints for forward flow analysis.
    
    This function analyzes the forward flow path and extracts constraints
    that must be satisfied for the data to flow from source to sink.
    
    Args:
        context: ForwardToSinkFlowContext containing the flow steps
        project_name: Name of the project being analyzed
        cache_dir: Cache directory for analysis
        verbose: Whether to output detailed logs
        
    Returns:
        A tuple of (full_analysis, constraint_text_for_prompt) where:
        - full_analysis: Complete constraint analysis output
        - constraint_text_for_prompt: Natural language formatted constraints for LLM prompts, or None
    """
    if not CONSTRAINT_EXTRACTOR_AVAILABLE:
        return "Constraint extraction not available (ConstraintExtractor module not found)", None
    
    try:
        # Initialize constraint extractor
        logging.debug(f"[FORWARD] Initializing ConstraintExtractor with project_name={project_name}, cache_dir={cache_dir}")
        extractor = ConstraintExtractor(
            project_name=project_name,
            cache_dir=cache_dir
        )
        logging.debug(f"[FORWARD] ConstraintExtractor initialized successfully")
        
        # Log extractor state
        if hasattr(extractor, 'cfg_db'):
            logging.debug(f"[FORWARD] Extractor has cfg_db: {extractor.cfg_db is not None}")
            if extractor.cfg_db:
                logging.debug(f"[FORWARD] cfg_db type: {type(extractor.cfg_db)}")
        else:
            logging.debug(f"[FORWARD] Extractor has no cfg_db attribute")
            
        if hasattr(extractor, 'cfg_manager'):
            logging.debug(f"[FORWARD] Extractor has cfg_manager: {extractor.cfg_manager is not None}")
            if extractor.cfg_manager:
                logging.debug(f"[FORWARD] cfg_manager type: {type(extractor.cfg_manager)}")
                logging.debug(f"[FORWARD] cfg_manager cache_dir: {extractor.cfg_manager.cache_dir}")
        else:
            logging.debug(f"[FORWARD] Extractor has no cfg_manager attribute")
        
        # Step 1: Collect all points and group by function (following backward analysis pattern)
        function_points = {}  # function_name -> [(step_idx, point_type, point)]
        
        for step_idx, step in enumerate(context.steps):
            # Process fromPoint - skip if it's a function parameter position
            if not is_function_parameter_position(step.fromPoint):
                func_name = step.fromPoint.functionName
                if func_name not in function_points:
                    function_points[func_name] = []
                function_points[func_name].append((step.flowstep, 'from', step.fromPoint))
            else:
                logging.debug(f"[FORWARD] Skipping function parameter position: {step.fromPoint.functionName}:{step.fromPoint.line}")
            
            # Process toPoint - skip if it's a function parameter position
            if not is_function_parameter_position(step.toPoint):
                to_func = step.toPoint.functionName
                if to_func not in function_points:
                    function_points[to_func] = []
                function_points[to_func].append((step.flowstep, 'to', step.toPoint))
            else:
                logging.debug(f"[FORWARD] Skipping function parameter position: {step.toPoint.functionName}:{step.toPoint.line}")
        
        # Step 2: Analyze constraints for each function
        results_by_function = {}
        
        for func_name, points_list in function_points.items():
            # Sort by step index to maintain flow order
            points_list.sort(key=lambda x: x[0])
            
            # Get function info from first point
            if not points_list:
                logging.debug(f"[FORWARD] No points in function {func_name}, skipping")
                continue
                
            first_point = points_list[0][2]
            file_path = first_point.file
            
            # Resolve file path (same as backward)
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
                # Check that point is within function body (same as backward)
                if extractor.is_point_in_function_body(func_name, file_path, point.line):
                    # Create program point with column info if available
                    if hasattr(point, 'startColumn') and point.startColumn is not None and hasattr(point, 'endColumn') and point.endColumn is not None:
                        program_point = ProgramPoint.from_location(
                            start_line=point.line,
                            start_column=point.startColumn,
                            end_line=point.line,
                            end_column=point.endColumn
                        )
                        logging.debug(f"[FORWARD] Created precise ProgramPoint for {func_name}:{point.line}:{point.startColumn}-{point.endColumn}")
                    else:
                        program_point = ProgramPoint.from_line(point.line)
                        logging.debug(f"[FORWARD] Created line-based ProgramPoint for {func_name}:{point.line} (no column info)")
                    
                    target_points.append(program_point)
                    point_info.append({
                        'step': step_idx,
                        'point_type': point_type,
                        'line': point.line,
                        'variable': point.variable,
                        'line_code': point.lineCode.strip(),
                        'start_column': getattr(point, 'startColumn', None),
                        'end_column': getattr(point, 'endColumn', None)
                    })
                else:
                    logging.debug(f"[FORWARD] Filtering out declaration/non-body line point: {func_name}:{point.line}")
            
            # Skip this function if no valid points remain
            if not target_points:
                logging.debug(f"[FORWARD] No valid body points for function {func_name}, skipping")
                continue
            
            try:
                logging.debug(f"[FORWARD] Analyzing function {func_name} in file {file_path}")
                
                # Get function start line from database if available
                func_start = None
                if hasattr(extractor, 'cfg_db') and extractor.cfg_db:
                    try:
                        logging.debug(f"[FORWARD] Looking up function {func_name} in database...")
                        functions = extractor.cfg_db.get_function_info(func_name, file_path)
                        if functions:
                            func_start = int(functions[0][2])
                            logging.debug(f"[FORWARD] Found function start line from database: {func_name} starts at {func_start}")
                            logging.debug(f"[FORWARD] Function info: {functions[0]}")
                        else:
                            logging.debug(f"[FORWARD] Function {func_name} not found in database")
                    except Exception as e:
                        logging.debug(f"[FORWARD] Error getting function start line from database: {e}")
                else:
                    logging.debug(f"[FORWARD] No cfg_db available for function lookup")
                    if hasattr(extractor, 'cfg_db'):
                        logging.debug(f"[FORWARD] extractor.cfg_db = {extractor.cfg_db}")
                    else:
                        logging.debug(f"[FORWARD] extractor has no cfg_db attribute")
                
                if func_start is None and get_function_start_line_from_csv:
                    # Try to get from Function CSV
                    logging.debug(f"[FORWARD] Trying to get function start line from Function CSV for {func_name}")
                    func_start = get_function_start_line_from_csv(func_name, file_path)
                    if func_start:
                        logging.debug(f"[FORWARD] Found function start line from CSV: {func_name} starts at {func_start}")
                
                if func_start is None:
                    logging.error(f"[FORWARD] Cannot find function start line for {func_name} in database or CSV. Skipping.")
                    results_by_function[func_name] = {
                        'success': False,
                        'points': point_info,
                        'error': 'Function not found in database or CSV'
                    }
                    continue
                
                logging.debug(f"[FORWARD] Processing {len(target_points)} points for {func_name} after filtering")
                
                # IMPORTANT: For forward analysis, REVERSE everything first
                # This allows us to use the same backward traversal logic
                logging.debug(f"[FORWARD] Before reversal: {[p.start_line for p in target_points]}")
                target_points.reverse()
                point_info.reverse()
                logging.debug(f"[FORWARD] After reversal: {[p.start_line for p in target_points]}")
                
                # Step 2.5: Merge adjacent identical points
                ENABLE_MERGING = True
                
                if ENABLE_MERGING and len(target_points) > 1:
                    # Check for consecutive IDENTICAL points that can be merged
                    merged_indices = set()
                    merged_groups = []  # List of (start_idx, end_idx) for merged groups
                    
                    i = 0
                    while i < len(target_points) - 1:
                        if i in merged_indices:
                            i += 1
                            continue
                            
                        # Check if current and next point are identical (same line and position)
                        current_point = target_points[i]
                        next_point = target_points[i + 1]
                        
                        if (current_point.start_line == next_point.start_line and 
                            current_point.start_column == next_point.start_column and
                            current_point.end_column == next_point.end_column):
                            # Start a merge group of identical points
                            start_idx = i
                            end_idx = i + 1
                            
                            # Continue merging while consecutive points are identical
                            while end_idx < len(target_points) - 1:
                                next_point = target_points[end_idx + 1]
                                if (current_point.start_line == next_point.start_line and 
                                    current_point.start_column == next_point.start_column and
                                    current_point.end_column == next_point.end_column):
                                    end_idx += 1
                                else:
                                    break
                            
                            # Log the merge
                            logging.debug(f"[FORWARD] Merging {end_idx - start_idx + 1} identical points at line {current_point.start_line}")
                            
                            # Mark all indices as merged
                            for idx in range(start_idx, end_idx + 1):
                                merged_indices.add(idx)
                            merged_groups.append((start_idx, end_idx))
                            
                            i = end_idx + 1
                        else:
                            i += 1
                    
                    # Create merged target points
                    if merged_groups:
                        new_target_points = []
                        new_point_info = []
                        
                        i = 0
                        for start_idx, end_idx in merged_groups:
                            # Add any unmerged points before this group
                            while i < start_idx:
                                if i not in merged_indices:
                                    new_target_points.append(target_points[i])
                                    new_point_info.append(point_info[i])
                                i += 1
                            
                            # Add the merged point (use the first point of the group)
                            new_target_points.append(target_points[start_idx])
                            # Merge point info - collect all merged steps
                            merged_info = point_info[start_idx].copy()
                            merged_info['merged_count'] = end_idx - start_idx + 1
                            # Collect all step numbers that were merged
                            merged_steps = []
                            for idx in range(start_idx, end_idx + 1):
                                merged_steps.append(point_info[idx]['step'])
                            merged_info['merged_steps'] = merged_steps
                            new_point_info.append(merged_info)
                            
                            i = end_idx + 1
                        
                        # Add any remaining unmerged points
                        while i < len(target_points):
                            if i not in merged_indices:
                                new_target_points.append(target_points[i])
                                new_point_info.append(point_info[i])
                            i += 1
                        
                        logging.debug(f"[FORWARD] After merging: {len(target_points)} points reduced to {len(new_target_points)} points")
                        target_points = new_target_points
                        point_info = new_point_info
                
                # Now we can use the exact same logic as backward analysis
                # since we already reversed the points
                if len(target_points) == 1:
                    # Single point - just analyze constraints to reach it
                    logging.debug(f"[FORWARD] Single point analysis: {func_name} @ {file_path}:{func_start}, target: {target_points[0].start_line}")
                    
                    # Log CFG manager state
                    if hasattr(extractor, 'cfg_manager'):
                        # Check if cached CFG exists
                        has_cached = extractor.cfg_manager.has_cached_cfg(func_name, file_path, func_start)
                        logging.debug(f"[FORWARD] CFG cached: {has_cached}")
                    else:
                        logging.debug(f"[FORWARD] No cfg_manager attribute in extractor")
                    
                    paths, all_constraints = extractor.core_extractor.extract_path_constraints_from_cached_cfg(
                        function_name=func_name,
                        file_path=file_path,
                        start_line=func_start,
                        target_program_points=target_points,
                        required_program_points=[],
                        verbose=verbose
                    )
                else:
                    # Multiple points - for backward traversal after reversal:
                    # - First point (index 0) is the target (end of forward flow)
                    # - Rest are required waypoints in reverse order
                    final_target = [target_points[0]]  # First point after reversal is the end of forward flow
                    required_points = target_points[1:]  # Rest are waypoints
                    
                    all_points = [final_target[0]] + required_points
                    forward_order = list(reversed([p.start_line for p in all_points]))
                    logging.debug(f"[FORWARD] Multi-point: {func_name}, {len(target_points)} points, flow: {' -> '.join(map(str, forward_order))}")
                    
                    # Log CFG manager state
                    if hasattr(extractor, 'cfg_manager'):
                        # Check if cached CFG exists
                        has_cached = extractor.cfg_manager.has_cached_cfg(func_name, file_path, func_start)
                        logging.debug(f"[FORWARD] CFG cached: {has_cached}")
                    else:
                        logging.debug(f"[FORWARD] No cfg_manager attribute in extractor")
                    
                    paths, all_constraints = extractor.core_extractor.extract_path_constraints_from_cached_cfg(
                        function_name=func_name,
                        file_path=file_path,
                        start_line=func_start,
                        target_program_points=final_target,
                        required_program_points=required_points,
                        verbose=verbose
                    )
                
                if paths:
                    logging.debug(f"[FORWARD] Found {len(paths)} paths for {func_name}")
                    logging.debug(f"[FORWARD] Path extraction successful")
                    # Extract constraint information
                    dominator_constraints = []
                    optional_constraints = []
                    
                    if all_constraints and isinstance(all_constraints[0], dict):
                        constraint_dict = all_constraints[0]
                        dominator_constraints = constraint_dict.get('dominator_constraints', [])
                        optional_constraints = constraint_dict.get('optional_constraints', [])
                        logging.debug(f"[FORWARD] Extracted {len(dominator_constraints)} dominator constraints and {len(optional_constraints)} optional constraints")
                    
                    # Reverse point_info back for display in forward order
                    display_point_info = []
                    for p in reversed(point_info):
                        p_copy = p.copy()
                        # Also reverse the merged_steps array if present
                        if 'merged_steps' in p_copy:
                            p_copy['merged_steps'] = list(reversed(p_copy['merged_steps']))
                        display_point_info.append(p_copy)
                    
                    results_by_function[func_name] = {
                        'success': True,
                        'points': display_point_info,
                        'paths_found': len(paths),
                        'dominator_constraints': dominator_constraints,
                        'optional_constraints': optional_constraints
                    }
                else:
                    logging.debug(f"[FORWARD] No paths found for {func_name}")
                    # Note: target_points has been reversed for backward traversal
                    # Show the original forward flow order in logs
                    original_order = list(reversed([p.start_line for p in target_points]))
                    logging.debug(f"[FORWARD] Target points were (in forward flow order): {[f'Line {line}' for line in original_order]}")
                    if len(target_points) > 1:
                        # The actual final target in forward flow is the first element after reversal
                        logging.debug(f"[FORWARD] Final target (end of forward flow): Line {target_points[0].start_line}")
                        # Required waypoints in forward order
                        waypoints_forward = list(reversed([p.start_line for p in target_points[1:]]))
                        logging.debug(f"[FORWARD] Required waypoints (in forward order): {[f'Line {line}' for line in waypoints_forward]}")
                    
                    # Debug information
                    logging.debug(f"[FORWARD] Debug: all_constraints = {all_constraints}")
                    logging.debug(f"[FORWARD] Debug: type(all_constraints) = {type(all_constraints)}")
                    if all_constraints:
                        logging.debug(f"[FORWARD] Debug: len(all_constraints) = {len(all_constraints)}")
                    
                    # Reverse point_info back for display in forward order
                    display_point_info = []
                    for p in reversed(point_info):
                        p_copy = p.copy()
                        # Also reverse the merged_steps array if present
                        if 'merged_steps' in p_copy:
                            p_copy['merged_steps'] = list(reversed(p_copy['merged_steps']))
                        display_point_info.append(p_copy)
                    
                    results_by_function[func_name] = {
                        'success': False,
                        'points': display_point_info,
                        'error': 'No paths found for forward analysis'
                    }
                    
            except Exception as e:
                logging.debug(f"[FORWARD] Error analyzing forward path for {func_name}: {e}")
                # Reverse point_info back for display in forward order
                display_point_info = []
                for p in reversed(point_info):
                    p_copy = p.copy()
                    # Also reverse the merged_steps array if present
                    if 'merged_steps' in p_copy:
                        p_copy['merged_steps'] = list(reversed(p_copy['merged_steps']))
                    display_point_info.append(p_copy)
                
                results_by_function[func_name] = {
                    'success': False,
                    'points': display_point_info,
                    'error': str(e)
                }
        
        # Format output
        output_lines = []
        
        for func_name, result in results_by_function.items():
            output_lines.append(f"Function: {func_name}")
            
            # Show points in this function
            output_lines.append(f"  Points in forward flow:")
            for point in result['points']:
                location = f"Line {point['line']}"
                if point.get('start_column') is not None and point.get('end_column') is not None:
                    location = f"Line {point['line']}:{point['start_column']}-{point['end_column']}"
                
                # Check if this is a merged point
                if point.get('merged_count', 1) > 1:
                    # Show the actual merged steps
                    merged_steps = point.get('merged_steps', [point['step']])
                    if len(merged_steps) > 1:
                        steps_str = f"Steps {','.join(map(str, merged_steps))}"
                    else:
                        steps_str = f"Step {point['step']}"
                    output_lines.append(f"    {steps_str}: {location} (merged {point['merged_count']} points) ({point['point_type']}) - {point['variable']}")
                else:
                    output_lines.append(f"    Step {point['step']}: {location} ({point['point_type']}) - {point['variable']}")
                output_lines.append(f"      Code: {point['line_code']}")
            
            if result['success']:
                output_lines.append(f"\n  Forward path analysis: {result['paths_found']} paths found")
                
                # Show constraints in natural language
                if result['dominator_constraints']:
                    output_lines.append("\n  Branch conditions required for data to flow forward:")
                    constraint_lines = format_constraints_natural_language(result['dominator_constraints'], "must-satisfy")
                    # Modify the lines to emphasize data flow
                    for line in constraint_lines:
                        modified_line = line.replace("must evaluate to", "must be").replace("take the", "must take")
                        output_lines.append(modified_line + " for data flow to continue")
                else:
                    output_lines.append("\n  No branch requirements - data flows unconditionally")
                
                # Show optional constraints
                if result.get('optional_constraints'):
                    # Separate must-take branches
                    must_take = [c for c in result['optional_constraints'] if c.get('must_take')]
                    optional = [c for c in result['optional_constraints'] if not c.get('must_take')]
                    
                    if must_take:
                        output_lines.append("  Must-take branches for forward flow:")
                        for constraint in must_take:
                            line = constraint.get('line', 'unknown')
                            branch = constraint.get('branch', 'unknown')
                            context = constraint.get('iteration_context', '')
                            condition_text = constraint.get('condition_text', '')
                            
                            ctx_str = f" [{context}]" if context and context != 'default' else ""
                            
                            output_lines.append(f"    - Line {line}: {branch}{ctx_str} - {condition_text}")
                    
                    if optional and len(optional) <= 10:
                        output_lines.append("  Optional constraints (alternative paths):")
                        for constraint in optional:
                            line = constraint.get('line', 'unknown')
                            branch = constraint.get('branch', 'unknown')
                            context = constraint.get('iteration_context', '')
                            condition_text = constraint.get('condition_text', '')
                            
                            ctx_str = f" [{context}]" if context and context != 'default' else ""
                            
                            output_lines.append(f"    - Line {line}: {branch}{ctx_str} - {condition_text}")
            else:
                output_lines.append(f"  Analysis failed: {result['error']}")
            
            output_lines.append("")  # Empty line between functions
        
        # Add constraint summary
        output_lines.append("\n--- Constraint Details ---")
        total_dominators = sum(len(r.get('dominator_constraints', [])) 
                              for r in results_by_function.values() if r['success'])
        total_optional = sum(len(r.get('optional_constraints', [])) 
                            for r in results_by_function.values() if r['success'])
        
        output_lines.append(f"Total dominator constraints: {total_dominators}")
        output_lines.append(f"Total optional constraints: {total_optional}")
        
        full_analysis = '\n'.join(output_lines)
        
        # Generate natural language constraint text for prompts
        constraint_text_parts = []
        constraint_text_parts.append("=== Control Flow Constraints ===")
        constraint_text_parts.append("")
        
        has_constraints = False
        for func_name, result in results_by_function.items():
            if result['success'] and result['dominator_constraints']:
                # Only add functions that have actual constraints
                has_constraints = True
                constraint_text_parts.append(f"Function: {func_name}")
                constraint_text_parts.append("\nBranch conditions required for data to flow forward:")
                constraint_lines = format_constraints_natural_language(result['dominator_constraints'], "must-satisfy")
                for line in constraint_lines:
                    modified_line = line.replace("must evaluate to", "must be").replace("take the", "must take")
                    constraint_text_parts.append(modified_line + " for data flow to continue")
                constraint_text_parts.append("")  # Empty line between functions
            # Skip functions with no constraints, failures, or unconditional flow
        
        constraint_text_for_prompt = '\n'.join(constraint_text_parts) if has_constraints else None
        
        return full_analysis, constraint_text_for_prompt
        
    except Exception as e:
        logging.error(f"[FORWARD] Failed to extract forward flow constraints: {e}")
        import traceback
        traceback.print_exc()
        return f"Error extracting forward flow constraints: {str(e)}", None




def analyze_forward_flow_with_constraints(machine):
    """
    Analyze forward flow and add constraint information to the machine context.

    This function should be called from the forward analysis state machine
    to enrich the analysis with constraint information.

    When pre-computed merged constraints are available (from variant merging),
    they are used directly instead of re-extracting from single-variant steps.
    """
    if not hasattr(machine, 'context') or not hasattr(machine.context, 'steps'):
        logging.warning("[FORWARD] No forward flow context available")
        return

    # Get project name and cache dir (needed for both merged and fresh extraction paths)
    project_name = getattr(machine, 'project_name', 'default')
    cache_dir = getattr(machine, 'cache_dir', None)
    if not cache_dir:
        cache_dir = os.environ.get('AI_ANALYSIS_DIR')

    # Use pre-computed merged constraints when available (only for multi-variant units)
    merged = getattr(machine, 'merged_constraints', None)
    if merged and getattr(machine, 'has_propagation_variants', False):
        from ..utils.variant_description import format_merged_constraints
        formatted = format_merged_constraints(merged)
        if formatted is not None:
            machine.constraint_text_for_prompt = formatted
            machine.forward_flow_constraints = "Using pre-computed merged constraints"
            logging.info("[FORWARD] Using pre-computed merged constraints from variant analysis")
        else:
            # Merged constraints exist but are empty — fall through to independent extraction
            merged = None
    else:
        logging.debug(f"[FORWARD] Using project_name={project_name}, cache_dir={cache_dir}")

        # Extract constraints
        full_analysis, constraint_text_for_prompt = extract_constraints_for_forward_flow(
            machine.context,
            project_name=project_name,
            cache_dir=cache_dir,
            verbose=True
        )

        # Add to machine context
        machine.forward_flow_constraints = full_analysis
        machine.constraint_text_for_prompt = constraint_text_for_prompt

        # Log summary at INFO level
        num_functions = sum(1 for line in full_analysis.split('\n') if line.startswith('Function: '))
        has_constraints = constraint_text_for_prompt is not None
        logging.debug(f"[FORWARD] Constraint analysis completed: {num_functions} functions analyzed, constraints found: {has_constraints}")

    # Also add as context variable for templates
    if hasattr(machine, 'shared_variables'):
        machine.shared_variables['forward_flow_constraints'] = machine.forward_flow_constraints

    # Preload macro definitions using use-def relationship
    try:
        logging.info(f'[FORWARD] Starting macro preload with cache_dir={cache_dir}')
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
        logging.info(f'[FORWARD] Macro preload completed: {len(macros)} macros found via use-def')
    except Exception as e:
        import traceback
        logging.warning(f"[FORWARD] Macro preload failed: {e}\n{traceback.format_exc()}")
        machine.preloaded_macros = {}
        machine.macro_text_for_prompt = None