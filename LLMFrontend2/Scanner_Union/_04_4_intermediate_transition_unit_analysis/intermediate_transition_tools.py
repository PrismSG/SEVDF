"""
Tools for intermediate transition path analysis with constraint extraction.

This module provides constraint extraction capabilities for intermediate data flow analysis,
analyzing the transition points between functions in the data flow path.
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
    logging.warning("[INTERMEDIATE] ConstraintExtractor not available. Constraint analysis will be skipped.")

from .intermediate_transition_context import (
    IntermediateTransitionFlowContext, Step, Point
)

from AdvancedTools.ConstraintAnalysis.constraint_formatter import format_constraints_natural_language
from ..utils.code_utils import is_function_parameter_position

try:
    from AdvancedTools.CodeSearch.symbol_lookup import get_function_start_line_from_csv
except ImportError:
    logging.warning("SymbolLookup not available. Function start line lookup will use database only.")
    get_function_start_line_from_csv = None


def extract_constraints_for_intermediate_flow(
    context: IntermediateTransitionFlowContext, 
    project_name: str = "default",
    cache_dir: Optional[str] = None,
    verbose: bool = True
) -> Tuple[str, Optional[str]]:
    """
    Extract path-based constraints for intermediate transition analysis.
    
    This function analyzes the intermediate transition points and extracts constraints
    that must be satisfied at function boundaries and transition points.
    
    Args:
        context: IntermediateTransitionFlowContext containing the flow steps
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
        extractor = ConstraintExtractor(
            project_name=project_name,
            cache_dir=cache_dir
        )
        
        # Focus on transition points between functions
        transition_points = []
        
        logging.debug(f"[INTERMEDIATE] Processing {len(context.steps)} steps for transitions")
        
        # Track statistics
        same_function_count = 0
        different_function_count = 0
        relation_types = {}
        steps_relationships = getattr(context, 'steps_relationships', {})

        for i, step in enumerate(context.steps):
            # Count statistics
            if step.sameFunction:
                same_function_count += 1
            else:
                different_function_count += 1

            step_key = (step.fromPoint.file, step.fromPoint.line,
                        step.toPoint.file, step.toPoint.line, step.flowstep)
            rel_type = steps_relationships.get(step_key, "NONE")
            relation_types[rel_type] = relation_types.get(rel_type, 0) + 1

            # Log step details for debugging (only first few to avoid spam)
            if i < 5 or not step.sameFunction:
                logging.debug(f"[INTERMEDIATE] Step {i}: sameFunction={step.sameFunction}, relation={rel_type}, "
                             f"from={step.fromPoint.functionName}:{step.fromPoint.line}, "
                             f"to={step.toPoint.functionName}:{step.toPoint.line}")

            # Identify cross-function transitions
            if not step.sameFunction and rel_type in ["CALL", "RETURN"]:
                logging.debug(f"[INTERMEDIATE] Found transition at step {i}: {rel_type}")
                transition_points.append({
                    'step': step,
                    'step_index': i,
                    'transition_type': rel_type,
                    'from_func': step.fromPoint.functionName,
                    'to_func': step.toPoint.functionName,
                    'from_point': step.fromPoint,
                    'to_point': step.toPoint
                })
        
        # Log statistics
        logging.debug(f"[INTERMEDIATE] Steps: {same_function_count} same-func, {different_function_count} cross-func, types: {relation_types}")
        
        # If no cross-function transitions, analyze the entire path within the function
        if not transition_points and context.steps:
            logging.debug(f"[INTERMEDIATE] No cross-function transitions found. Analyzing entire path within single function.")
            
            # Get the function and file info from the first step
            first_step = context.steps[0]
            last_step = context.steps[-1]
            func_name = first_step.fromPoint.functionName
            file_path = first_step.fromPoint.file
            
            # Create a pseudo-transition for the entire function flow
            transition_points.append({
                'step': None,  # No specific step, it's the entire path
                'transition_type': 'INTRA_FUNCTION',
                'from_func': func_name,
                'to_func': func_name,
                'from_point': first_step.fromPoint,
                'to_point': last_step.toPoint,
                'is_entire_path': True
            })
        
        # New approach: For intermediate analysis, we need to analyze the first encountered function
        # and collect ALL its points throughout the entire path
        results_by_transition = []
        
        # Identify the first encountered function
        if context.steps:
            first_func_name = context.steps[0].fromPoint.functionName
            logging.debug(f"[INTERMEDIATE] First encountered function: {first_func_name}")
            
            # Collect all points belonging to the first function throughout the path
            first_func_points = []
            for i, step in enumerate(context.steps):
                # Check if fromPoint belongs to first function
                if step.fromPoint.functionName == first_func_name:
                    first_func_points.append({
                        'point': step.fromPoint,
                        'step_index': i,
                        'is_from': True
                    })
                # Check if toPoint belongs to first function (and different from fromPoint)
                if step.toPoint.functionName == first_func_name:
                    # Avoid duplicates for same-location points
                    if (not first_func_points or 
                        first_func_points[-1]['point'].line != step.toPoint.line or
                        first_func_points[-1]['point'].startColumn != step.toPoint.startColumn):
                        first_func_points.append({
                            'point': step.toPoint,
                            'step_index': i,
                            'is_from': False
                        })
            
            logging.debug(f"[INTERMEDIATE] Found {len(first_func_points)} points in {first_func_name}")
            
            # Analyze constraints for all points in the first function
            if len(first_func_points) >= 2:
                # Analyze the path through all these points
                file_path = first_func_points[0]['point'].file
                
                # Special handling for the original transition-based analysis
                # This is kept for backward compatibility but will be replaced
                analyze_first_func_as_whole = True
                
                if analyze_first_func_as_whole:
                    # Create a single analysis entry for the entire first function path
                    transition_points = [{
                        'step': None,
                        'transition_type': 'FIRST_FUNCTION_COMPLETE',
                        'from_func': first_func_name,
                        'to_func': first_func_name,
                        'first_func_points': first_func_points,
                        'from_point': first_func_points[0]['point'],
                        'to_point': first_func_points[-1]['point']
                    }]
        
        for i, transition in enumerate(transition_points):
            step = transition['step']
            trans_type = transition['transition_type']
            
            # For FIRST_FUNCTION_COMPLETE (analyze all points in first function)
            if trans_type == "FIRST_FUNCTION_COMPLETE":
                func_name = transition['from_func']
                first_func_points = transition['first_func_points']
                
                logging.debug(f"[INTERMEDIATE] Analyzing complete path through first function {func_name} with {len(first_func_points)} points")
                
                try:
                    file_path = first_func_points[0]['point'].file
                    
                    # Resolve file path
                    if not os.path.isabs(file_path):
                        ai_analysis_dir = os.environ.get('AI_ANALYSIS_DIR', '')
                        if ai_analysis_dir:
                            possible_path = os.path.join(ai_analysis_dir, 'sourcecode', file_path)
                            if os.path.exists(possible_path):
                                file_path = possible_path
                    
                    # Get function start line
                    func_start = None
                    if hasattr(extractor, 'cfg_db') and extractor.cfg_db:
                        try:
                            functions = extractor.cfg_db.get_function_info(func_name, file_path)
                            if functions:
                                func_start = int(functions[0][2])
                                logging.debug(f"[INTERMEDIATE] Found function start line: {func_name} starts at {func_start}")
                        except Exception as e:
                            logging.debug(f"[INTERMEDIATE] Error getting function start line: {e}")
                    
                    if func_start is None and get_function_start_line_from_csv:
                        func_start = get_function_start_line_from_csv(func_name, file_path)
                    
                    if func_start is None:
                        logging.warning(f"[INTERMEDIATE] Could not determine start line for {func_name}")
                        continue
                    
                    # Create program points for all occurrences in first function
                    target_points = []
                    for point_info in first_func_points:
                        point = point_info['point']
                        if hasattr(point, 'startColumn') and point.startColumn is not None:
                            prog_point = ProgramPoint(
                                start_line=point.line,
                                start_column=point.startColumn,
                                end_line=point.line,
                                end_column=point.endColumn
                            )
                        else:
                            prog_point = ProgramPoint.from_line(point.line)
                        target_points.append(prog_point)
                    
                    logging.debug(f"[INTERMEDIATE] Created {len(target_points)} program points for {func_name}")
                    
                    # Analyze path through all points
                    paths, all_constraints = extractor.core_extractor.extract_path_constraints_from_cached_cfg(
                        function_name=func_name,
                        file_path=file_path,
                        start_line=func_start,
                        target_program_points=target_points[-1:],  # Last point as target
                        required_program_points=target_points[:-1] if len(target_points) > 1 else [],  # Others as waypoints
                        verbose=verbose
                    )
                    
                    # Process results
                    dominator_constraints = []
                    optional_constraints = []
                    paths_with_constraints = []
                    
                    if all_constraints and isinstance(all_constraints[0], dict):
                        constraint_dict = all_constraints[0]
                        dominator_constraints = constraint_dict.get('dominator_constraints', [])
                        optional_constraints = constraint_dict.get('optional_constraints', [])
                        
                        if 'paths_with_constraints' in constraint_dict:
                            paths_with_constraints = constraint_dict['paths_with_constraints']
                    
                    # Log results
                    if paths:
                        # Create summary log
                        logging.debug(f"[INTERMEDIATE] Function: {func_name} | Paths: {len(paths)} | Points: {len(target_points)}")
                        
                        # Detailed logging similar to backward/forward
                        if paths_with_constraints and verbose:
                            paths_to_show = min(10, len(paths_with_constraints))
                            logging.debug(f"[INTERMEDIATE] === Detailed Path Analysis (showing {paths_to_show} of {len(paths_with_constraints)} paths) ===")
                            
                            for i, (path, constraints) in enumerate(paths_with_constraints[:paths_to_show]):
                                logging.debug(f"[INTERMEDIATE] ==== Path {i+1} ====")
                                logging.debug(f"  Path length: {len(path)} blocks")
                                if constraints:
                                    logging.debug(f"  Constraints: {len(constraints)}")
                                    for constraint in constraints[:5]:  # Show first 5
                                        line = constraint.get('line', '?')
                                        branch = constraint.get('branch', '?')
                                        logging.debug(f"    - Line {line}: {branch}")
                        
                        results_by_transition.append({
                            'transition_index': 1,
                            'type': 'FIRST_FUNCTION_COMPLETE',
                            'from_func': func_name,
                            'to_func': func_name,
                            'points_analyzed': len(target_points),
                            'paths_found': len(paths),
                            'dominator_constraints': dominator_constraints,
                            'optional_constraints': optional_constraints,
                            'success': True
                        })
                    else:
                        logging.warning(f"[INTERMEDIATE] No paths found through {len(target_points)} points in {func_name}")
                        results_by_transition.append({
                            'transition_index': 1,
                            'type': 'FIRST_FUNCTION_COMPLETE',
                            'from_func': func_name,
                            'to_func': func_name,
                            'points_analyzed': len(target_points),
                            'paths_found': 0,
                            'success': False,
                            'error': 'No paths found'
                        })
                        
                except Exception as e:
                    logging.error(f"[INTERMEDIATE] Error analyzing first function {func_name}: {e}")
                    results_by_transition.append({
                        'transition_index': 1,
                        'type': 'FIRST_FUNCTION_COMPLETE',
                        'from_func': func_name,
                        'to_func': func_name,
                        'success': False,
                        'error': str(e)
                    })
                    
            # For INTRA_FUNCTION (entire path within single function)
            elif trans_type == "INTRA_FUNCTION":
                func_name = transition['from_func']
                start_point = transition['from_point']
                end_point = transition['to_point']
                
                logging.debug(f"[INTERMEDIATE] Analyzing intra-function path: {func_name} from line {start_point.line} to {end_point.line}")
                
                try:
                    file_path = start_point.file
                    
                    # Resolve file path
                    if not os.path.isabs(file_path):
                        search_path = os.environ.get('OPENGROK_SEARCH_PATH', '')
                        if search_path:
                            import glob
                            pattern = os.path.join(search_path, '**', os.path.basename(file_path))
                            matches = glob.glob(pattern, recursive=True)
                            if matches:
                                file_path = matches[0]
                    
                    # Get function start line
                    func_start = None
                    if hasattr(extractor, 'cfg_db') and extractor.cfg_db:
                        try:
                            functions = extractor.cfg_db.get_function_info(func_name, file_path)
                            if functions:
                                func_start = int(functions[0][2])
                                logging.debug(f"[INTERMEDIATE] Found function start line: {func_name} starts at {func_start}")
                        except Exception as e:
                            logging.debug(f"[INTERMEDIATE] Error getting function start line: {e}")
                    
                    if func_start is None and get_function_start_line_from_csv:
                        func_start = get_function_start_line_from_csv(func_name, file_path)
                    
                    if func_start is None:
                        logging.warning(f"[INTERMEDIATE] Could not determine start line for {func_name}")
                        continue
                    
                    # Create program points for all intermediate steps
                    target_points = []
                    all_points = []  # Collect all unique points (both from and to)
                    seen_points = set()  # Track unique points to avoid duplicates
                    
                    # Special case: if there's only one step, always include both points
                    # even if they have the same location
                    if len(context.steps) == 1:
                        step = context.steps[0]
                        # Always add both points for single step
                        from_point = ProgramPoint(
                            start_line=step.fromPoint.line,
                            start_column=step.fromPoint.startColumn,
                            end_line=step.fromPoint.line,
                            end_column=step.fromPoint.endColumn
                        )
                        to_point = ProgramPoint(
                            start_line=step.toPoint.line,
                            start_column=step.toPoint.startColumn,
                            end_line=step.toPoint.line,
                            end_column=step.toPoint.endColumn
                        )
                        all_points = [from_point, to_point]
                        logging.debug(f"[INTERMEDIATE] Single step case - keeping both points even if identical")
                    else:
                        # Multiple steps - deduplicate points
                        for step in context.steps:
                            # Add fromPoint if it's unique
                            from_key = (step.fromPoint.line, step.fromPoint.startColumn, step.fromPoint.endColumn)
                            if from_key not in seen_points:
                                from_point = ProgramPoint(
                                    start_line=step.fromPoint.line,
                                    start_column=step.fromPoint.startColumn,
                                    end_line=step.fromPoint.line,
                                    end_column=step.fromPoint.endColumn
                                )
                                all_points.append(from_point)
                                seen_points.add(from_key)
                            
                            # Add toPoint if it's unique
                            to_key = (step.toPoint.line, step.toPoint.startColumn, step.toPoint.endColumn)
                            if to_key not in seen_points:
                                to_point = ProgramPoint(
                                    start_line=step.toPoint.line,
                                    start_column=step.toPoint.startColumn,
                                    end_line=step.toPoint.line,
                                    end_column=step.toPoint.endColumn
                                )
                                all_points.append(to_point)
                                seen_points.add(to_key)
                    
                    target_points = all_points
                    
                    # Analyze path through all points
                    logging.debug(f"[INTERMEDIATE] Analyzing path through {len(target_points)} points (from {len(context.steps)} steps)")
                    paths, all_constraints = extractor.core_extractor.extract_path_constraints_from_cached_cfg(
                        function_name=func_name,
                        file_path=file_path,
                        start_line=func_start,
                        target_program_points=target_points[-1:],  # Last point as target
                        required_program_points=target_points[:-1] if len(target_points) > 1 else [],  # Rest as waypoints
                        verbose=verbose
                    )
                    
                    # Process results
                    dominator_constraints = []
                    optional_constraints = []
                    paths_with_constraints = []
                    
                    if all_constraints and isinstance(all_constraints[0], dict):
                        constraint_dict = all_constraints[0]
                        dominator_constraints = constraint_dict.get('dominator_constraints', [])
                        optional_constraints = constraint_dict.get('optional_constraints', [])
                        
                        # Get paths with constraints if available
                        if 'paths_with_constraints' in constraint_dict:
                            paths_with_constraints = constraint_dict['paths_with_constraints']
                    
                    # Log detailed path information (similar to backward analysis)
                    if paths:
                        # Create summary log
                        logging.debug(f"[INTERMEDIATE] Function: {func_name} | Paths: {len(paths)} | Points: {len(target_points)}")
                        
                        # Show detailed path analysis if we have paths with constraints
                        if paths_with_constraints:
                            paths_to_show = len(paths_with_constraints) if len(paths_with_constraints) <= 10 else 12
                            logging.debug(f"[INTERMEDIATE] === Detailed Path Analysis (showing {min(paths_to_show, len(paths_with_constraints))} of {len(paths_with_constraints)} paths) ===")
                            
                            for i, (path, constraints) in enumerate(paths_with_constraints[:paths_to_show]):
                                logging.debug(f"[INTERMEDIATE] ==== Path {i+1} of {len(paths_with_constraints)} ====")
                                logging.debug(f"  Path length: {len(path)} blocks")
                                
                                # Show path blocks
                                logging.debug("  Block sequence:")
                                for j, bb in enumerate(path):
                                    logging.debug(f"    {j+1}. {bb.block_id}")
                                
                                # Print constraints for this specific path
                                if constraints:
                                    logging.debug(f"  Constraints for Path {i+1}: ({len(constraints)} total)")
                                    
                                    for constraint in constraints:
                                        line = constraint.get('line', '?')
                                        branch = constraint.get('branch', '?')
                                        context = constraint.get('iteration_context', 'original')
                                        condition_text = constraint.get('condition_text', '')
                                        block_id = constraint.get('block_id', 'unknown')
                                        
                                        ctx_str = f" [{context}]" if context != 'original' else ""
                                        cond_str = f" - `{condition_text}`" if condition_text else ""
                                        
                                        logging.debug(f"    - Line {line}: {branch}{ctx_str}{cond_str} (from block: {block_id})")
                                else:
                                    logging.debug(f"  No constraints for Path {i+1}")
                            
                            if len(paths_with_constraints) > paths_to_show:
                                logging.debug(f"  ... and {len(paths_with_constraints) - paths_to_show} more paths not shown")
                    
                    results_by_transition.append({
                        'transition_index': i + 1,
                        'type': trans_type,
                        'from_func': func_name,
                        'to_func': func_name,  # Same function for intra-function
                        'call_line': start_point.line,
                        'return_line': end_point.line,  # Add return_line for consistency
                        'call_code': start_point.lineCode if hasattr(start_point, 'lineCode') else '',
                        'success': True,
                        'paths_found': len(paths) if paths else 0,
                        'dominator_constraints': dominator_constraints,
                        'optional_constraints': optional_constraints
                    })
                    
                except Exception as e:
                    logging.error(f"[INTERMEDIATE] Error analyzing intra-function flow: {str(e)}")
                    import traceback
                    logging.debug(traceback.format_exc())
                    results_by_transition.append({
                        'transition_index': i + 1,
                        'type': trans_type,
                        'from_func': func_name,
                        'to_func': func_name,
                        'call_line': start_point.line,
                        'return_line': end_point.line,  # Add return_line for consistency
                        'call_code': start_point.lineCode if hasattr(start_point, 'lineCode') else '',
                        'success': False,
                        'error': str(e)
                    })
            
            # For CALL transitions, analyze the calling function up to the call point
            elif trans_type == "CALL":
                func_name = transition['from_func']
                call_point = transition['from_point']
                
                try:
                    # Extract constraints leading to the call
                    file_path = call_point.file
                    
                    # Resolve file path (same as backward/forward)
                    if not os.path.isabs(file_path):
                        ai_analysis_dir = os.environ.get('AI_ANALYSIS_DIR', '')
                        if ai_analysis_dir:
                            possible_path = os.path.join(ai_analysis_dir, 'sourcecode', file_path)
                            if os.path.exists(possible_path):
                                file_path = possible_path
                    
                    # Skip if it's a function parameter position
                    if is_function_parameter_position(call_point):
                        logging.debug(f"[INTERMEDIATE] Skipping function parameter position: {func_name}:{call_point.line}")
                        continue
                    
                    # Check that point is within function body
                    if not extractor.is_point_in_function_body(func_name, file_path, call_point.line):
                        logging.debug(f"[INTERMEDIATE] Skipping declaration/non-body line: {func_name}:{call_point.line}")
                        continue
                    
                    # Get function start line from database (same as backward/forward)
                    func_start = None
                    if hasattr(extractor, 'cfg_db') and extractor.cfg_db:
                        try:
                            functions = extractor.cfg_db.get_function_info(func_name, file_path)
                            if functions:
                                func_start = int(functions[0][2])
                                logging.info(f"[INTERMEDIATE] Found function start line from database: {func_name} starts at {func_start}")
                        except Exception as e:
                            logging.debug(f"[INTERMEDIATE] Error getting function start line from database: {e}")
                    
                    if func_start is None and get_function_start_line_from_csv:
                        # Try to get from Function CSV
                        logging.debug(f"[INTERMEDIATE] Trying to get function start line from Function CSV for {func_name}")
                        func_start = get_function_start_line_from_csv(func_name, file_path)
                        if func_start:
                            logging.debug(f"[INTERMEDIATE] Found function start line from CSV: {func_name} starts at {func_start}")
                    
                    if func_start is None:
                        logging.error(f"[INTERMEDIATE] Cannot find function start line for {func_name} in database or CSV. Skipping call-to-return.")
                        continue
                    
                    # Create proper ProgramPoint (same as backward/forward)
                    if hasattr(call_point, 'startColumn') and call_point.startColumn is not None and hasattr(call_point, 'endColumn') and call_point.endColumn is not None:
                        target_point = ProgramPoint.from_location(
                            start_line=call_point.line,
                            start_column=call_point.startColumn,
                            end_line=call_point.line,
                            end_column=call_point.endColumn
                        )
                        logging.debug(f"[INTERMEDIATE] Created precise ProgramPoint for {func_name}:{call_point.line}:{call_point.startColumn}-{call_point.endColumn}")
                    else:
                        target_point = ProgramPoint.from_line(call_point.line)
                        logging.debug(f"[INTERMEDIATE] Created line-based ProgramPoint for {func_name}:{call_point.line} (no column info)")
                    
                    # For the first CALL transition in intermediate, we need to analyze the path
                    # that continues after the function returns
                    additional_target_points = []
                    if i == 0:  # First transition (first cross-function call)
                        # Find the next point after this call returns
                        # Look for the next step in the same function after the call
                        for j in range(transition['step_index'] + 1, len(context.steps)):
                            next_step = context.steps[j]
                            # Find the first point back in the calling function
                            if next_step.fromPoint.functionName == func_name or next_step.toPoint.functionName == func_name:
                                # Add the point where execution continues after return
                                continue_point = next_step.fromPoint if next_step.fromPoint.functionName == func_name else next_step.toPoint
                                if hasattr(continue_point, 'startColumn') and continue_point.startColumn is not None:
                                    continue_target = ProgramPoint.from_location(
                                        start_line=continue_point.line,
                                        start_column=continue_point.startColumn,
                                        end_line=continue_point.line,
                                        end_column=continue_point.endColumn
                                    )
                                else:
                                    continue_target = ProgramPoint.from_line(continue_point.line)
                                additional_target_points.append(continue_target)
                                logging.debug(f"[INTERMEDIATE] For first CALL, also analyzing path to continuation point at line {continue_point.line}")
                                break
                    
                    # Combine target points: the call point and any continuation points
                    all_target_points = [target_point] + additional_target_points
                    
                    # Extract path constraints to reach the call and continue after return
                    paths, all_constraints = extractor.core_extractor.extract_path_constraints_from_cached_cfg(
                        function_name=func_name,
                        file_path=file_path,
                        start_line=func_start,
                        target_program_points=all_target_points[-1:],  # Use the last point as target
                        required_program_points=all_target_points[:-1] if len(all_target_points) > 1 else [],  # Others as waypoints
                        verbose=verbose
                    )
                    
                    if paths:
                        # Extract constraint information
                        dominator_constraints = []
                        optional_constraints = []
                        paths_with_constraints = []
                        
                        if all_constraints and isinstance(all_constraints[0], dict):
                            constraint_dict = all_constraints[0]
                            dominator_constraints = constraint_dict.get('dominator_constraints', [])
                            optional_constraints = constraint_dict.get('optional_constraints', [])
                            
                            # Get paths with constraints if available
                            if 'paths_with_constraints' in constraint_dict:
                                paths_with_constraints = constraint_dict['paths_with_constraints']
                        
                        # Log detailed path information for CALL transitions
                        logging.debug(f"[INTERMEDIATE] Transition {i+1} | Function: {func_name} | Paths: {len(paths)}")
                        
                        if paths_with_constraints:
                            paths_to_show = len(paths_with_constraints) if len(paths_with_constraints) <= 10 else 12
                            logging.debug(f"[INTERMEDIATE] === Detailed Path Analysis for CALL (showing {min(paths_to_show, len(paths_with_constraints))} of {len(paths_with_constraints)} paths) ===")
                            
                            for i, (path, constraints) in enumerate(paths_with_constraints[:paths_to_show]):
                                logging.debug(f"[INTERMEDIATE] ==== Path {i+1} of {len(paths_with_constraints)} ====")
                                logging.debug(f"  Path length: {len(path)} blocks")
                                
                                # Show path blocks
                                logging.debug("  Block sequence:")
                                for j, bb in enumerate(path):
                                    logging.debug(f"    {j+1}. {bb.block_id}")
                                
                                # Print constraints for this specific path
                                if constraints:
                                    logging.debug(f"  Constraints for Path {i+1}: ({len(constraints)} total)")
                                    
                                    for constraint in constraints:
                                        line = constraint.get('line', '?')
                                        branch = constraint.get('branch', '?')
                                        context = constraint.get('iteration_context', 'original')
                                        condition_text = constraint.get('condition_text', '')
                                        block_id = constraint.get('block_id', 'unknown')
                                        
                                        ctx_str = f" [{context}]" if context != 'original' else ""
                                        cond_str = f" - `{condition_text}`" if condition_text else ""
                                        
                                        logging.debug(f"    - Line {line}: {branch}{ctx_str}{cond_str} (from block: {block_id})")
                                else:
                                    logging.debug(f"  No constraints for Path {i+1}")
                            
                            if len(paths_with_constraints) > paths_to_show:
                                logging.debug(f"  ... and {len(paths_with_constraints) - paths_to_show} more paths not shown")
                        
                        results_by_transition.append({
                            'transition_index': i + 1,
                            'type': trans_type,
                            'from_func': func_name,
                            'to_func': transition['to_func'],
                            'call_line': call_point.line,
                            'call_code': call_point.lineCode,
                            'success': True,
                            'paths_found': len(paths),
                            'dominator_constraints': dominator_constraints,
                            'optional_constraints': optional_constraints
                        })
                    else:
                        results_by_transition.append({
                            'transition_index': i + 1,
                            'type': trans_type,
                            'from_func': func_name,
                            'to_func': transition['to_func'],
                            'call_line': call_point.line,
                            'call_code': call_point.lineCode,
                            'success': False,
                            'error': 'No paths found to call point'
                        })
                        
                except Exception as e:
                    logging.warning(f"[INTERMEDIATE] Error analyzing transition {i+1}: {e}")
                    results_by_transition.append({
                        'transition_index': i + 1,
                        'type': trans_type,
                        'from_func': func_name,
                        'to_func': transition['to_func'],
                        'call_line': call_point.line,
                        'call_code': call_point.lineCode,
                        'success': False,
                        'error': str(e)
                    })
            
            # For RETURN transitions, analyze the called function
            elif trans_type == "RETURN":
                func_name = transition['from_func']
                return_point = transition['from_point']
                
                try:
                    # Extract constraints in the returning function
                    file_path = return_point.file
                    
                    # Resolve file path (same as backward/forward)
                    if not os.path.isabs(file_path):
                        ai_analysis_dir = os.environ.get('AI_ANALYSIS_DIR', '')
                        if ai_analysis_dir:
                            possible_path = os.path.join(ai_analysis_dir, 'sourcecode', file_path)
                            if os.path.exists(possible_path):
                                file_path = possible_path
                    
                    # Skip if it's a function parameter position
                    if is_function_parameter_position(return_point):
                        logging.debug(f"[INTERMEDIATE] Skipping function parameter position: {func_name}:{return_point.line}")
                        continue
                    
                    # Check that point is within function body
                    if not extractor.is_point_in_function_body(func_name, file_path, return_point.line):
                        logging.debug(f"[INTERMEDIATE] Skipping declaration/non-body line: {func_name}:{return_point.line}")
                        continue
                    
                    # Get function start line from database (same as backward/forward)
                    func_start = None
                    if hasattr(extractor, 'cfg_db') and extractor.cfg_db:
                        try:
                            functions = extractor.cfg_db.get_function_info(func_name, file_path)
                            if functions:
                                func_start = int(functions[0][2])
                                logging.info(f"[INTERMEDIATE] Found function start line from database: {func_name} starts at {func_start}")
                        except Exception as e:
                            logging.debug(f"[INTERMEDIATE] Error getting function start line from database: {e}")
                    
                    if func_start is None and get_function_start_line_from_csv:
                        # Try to get from Function CSV
                        logging.debug(f"[INTERMEDIATE] Trying to get function start line from Function CSV for {func_name}")
                        func_start = get_function_start_line_from_csv(func_name, file_path)
                        if func_start:
                            logging.debug(f"[INTERMEDIATE] Found function start line from CSV: {func_name} starts at {func_start}")
                    
                    if func_start is None:
                        logging.error(f"[INTERMEDIATE] Cannot find function start line for {func_name} in database or CSV. Skipping return-to-call.")
                        continue
                    
                    # Create proper ProgramPoint (same as backward/forward)
                    if hasattr(return_point, 'startColumn') and return_point.startColumn is not None and hasattr(return_point, 'endColumn') and return_point.endColumn is not None:
                        target_point = ProgramPoint.from_location(
                            start_line=return_point.line,
                            start_column=return_point.startColumn,
                            end_line=return_point.line,
                            end_column=return_point.endColumn
                        )
                        logging.debug(f"[INTERMEDIATE] Created precise ProgramPoint for {func_name}:{return_point.line}:{return_point.startColumn}-{return_point.endColumn}")
                    else:
                        target_point = ProgramPoint.from_line(return_point.line)
                        logging.debug(f"[INTERMEDIATE] Created line-based ProgramPoint for {func_name}:{return_point.line} (no column info)")
                    
                    # Extract path constraints to reach the return
                    paths, all_constraints = extractor.core_extractor.extract_path_constraints_from_cached_cfg(
                        function_name=func_name,
                        file_path=file_path,
                        start_line=func_start,
                        target_program_points=[target_point],
                        required_program_points=[],
                        verbose=verbose
                    )
                    
                    if paths:
                        # Extract constraint information
                        dominator_constraints = []
                        optional_constraints = []
                        
                        if all_constraints and isinstance(all_constraints[0], dict):
                            constraint_dict = all_constraints[0]
                            dominator_constraints = constraint_dict.get('dominator_constraints', [])
                            optional_constraints = constraint_dict.get('optional_constraints', [])
                        
                        results_by_transition.append({
                            'transition_index': i + 1,
                            'type': trans_type,
                            'from_func': func_name,
                            'to_func': transition['to_func'],
                            'return_line': return_point.line,
                            'return_code': return_point.lineCode,
                            'success': True,
                            'paths_found': len(paths),
                            'dominator_constraints': dominator_constraints,
                            'optional_constraints': optional_constraints
                        })
                    else:
                        results_by_transition.append({
                            'transition_index': i + 1,
                            'type': trans_type,
                            'from_func': func_name,
                            'to_func': transition['to_func'],
                            'return_line': return_point.line,
                            'return_code': return_point.lineCode,
                            'success': False,
                            'error': 'No paths found to return point'
                        })
                        
                except Exception as e:
                    logging.warning(f"[INTERMEDIATE] Error analyzing transition {i+1}: {e}")
                    results_by_transition.append({
                        'transition_index': i + 1,
                        'type': trans_type,
                        'from_func': func_name,
                        'to_func': transition['to_func'],
                        'return_line': return_point.line,
                        'return_code': return_point.lineCode,
                        'success': False,
                        'error': str(e)
                    })
        
        # Format output (similar to forward/backward analysis format)
        output_lines = ["\n=== [INTERMEDIATE] Constraint Analysis Summary ===\n"]
        
        # First, show all steps in order (like forward/backward)
        if context.steps:
            # Collect all points with their function info
            all_points = []
            seen_points = set()
            
            # Special case: if there's only one step, always include both points
            if len(context.steps) == 1:
                step = context.steps[0]
                # Always add both points for single step
                all_points.append({
                    'point': step.fromPoint,
                    'function': step.fromPoint.functionName,
                    'step_idx': 0,
                    'is_from': True,
                    'step': step
                })
                all_points.append({
                    'point': step.toPoint,
                    'function': step.toPoint.functionName,
                    'step_idx': 0,
                    'is_from': False,
                    'step': step
                })
            else:
                # Multiple steps - use deduplication logic
                for i, step in enumerate(context.steps):
                    # Add fromPoint if it's unique or the first point
                    from_key = (step.fromPoint.functionName, step.fromPoint.line, step.fromPoint.startColumn, step.fromPoint.endColumn)
                    if i == 0 or from_key not in seen_points:
                        all_points.append({
                            'point': step.fromPoint,
                            'function': step.fromPoint.functionName,
                            'step_idx': i,
                            'is_from': True,
                            'step': step
                        })
                        seen_points.add(from_key)
                    
                    # Add toPoint if it's unique
                    to_key = (step.toPoint.functionName, step.toPoint.line, step.toPoint.startColumn, step.toPoint.endColumn)
                    if to_key not in seen_points:
                        all_points.append({
                            'point': step.toPoint,
                            'function': step.toPoint.functionName,
                            'step_idx': i,
                            'is_from': False,
                            'step': step
                        })
                        seen_points.add(to_key)
            
            # Group points by function while maintaining order
            current_func = None
            func_points = []
            
            for point_info in all_points:
                if current_func != point_info['function']:
                    # Output previous function's points if any
                    if current_func and func_points:
                        output_lines.append(f"Function: {current_func}")
                        output_lines.append(f"  Points in execution order:")
                        
                        for j, pt in enumerate(func_points):
                            # Determine point type
                            if j == 0 and all_points.index(pt) == 0:
                                point_type = "source"
                            elif all_points.index(pt) == len(all_points) - 1:
                                point_type = "sink"
                            else:
                                point_type = "intermediate"
                            
                            # Format location
                            p = pt['point']
                            location = f"Line {p.line}"
                            if p.startColumn is not None and p.endColumn is not None:
                                location = f"Line {p.line}:{p.startColumn}-{p.endColumn}"
                            
                            output_lines.append(f"    {location} ({point_type}) - {p.variable}")
                            output_lines.append(f"      Code: {p.lineCode}")
                            
                            # Show transition if this is a toPoint of a cross-function step
                            if not pt['is_from'] and not pt['step'].sameFunction:
                                output_lines.append(f"      Transition: {pt.get('transition_type', 'UNKNOWN')} to {pt['step'].toPoint.functionName}")
                        
                        output_lines.append("")  # Empty line between functions
                    
                    # Start new function
                    current_func = point_info['function']
                    func_points = []
                
                func_points.append(point_info)
            
            # Output last function's points
            if current_func and func_points:
                output_lines.append(f"Function: {current_func}")
                output_lines.append(f"  Points in execution order:")
                
                for j, pt in enumerate(func_points):
                    # Determine point type
                    if j == 0 and all_points.index(pt) == 0:
                        point_type = "source"
                    elif all_points.index(pt) == len(all_points) - 1:
                        point_type = "sink"
                    else:
                        point_type = "intermediate"
                    
                    # Format location
                    p = pt['point']
                    location = f"Line {p.line}"
                    if p.startColumn is not None and p.endColumn is not None:
                        location = f"Line {p.line}:{p.startColumn}-{p.endColumn}"
                    
                    output_lines.append(f"    {location} ({point_type}) - {p.variable}")
                    output_lines.append(f"      Code: {p.lineCode}")
                    
                    # Show transition if this is a toPoint of a cross-function step
                    if not pt['is_from'] and not pt['step'].sameFunction:
                        output_lines.append(f"      Transition: {pt.get('transition_type', 'UNKNOWN')} to {pt['step'].toPoint.functionName}")
            
        # Now show the constraint analysis results
        if results_by_transition:
            for result in results_by_transition:
                trans_type = result['type']
                
                output_lines.append("")  # Empty line before analysis results
                
                if result['success']:
                    if trans_type == "FIRST_FUNCTION_COMPLETE":
                        output_lines.append(f"  Analysis of first encountered function {result['from_func']}: {result['paths_found']} paths found")
                        output_lines.append(f"    Points analyzed: {result['points_analyzed']} occurrences throughout the path")
                    elif trans_type == "INTRA_FUNCTION":
                        output_lines.append(f"  Path analysis: {result['paths_found']} paths found")
                        # Show target and required points (similar to forward/backward)
                        if context.steps:
                            output_lines.append("  Target point: Line " + str(context.steps[-1].toPoint.line))
                            if len(context.steps) > 1:
                                output_lines.append("  Required waypoints:")
                                for i, step in enumerate(context.steps[:-1]):
                                    output_lines.append(f"    - Line {step.toPoint.line}")
                    elif trans_type == "CALL":
                        output_lines.append(f"  CALL transition analysis: {result['paths_found']} paths to call at line {result['call_line']}")
                        output_lines.append(f"    Function: {result['from_func']} → {result['to_func']}")
                        if result.get('call_code'):
                            output_lines.append(f"    Call: {result['call_code']}")
                    elif trans_type == "RETURN":
                        output_lines.append(f"  RETURN transition analysis: {result['paths_found']} paths to return at line {result['return_line']}")
                        output_lines.append(f"    Function: {result['from_func']} → {result['to_func']}")
                        if result.get('return_code'):
                            output_lines.append(f"    Return: {result['return_code']}")
                    
                    # Show constraints in natural language
                    if result['dominator_constraints']:
                        output_lines.append(f"\n  Branch decisions needed at this transition point:")
                        constraint_lines = format_constraints_natural_language(result['dominator_constraints'], "must-satisfy")
                        for line in constraint_lines:
                            output_lines.append(line)

                        # Add must-take notes if any
                        for constraint in result['dominator_constraints']:
                            if constraint.get('must_take', False):
                                line_num = constraint.get('line', '?')
                                output_lines.append(f"      (Note: Line {line_num} - only this branch reaches the target function)")
                    else:
                        output_lines.append(f"\n  No branch decisions needed - execution flows directly")
                    
                    # Show optional constraints
                    if result.get('optional_constraints'):
                        # Separate must-take branches
                        must_take = [c for c in result['optional_constraints'] if c.get('must_take')]
                        optional = [c for c in result['optional_constraints'] if not c.get('must_take')]
                        
                        if must_take:
                            output_lines.append(f"  Must-take branches:")
                            for constraint in must_take:
                                line = constraint.get('line', 'unknown')
                                branch = constraint.get('branch', 'unknown')
                                context_iter = constraint.get('iteration_context', '')
                                condition_text = constraint.get('condition_text', '')
                                
                                ctx_str = f" [{context_iter}]" if context_iter and context_iter != 'original' else ""
                                
                                # Handle missing condition text
                                if condition_text:
                                    output_lines.append(f"    - Line {line}: {branch}{ctx_str} - {condition_text}")
                                else:
                                    output_lines.append(f"    - Line {line}: {branch}{ctx_str} (condition text not available)")
                        
                        if optional and len(optional) <= 10:
                            output_lines.append(f"  Optional constraints (alternative paths):")
                            for constraint in optional:
                                line = constraint.get('line', 'unknown')
                                branch = constraint.get('branch', 'unknown')
                                context_iter = constraint.get('iteration_context', '')
                                condition_text = constraint.get('condition_text', '')
                                
                                ctx_str = f" [{context_iter}]" if context_iter and context_iter != 'original' else ""
                                
                                # Handle missing condition text
                                if condition_text:
                                    output_lines.append(f"    - Line {line}: {branch}{ctx_str} - {condition_text}")
                                else:
                                    output_lines.append(f"    - Line {line}: {branch}{ctx_str} (condition text not available)")
                else:
                    output_lines.append(f"  Analysis failed: {result['error']}")
            
            output_lines.append("")  # Empty line between transitions
        
        # Add summary
        output_lines.append("\n=== Transition Summary ===")
        total_transitions = len(results_by_transition)
        successful = sum(1 for r in results_by_transition if r.get('error') is None)
        call_transitions = sum(1 for r in results_by_transition if r.get('type') == 'CALL')
        return_transitions = sum(1 for r in results_by_transition if r.get('type') == 'RETURN')
        intra_transitions = sum(1 for r in results_by_transition if r.get('type') == 'INTRA_FUNCTION')
        
        output_lines.append(f"Total transitions analyzed: {total_transitions}")
        output_lines.append(f"  - CALL transitions: {call_transitions}")
        output_lines.append(f"  - RETURN transitions: {return_transitions}")
        output_lines.append(f"  - INTRA_FUNCTION transitions: {intra_transitions}")
        output_lines.append(f"Successfully analyzed: {successful}/{total_transitions}")
        
        full_analysis = '\n'.join(output_lines)
        
        # Generate natural language constraint text for prompts
        constraint_text_parts = []
        constraint_text_parts.append("=== Control Flow Constraints ===")
        constraint_text_parts.append("")
        
        has_constraints = False
        
        for result in results_by_transition:
            if result['success'] and result['dominator_constraints']:
                # Only add transitions that have actual constraints
                has_constraints = True
                
                trans_type = result['type']
                if trans_type == "FIRST_FUNCTION_COMPLETE":
                    constraint_text_parts.append(f"Function: {result['from_func']} (complete path analysis)")
                elif trans_type == "CALL":
                    constraint_text_parts.append(f"Function: {result['from_func']} → {result['to_func']} (call transition)")
                elif trans_type == "RETURN":
                    constraint_text_parts.append(f"Function: {result['from_func']} → {result['to_func']} (return transition)")
                elif trans_type == "INTRA_FUNCTION":
                    constraint_text_parts.append(f"Function: {result['from_func']} (within-function flow)")
                
                constraint_text_parts.append("\nBranch decisions needed at this transition point:")
                constraint_lines = format_constraints_natural_language(result['dominator_constraints'], "must-satisfy")
                for line in constraint_lines:
                    constraint_text_parts.append(line)
                        
                constraint_text_parts.append("")  # Empty line
            # Skip transitions with no constraints, failures, or unconditional flow
        
        constraint_text_for_prompt = '\n'.join(constraint_text_parts) if has_constraints else None
        
        return full_analysis, constraint_text_for_prompt
        
    except Exception as e:
        logging.error(f"[INTERMEDIATE] Failed to extract intermediate flow constraints: {e}")
        import traceback
        traceback.print_exc()
        return f"Error extracting intermediate flow constraints: {str(e)}", None




def analyze_intermediate_transitions_with_constraints(machine):
    """
    Analyze intermediate transitions and add constraint information to the machine context.

    This function should be called from the intermediate analysis state machine
    to enrich the analysis with constraint information.

    When pre-computed merged constraints are available (from variant merging),
    they are used directly instead of re-extracting from single-variant steps.
    """
    if not hasattr(machine, 'context') or not hasattr(machine.context, 'steps'):
        logging.warning("[INTERMEDIATE] No intermediate transition context available")
        return

    # Get project name and cache dir (needed for both merged and fresh extraction paths)
    project_name = getattr(machine, 'project_name', 'default')
    cache_dir = getattr(machine, 'cache_dir', None)

    # Use pre-computed merged constraints when available (only for multi-variant units)
    merged = getattr(machine, 'merged_constraints', None)
    if merged and getattr(machine, 'has_propagation_variants', False):
        from ..utils.variant_description import format_merged_constraints
        formatted = format_merged_constraints(merged)
        if formatted is not None:
            machine.constraint_text_for_prompt = formatted
            machine.intermediate_flow_constraints = "Using pre-computed merged constraints"
            logging.info("[INTERMEDIATE] Using pre-computed merged constraints from variant analysis")
        else:
            # Merged constraints exist but are empty — fall through to independent extraction
            merged = None
    else:
        # Extract constraints
        full_analysis, constraint_text_for_prompt = extract_constraints_for_intermediate_flow(
            machine.context,
            project_name=project_name,
            cache_dir=cache_dir,
            verbose=True
        )

        # Add to machine context
        machine.intermediate_flow_constraints = full_analysis
        machine.constraint_text_for_prompt = constraint_text_for_prompt

        # Log constraint information (full_analysis already contains the header)
        logging.debug(full_analysis)

    # Also add as context variable for templates
    if hasattr(machine, 'shared_variables'):
        machine.shared_variables['intermediate_flow_constraints'] = getattr(
            machine, 'intermediate_flow_constraints', '')

    # Preload macro definitions using use-def relationship
    try:
        logging.info(f'[INTERMEDIATE] Starting macro preload with cache_dir={cache_dir}')
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
        logging.info(f'[INTERMEDIATE] Macro preload completed: {len(macros)} macros found via use-def')
    except Exception as e:
        import traceback
        logging.warning(f"[INTERMEDIATE] Macro preload failed: {e}\n{traceback.format_exc()}")
        machine.preloaded_macros = {}
        machine.macro_text_for_prompt = None