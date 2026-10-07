"""
Path Decomposition Tools for Scanner-Union
Uses local path-splitting tools and call-relationship analysis.
"""
import logging
from typing import List, Dict, Tuple, Optional, Any
from colorama import Fore
import hashlib

# Core data types
from .path_decomposition_context import FlowStepDivide, Step, Point

# Path processing tools (canonical location: path_splitting_tools)
from .path_splitting_tools import (
    parse_json_to_flow_step_divide,
    classify_steps,
    analyze_call_relationships,
    calculate_call_depth,
    split_call_path as split_path_segments
)

# Virtual step enrichment
from .virtual_step_enrichment import enrich_with_virtual_steps

# Import from Knowledge Storage
from AdvancedTools.KnowledgeStorage.knowledge_storage import (
    extract_unique_function_chain
)

logger = logging.getLogger(__name__)


def normalize_file_path(file_path: str) -> str:
    """Normalize file path by removing directory prefixes like 's01/'"""
    return file_path.split('/')[-1] if '/' in file_path else file_path


def create_step_key(step: Step) -> Tuple:
    """Create a key for a step using the original file paths.

    Must match the key format used by the state machines when looking up
    relationships:  (fromPoint.file, fromPoint.line, toPoint.file, toPoint.line, flowstep)
    """
    return (
        step.fromPoint.file,
        step.fromPoint.line,
        step.toPoint.file,
        step.toPoint.line,
        step.flowstep
    )


def split_call_path(flow_step: FlowStepDivide, codeql_db_path: str = "") -> Tuple[List[Step], List[Step], List[Step], Dict, bool, bool]:
    """
    Split a complete flow path into backward, intermediate, and forward segments.
    Uses the local path-splitting implementation with the flow context.
    
    Args:
        flow_step: FlowStepDivide object containing all steps
        
    Returns:
        tuple: (backward_steps, intermediate_steps, forward_steps, steps_relationships)
    """
    steps = flow_step.steps
    
    # Step 1: Classify steps
    same_function_steps, cross_function_steps = classify_steps(steps)
    
    # STRICT: verify all steps are classified
    total_classified = len(same_function_steps) + len(cross_function_steps)
    if total_classified != len(steps):
        raise ValueError(f"Step classification failed! Total steps: {len(steps)}, "
                        f"Same-function: {len(same_function_steps)}, "
                        f"Cross-function: {len(cross_function_steps)}. "
                        f"Missing {len(steps) - total_classified} steps in classification.")
    
    # Create a dictionary to store step relationships
    steps_relationships = {}
    
    # First, validate and populate relationships for ALL steps
    # IMPORTANT: Must add ALL steps to dictionary, not just same-function ones
    logger.info(f"  Initializing relationships for {len(steps)} steps")
    logger.info(f"  Total steps to process: {len(steps)}")
    logger.info(f"  Same-function steps: {len(same_function_steps)}")
    logger.info(f"  Cross-function steps: {len(cross_function_steps)}")
    
    # Log flowstep range to help debug
    flowsteps = [s.flowstep for s in steps]
    logger.info(f"  Flowstep range in original steps: {min(flowsteps) if flowsteps else 'N/A'} to {max(flowsteps) if flowsteps else 'N/A'}")
    logger.info(f"  Unique flowsteps: {sorted(set(flowsteps))[:10]}..." if len(set(flowsteps)) > 10 else f"  Unique flowsteps: {sorted(set(flowsteps))}")
    
    for i, step in enumerate(steps):
        key = create_step_key(step)
        
        # Debug: Check file path format
        if i == 0:
            logger.info(Fore.YELLOW + f"\n  === FILE PATH FORMAT CHECK ===" + Fore.RESET)
            logger.info(Fore.YELLOW + f"  First step file path: {step.fromPoint.file}" + Fore.RESET)
            logger.info(Fore.YELLOW + f"  Has 's01/' prefix: {'s01/' in step.fromPoint.file}" + Fore.RESET)
            logger.info(Fore.YELLOW + f"  === END FORMAT CHECK ===" + Fore.RESET)
        
        # Add ALL steps to the dictionary
        if step.sameFunction:
            steps_relationships[key] = 'SAME'
        else:
            # Cross-function steps get a temporary placeholder
            # Will be updated to CALL/RETURN after analysis
            steps_relationships[key] = 'PENDING_ANALYSIS'
            
        # Log ALL steps to debug missing relationships
        logger.info(f"  Step {i}: flowstep={step.flowstep}, {step.fromPoint.functionName}:{step.fromPoint.line} -> {step.toPoint.functionName}:{step.toPoint.line} (sameFunction={step.sameFunction}) => {steps_relationships[key]}")
    
    logger.info(f"  After initial population: {len(steps_relationships)} entries in dictionary")
    
    # Override with specific SAME relations for classified same-function steps
    for step in same_function_steps:
        key = create_step_key(step)
        steps_relationships[key] = 'SAME'
        logger.info(f"  Override with SAME relation for step: flowstep={step.flowstep}")
    
    if not cross_function_steps:
        # All steps are within the same function - no split needed.
        # Intermediate gets all steps; virtual B/F steps will be created
        # by enrich_with_virtual_steps() at the end.
        logger.warning(f"All {len(steps)} steps are within the same function, treating as intermediate path")
        logger.info(f"  Function: {steps[0].fromPoint.functionName if steps else 'N/A'}")
        all_backward_steps = []
        all_intermediate_steps = steps
        all_forward_steps = []
    else:
        # Step 2-4: Cross-function analysis and splitting
        all_backward_steps, all_intermediate_steps, all_forward_steps = \
            _analyze_and_split_cross_function(
                steps, cross_function_steps, same_function_steps,
                steps_relationships, codeql_db_path
            )

    # Enrich with virtual B/F steps where segments are missing
    (all_backward_steps, all_intermediate_steps, all_forward_steps,
     steps_relationships, backward_is_virtual, forward_is_virtual) = enrich_with_virtual_steps(
        all_backward_steps, all_intermediate_steps, all_forward_steps,
        steps_relationships
    )

    return (all_backward_steps, all_intermediate_steps, all_forward_steps,
            steps_relationships, backward_is_virtual, forward_is_virtual)


def _analyze_and_split_cross_function(
    steps, cross_function_steps, same_function_steps,
    steps_relationships, codeql_db_path
):
    """Steps 2-4: Analyze call relationships, calculate depth, split path."""
    # Step 2: Analyze call relationships using the local state machine.
    try:
        # We need to provide config_path and codeql_db_path for the analysis
        config_path = ""  # Will be set by state machine
        
        logger.info(f"  Analyzing call relationships for {len(cross_function_steps)} cross-function steps...")
        logger.info(f"  Using CodeQL database: {codeql_db_path if codeql_db_path else 'Not provided'}")
        call_relationships, step_types = analyze_call_relationships(
            cross_function_steps, config_path, codeql_db_path
        )
        
        logger.info(f"  Step types: {step_types[:5]}..." if len(step_types) > 5 else f"  Step types: {step_types}")
        
        # Update PENDING_ANALYSIS entries with actual relation types
        for i, step in enumerate(cross_function_steps):
            if i < len(step_types):
                # Update the placeholder with actual relation type
                key = create_step_key(step)
                old_value = steps_relationships.get(key, 'NOT_FOUND')
                steps_relationships[key] = step_types[i]
                logger.info(f"  Updated cross-function step {i}: flowstep={step.flowstep}, {old_value} -> {step_types[i]} for {step.fromPoint.functionName} -> {step.toPoint.functionName}")
        
        logger.info(f"  After analyzing cross-function steps: {len(steps_relationships)} entries in dictionary")
        
    except Exception as e:
        logger.error(f"  Failed to analyze call relationships: {e}")
        # NO FALLBACK - this is a critical error
        raise ValueError(f"Cannot determine call relationships for cross-function steps. "
                        f"CodeQL analysis failed: {e}. "
                        f"Ensure CodeQL database is available and properly configured.")
    
    # Step 3: Calculate call depth to find split point
    call_depth, min_depth_func, min_depth, min_depth_func_id = calculate_call_depth(
        cross_function_steps, step_types
    )
    
    logger.info(f"  Call depth analysis: shallowest function = {min_depth_func} (depth={min_depth})")
    if not min_depth_func:
        logger.warning("  No shallowest function found! All steps will be forward.")
    
    # Step 4: Split the path at the shallowest function
    result = split_path_segments(
        steps, cross_function_steps, step_types, min_depth_func, min_depth_func_id
    )
    
    # Extract the three segments from the result
    # The unified split_call_path now returns a consistent tuple
    all_backward_steps = result[0]
    all_intermediate_steps = result[1]
    all_forward_steps = result[2]
    
    # Log what the split produced
    logger.info(f"\n  === PATH SPLIT RESULTS ===")
    logger.info(f"  Original steps count: {len(steps)}")
    logger.info(f"  Backward steps: {len(all_backward_steps)}")
    logger.info(f"  Intermediate steps: {len(all_intermediate_steps)}")
    logger.info(f"  Forward steps: {len(all_forward_steps)}")
    logger.info(f"  Total after split: {len(all_backward_steps) + len(all_intermediate_steps) + len(all_forward_steps)}")
    
    # Log flowstep ranges for each segment
    if all_backward_steps:
        backward_flowsteps = [s.flowstep for s in all_backward_steps]
        logger.info(f"  Backward flowsteps: {min(backward_flowsteps)}-{max(backward_flowsteps)}")
    if all_intermediate_steps:
        intermediate_flowsteps = [s.flowstep for s in all_intermediate_steps]
        logger.info(f"  Intermediate flowsteps: {min(intermediate_flowsteps)}-{max(intermediate_flowsteps)}")
    if all_forward_steps:
        forward_flowsteps = [s.flowstep for s in all_forward_steps]
        logger.info(f"  Forward flowsteps: {min(forward_flowsteps)}-{max(forward_flowsteps)}")
    logger.info(f"  === END PATH SPLIT RESULTS ===")
    
    # CRITICAL VALIDATION: Verify ALL steps in segments have relationships
    # This must happen immediately after split to catch any issues
    logger.info("  === VALIDATING SEGMENT RELATIONSHIPS ===")
    
    # First, log the complete relationships dictionary
    logger.info(f"\n  === COMPLETE RELATIONSHIPS DICTIONARY ===")
    logger.info(f"  Total entries in steps_relationships: {len(steps_relationships)}")
    
    # Sort by flowstep for easier reading
    sorted_relationships = sorted(steps_relationships.items(), key=lambda x: x[0][4])  # Sort by flowstep (index 4)
    
    # Log ALL entries to debug missing relationships
    logger.info(f"  Showing ALL {len(sorted_relationships)} entries (sorted by flowstep):")
    
    # Create a map of (file, line) -> function name for quick lookup
    location_to_func = {}
    for step in steps:
        location_to_func[(step.fromPoint.file, step.fromPoint.line)] = step.fromPoint.functionName
        location_to_func[(step.toPoint.file, step.toPoint.line)] = step.toPoint.functionName
    
    for i, (key, relation) in enumerate(sorted_relationships):
        from_file, from_line, to_file, to_line, flowstep = key
        # Extract just the filename from the path
        from_file_short = from_file.split('/')[-1] if '/' in from_file else from_file
        to_file_short = to_file.split('/')[-1] if '/' in to_file else to_file
        
        # Get function names
        from_func = location_to_func.get((from_file, from_line), "unknown")
        to_func = location_to_func.get((to_file, to_line), "unknown")
        
        logger.info(f"    [{flowstep:3d}] {from_func}@{from_file_short}:{from_line} -> {to_func}@{to_file_short}:{to_line} => {relation}")
    
    # Show flowstep coverage - show ALL flowsteps
    all_flowsteps_in_dict = sorted(set(k[4] for k in steps_relationships.keys()))
    logger.info(f"  Flowsteps in dictionary: {all_flowsteps_in_dict}")
    logger.info(f"  === END RELATIONSHIPS DICTIONARY ===")
    
    segment_validation_errors = []
    segments_with_errors = set()
    
    for segment_name, segment_steps in [("backward", all_backward_steps),
                                       ("intermediate", all_intermediate_steps),
                                       ("forward", all_forward_steps)]:
        logger.info(f"  Checking {segment_name} segment with {len(segment_steps)} steps...")
        segment_has_error = False
        
        for i, step in enumerate(segment_steps):
            key = create_step_key(step)
            
            if key not in steps_relationships:
                error_msg = (f"{segment_name} segment step {i}: MISSING relationship for "
                           f"{step.fromPoint.functionName}:{step.fromPoint.line} -> "
                           f"{step.toPoint.functionName}:{step.toPoint.line} "
                           f"(flowstep={step.flowstep})")
                segment_validation_errors.append(error_msg)
                logger.error(f"  ERROR: {error_msg}")
                
                # Log additional debug info
                logger.error(f"    Key not found: {key}")
                logger.error(f"    Step details: sameFunction={step.sameFunction}")
                logger.error(f"    Available keys sample: {list(steps_relationships.keys())[:3]}...")
                
                segment_has_error = True
                segments_with_errors.add(segment_name)
        
        # If this segment has errors, print ALL relationships in the segment
        if segment_has_error:
            logger.error(f"\n  === PRINTING ALL RELATIONSHIPS IN {segment_name.upper()} SEGMENT ===")
            logger.error(f"  Total steps in {segment_name} segment: {len(segment_steps)}")
            
            for i, step in enumerate(segment_steps):
                key = create_step_key(step)
                
                relation = steps_relationships.get(key, "NOT_FOUND")
                # Extract filenames
                from_file_short = step.fromPoint.file.split('/')[-1] if '/' in step.fromPoint.file else step.fromPoint.file
                to_file_short = step.toPoint.file.split('/')[-1] if '/' in step.toPoint.file else step.toPoint.file
                
                logger.error(f"  Step {i}: flowstep={step.flowstep}, "
                           f"{step.fromPoint.functionName}@{from_file_short}:{step.fromPoint.line} -> "
                           f"{step.toPoint.functionName}@{to_file_short}:{step.toPoint.line} "
                           f"[sameFunction={step.sameFunction}] => relation={relation}")
            
            logger.error(f"  === END OF {segment_name.upper()} SEGMENT RELATIONSHIPS ===")
    
    if segment_validation_errors:
        logger.error(f"  === SEGMENT VALIDATION FAILED ===")
        logger.error(f"  Total errors: {len(segment_validation_errors)}")
        
        # Collect all missing flowsteps for summary
        missing_flowsteps = []
        for error_msg in segment_validation_errors:
            # Extract flowstep from error message
            import re
            match = re.search(r'flowstep=(\d+)', error_msg)
            if match:
                missing_flowsteps.append(int(match.group(1)))
        
        if missing_flowsteps:
            logger.error(f"\n  === SUMMARY OF MISSING FLOWSTEPS ===")
            logger.error(f"  Missing flowsteps: {sorted(set(missing_flowsteps))}")
            logger.error(f"  Total unique missing flowsteps: {len(set(missing_flowsteps))}")
            
            # Show flowstep distribution in original steps vs relationships
            all_flowsteps = [s.flowstep for s in steps]
            relationship_flowsteps = [k[4] for k in steps_relationships.keys()]  # flowstep is at index 4
            logger.error(f"  Original steps flowsteps range: {min(all_flowsteps)} - {max(all_flowsteps)}")
            logger.error(f"  Relationships flowsteps range: {min(relationship_flowsteps) if relationship_flowsteps else 'N/A'} - {max(relationship_flowsteps) if relationship_flowsteps else 'N/A'}")
            logger.error(f"  === END SUMMARY ===")
        
        raise ValueError(
            f"CRITICAL: {len(segment_validation_errors)} steps in segments have no relationship!\n"
            f"This indicates a bug in either:\n"
            f"1. Initial relationship population (some steps not added)\n"
            f"2. Step classification (steps misclassified)\n"
            f"3. Split algorithm (returning steps not in original list)\n\n"
            f"Errors:\n" + "\n".join(segment_validation_errors[:10]) +
            (f"\n... and {len(segment_validation_errors)-10} more" if len(segment_validation_errors) > 10 else "")
        )
    else:
        logger.info("  === SEGMENT VALIDATION PASSED ===")
    
    # STRICT VALIDATION: Every step must have a relationship
    logger.debug(f"Validating all segment steps have relationships...")
    validation_errors = []
    for segment_name, segment_steps in [("backward", all_backward_steps), 
                                       ("intermediate", all_intermediate_steps), 
                                       ("forward", all_forward_steps)]:
        if segment_steps:
            logger.debug(f"{segment_name} segment has {len(segment_steps)} steps")
            for i, step in enumerate(segment_steps):
                key = create_step_key(step)
                if key not in steps_relationships:
                    error_msg = (f"{segment_name} segment step {i}: missing relationship for "
                               f"{step.fromPoint.functionName}:{step.fromPoint.line} -> "
                               f"{step.toPoint.functionName}:{step.toPoint.line}")
                    validation_errors.append(error_msg)
                    logger.error(f"  {error_msg}")
    
    if validation_errors:
        raise ValueError(f"Relationship validation failed. {len(validation_errors)} steps have no relationship:\n" + 
                        "\n".join(validation_errors[:5]) + 
                        (f"\n... and {len(validation_errors)-5} more" if len(validation_errors) > 5 else ""))
    
    # FINAL VALIDATION: Ensure every original step has a relationship
    logger.info(f"  Total steps: {len(steps)}, Total relationships: {len(steps_relationships)}")
    
    # Check that every original step has a relationship and no PENDING_ANALYSIS remains
    missing_relationships = []
    pending_analysis = []
    
    for step in steps:
        key = create_step_key(step)
        if key not in steps_relationships:
            missing_relationships.append(f"{step.fromPoint.functionName}:{step.fromPoint.line} -> "
                                       f"{step.toPoint.functionName}:{step.toPoint.line} (flowstep={step.flowstep})")
        elif steps_relationships[key] == 'PENDING_ANALYSIS':
            pending_analysis.append(f"{step.fromPoint.functionName}:{step.fromPoint.line} -> "
                                  f"{step.toPoint.functionName}:{step.toPoint.line} (flowstep={step.flowstep})")
    
    if missing_relationships:
        raise ValueError(f"Failed to determine relationships for {len(missing_relationships)} steps:\n" +
                        "\n".join(missing_relationships[:10]) +
                        (f"\n... and {len(missing_relationships)-10} more" if len(missing_relationships) > 10 else ""))
    
    if pending_analysis:
        logger.warning(f"Warning: {len(pending_analysis)} cross-function steps were not analyzed properly")
        # Update them to a default value rather than failing
        for step in steps:
            key = create_step_key(step)
            if steps_relationships.get(key) == 'PENDING_ANALYSIS':
                steps_relationships[key] = 'CALL'  # Default assumption
                logger.warning(f"  Defaulted to CALL for: {key}")
    
    # Handle empty intermediate steps.
    if len(all_intermediate_steps) == 0 and len(all_forward_steps) > 0:
        logger.warning("No intermediate steps found but forward steps exist. Creating virtual intermediate step.")
        first_forward_step = all_forward_steps[0]
        source_point = first_forward_step.fromPoint
        virtual_step = Step(
            flowstep=0,
            fromPoint=source_point,
            toPoint=source_point,
            relatedCode=source_point.relatedCode,
            sameFunction=True
        )
        all_intermediate_steps = [virtual_step]
        virtual_key = (source_point.file, source_point.line,
                      source_point.file, source_point.line, 0)
        steps_relationships[virtual_key] = 'VIRTUAL'
        logger.info(f"Created virtual intermediate step at {source_point.functionName}:{source_point.line}")

    return all_backward_steps, all_intermediate_steps, all_forward_steps


def create_segment_descriptor(
    steps: List[Step],
    segment_type: str,
    steps_relationships: Dict = None
) -> Tuple[str, Dict[str, Any]]:
    """
    Create a segment descriptor (cache_key + metadata) from a list of steps.

    Cache Key Design (CFL-Reachability):
        The LCA variable is included in the cache key to prevent false negatives
        when paths share the same function chain but track different variables.

        - backward:     lca_variable = steps[-1].toPoint.variable  (endpoint/LCA)
        - intermediate: lca_variable = steps[0].fromPoint.variable (startpoint/LCA)
        - forward:      lca_variable = steps[0].fromPoint.variable (startpoint/LCA)

    Args:
        steps: List of Step objects
        segment_type: Type of segment ('backward', 'intermediate', 'forward')

    Returns:
        tuple: (cache_key, segment_descriptor)
    """
    if not steps:
        return None, None

    # Generate base cache key from function chain.
    # Pass segment_type so that backward and forward analyses of the same
    # function chain produce distinct hashes (prevents LogicUnit key collisions).
    function_list, base_cache_key = extract_unique_function_chain(steps, segment_type=segment_type)

    # Add LCA variable to cache key based on segment type
    # This prevents FN where paths with same call chain but different tracked
    # variables would incorrectly share cached results.
    if segment_type == 'backward':
        # Backward chain traces source -> LCA, endpoint is LCA
        lca_variable = steps[-1].toPoint.variable if steps else ""
    else:
        # Forward/Intermediate: startpoint is LCA
        lca_variable = steps[0].fromPoint.variable if steps else ""

    cache_key = f"{lca_variable}::{base_cache_key}" if lca_variable else base_cache_key
    
    # Create segment descriptor as abstract representation
    # No concrete steps or relationships - those belong to each path
    segment_descriptor = {
        'cache_key': cache_key,
        'segment_type': segment_type,
        'function_chain': function_list,
        'step_count': len(steps),
        'first_function': steps[0].fromPoint.functionName if steps else None,
        'last_function': steps[-1].toPoint.functionName if steps else None,
        # Remove concrete path-specific data:
        # 'steps': steps,  # ❌ Removed - each path keeps its own steps
        # 'steps_relationships': steps_relationships  # ❌ Removed - path-specific
    }
    
    return cache_key, segment_descriptor


def decompose_path(
    path_id: str,
    flow_step: FlowStepDivide,
    codeql_db_path: str = ""
) -> Dict[str, Any]:
    """
    Decompose a single path into segments.
    
    Args:
        path_id: Unique identifier for the path
        flow_step: FlowStepDivide object containing the path
        codeql_db_path: Path to CodeQL database for call relationship analysis

    Returns:
        dict: Path decomposition containing:
            - path_id
            - segments: Dict of segment_type -> cache_key
            - segment_descriptors: Dict of cache_key -> segment_descriptor
    """
    # Split the path
    (backward_steps, intermediate_steps, forward_steps,
     steps_relationships, backward_is_virtual, forward_is_virtual) = split_call_path(flow_step, codeql_db_path)
    
    # Log the split
    logger.info(f"Path {path_id} decomposition result:")
    logger.info(f"  Total steps: {len(flow_step.steps)}")
    logger.info(f"  Backward steps: {len(backward_steps)}")
    logger.info(f"  Intermediate steps: {len(intermediate_steps)}")
    logger.info(f"  Forward steps: {len(forward_steps)}")
    
    if len(backward_steps) == 0:
        logger.warning(f"  No backward steps for path {path_id}!")
    
    # Create segment descriptors for each segment
    segments = {}
    segment_descriptors = {}
    
    # Process backward segment
    if backward_steps:
        logger.info(f"Path {path_id}: Creating backward segment with {len(backward_steps)} steps")
        logger.info(f"  First step: {backward_steps[0].fromPoint.functionName} -> {backward_steps[0].toPoint.functionName}")
        logger.info(f"  Last step: {backward_steps[-1].fromPoint.functionName} -> {backward_steps[-1].toPoint.functionName}")
        
        cache_key, seg_data = create_segment_descriptor(
            backward_steps, 'backward', steps_relationships
        )
        if cache_key:
            segments['backward'] = cache_key
            segment_descriptors[cache_key] = seg_data
            logger.info(f"  Created backward segment descriptor with cache_key: {cache_key[:16]}...")
        else:
            logger.warning(f"  Failed to create backward segment descriptor for path {path_id}")
    
    # Process intermediate segment
    if intermediate_steps:
        # Check if this is a virtual intermediate step
        is_virtual = False
        if len(intermediate_steps) == 1 and intermediate_steps[0].flowstep == 0:
            is_virtual = True
            logger.info(f"Path {path_id}: Processing VIRTUAL intermediate step")
        
        cache_key, seg_data = create_segment_descriptor(
            intermediate_steps, 'intermediate', steps_relationships
        )
        if cache_key:
            segments['intermediate'] = cache_key
            segment_descriptors[cache_key] = seg_data
            if is_virtual:
                logger.info(f"  Created virtual intermediate segment descriptor with cache_key: {cache_key[:16]}...")
    
    # Process forward segment
    if forward_steps:
        cache_key, seg_data = create_segment_descriptor(
            forward_steps, 'forward', steps_relationships
        )
        if cache_key:
            segments['forward'] = cache_key
            segment_descriptors[cache_key] = seg_data
    
    # FINAL PATH VALIDATION: Check all segments have proper relationships before returning
    logger.info(f"\n  === FINAL PATH VALIDATION for path {path_id} ===")
    final_validation_errors = []
    
    for segment_name, segment_steps in [("backward", backward_steps),
                                        ("intermediate", intermediate_steps),
                                        ("forward", forward_steps)]:
        if segment_steps:
            logger.info(f"  Validating {segment_name} segment ({len(segment_steps)} steps)...")
            missing_count = 0
            
            for i, step in enumerate(segment_steps):
                key = create_step_key(step)
                
                if key not in steps_relationships:
                    missing_count += 1
                    error_msg = (f"{segment_name} step {i}: flowstep={step.flowstep} MISSING")
                    final_validation_errors.append(error_msg)
                    logger.error(f"    {error_msg}")
                else:
                    relation = steps_relationships[key]
                    # Extract filenames
                    from_file_short = step.fromPoint.file.split('/')[-1] if '/' in step.fromPoint.file else step.fromPoint.file
                    to_file_short = step.toPoint.file.split('/')[-1] if '/' in step.toPoint.file else step.toPoint.file
                    
                    # Log every step's relationship for debugging
                    logger.info(f"    Step {i}: flowstep={step.flowstep}, {step.fromPoint.functionName}@{from_file_short}:{step.fromPoint.line} -> {step.toPoint.functionName}@{to_file_short}:{step.toPoint.line} => {relation}")
            
            if missing_count > 0:
                logger.error(f"  {segment_name} segment: {missing_count}/{len(segment_steps)} steps MISSING relationships!")
            else:
                logger.info(f"  {segment_name} segment: ALL steps have relationships ✓")
    
    if final_validation_errors:
        logger.error(f"  === FINAL VALIDATION FAILED: {len(final_validation_errors)} missing relationships ===")
        # Don't raise here, just log - let the earlier validation handle the error
    else:
        logger.info(f"  === FINAL VALIDATION PASSED for path {path_id} ===")
    
    return {
        'path_id': path_id,
        'segments': segments,
        'segment_descriptors': segment_descriptors,
        'total_steps': len(flow_step.steps),
        'segment_count': len(segments),
        'steps_relationships': steps_relationships,
        '_flow_step': flow_step,  # Store for later reconstruction
        # Add concrete steps for each segment (path-specific data)
        'backward_steps': backward_steps,
        'intermediate_steps': intermediate_steps,
        'forward_steps': forward_steps,
        # Virtual segment flags
        'backward_is_virtual': backward_is_virtual,
        'forward_is_virtual': forward_is_virtual,
    }


def batch_decompose_paths(
    path_info_list: List[Any],
    codeql_db_path: str = ""
) -> Dict[str, Any]:
    """
    Batch decompose multiple paths into segments.
    
    Args:
        path_info_list: List of path info (can be dicts, strings, or special format with _flow_step)
        codeql_db_path: Path to CodeQL database for analysis
        
    Returns:
        path_decompositions: Dict of path_id -> decomposition
    """
    path_decompositions = {}

    total_paths = len(path_info_list)
    logger.info(f"{Fore.CYAN}╔{'═' * 78}╗{Fore.RESET}")
    logger.info(f"{Fore.CYAN}║ BATCH PATH DECOMPOSITION - Starting {total_paths} paths{' ' * (78 - 47 - len(str(total_paths)))}║{Fore.RESET}")
    logger.info(f"{Fore.CYAN}╚{'═' * 78}╝{Fore.RESET}")

    import time
    batch_start_time = time.time()

    for idx, path_info in enumerate(path_info_list):
        path_id = f"path_{idx}"
        path_start_time = time.time()

        # Progress indicator
        progress_pct = (idx / total_paths) * 100
        logger.info(f"\n{Fore.YELLOW}[{idx + 1}/{total_paths}] ({progress_pct:.1f}%) Processing {path_id}...{Fore.RESET}")

        try:
            # Handle different input formats
            flow_step = None

            if isinstance(path_info, dict) and '_flow_step' in path_info:
                # Special format from unified_scheduler
                flow_step = path_info['_flow_step']
            elif isinstance(path_info, str):
                flow_step = parse_json_to_flow_step_divide(path_info)
            elif isinstance(path_info, dict):
                import json
                flow_step = parse_json_to_flow_step_divide(json.dumps(path_info))
            elif hasattr(path_info, 'steps'):
                # Direct FlowStepDivide object
                flow_step = path_info
            else:
                logger.warning(f"Unknown path_info type for {path_id}: {type(path_info)}")
                continue

            # Log path structure before decomposition
            if flow_step and flow_step.steps:
                logger.info(f"  Path: {flow_step.steps[0].fromPoint.functionName} -> ... -> {flow_step.steps[-1].toPoint.functionName}")
                logger.info(f"  Total steps: {len(flow_step.steps)}")

            # Decompose the path with CodeQL database path
            logger.info(f"  {Fore.GREEN}→ Starting decomposition...{Fore.RESET}")
            decomposition = decompose_path(path_id, flow_step, codeql_db_path)
            path_decompositions[path_id] = decomposition

            # Log completion with timing
            path_elapsed = time.time() - path_start_time
            logger.info(f"  {Fore.GREEN}✓ Completed in {path_elapsed:.2f}s - Generated {decomposition['segment_count']} segments{Fore.RESET}")

            # Estimate remaining time
            if idx > 0:
                avg_time_per_path = (time.time() - batch_start_time) / (idx + 1)
                remaining_paths = total_paths - (idx + 1)
                estimated_remaining = avg_time_per_path * remaining_paths
                logger.info(f"  {Fore.CYAN}⏱ Estimated time remaining: {estimated_remaining:.1f}s ({remaining_paths} paths left){Fore.RESET}")

        except Exception as e:
            logger.error(f"  {Fore.RED}✗ Failed to decompose path {path_id}: {e}{Fore.RESET}")
            import traceback
            traceback.print_exc()
            continue
    
    # Log statistics and validation summary
    total_paths = len(path_decompositions)
    total_segments = sum(d['segment_count'] for d in path_decompositions.values())
    
    # Count segment distribution
    segment_distribution = {0: 0, 1: 0, 2: 0, 3: 0}
    paths_by_segment_type = {'backward': 0, 'intermediate': 0, 'forward': 0}
    
    for decomp in path_decompositions.values():
        seg_count = decomp['segment_count']
        if seg_count in segment_distribution:
            segment_distribution[seg_count] += 1
        else:
            segment_distribution[seg_count] = 1
            
        # Count by segment type
        if 'backward' in decomp['segments']:
            paths_by_segment_type['backward'] += 1
        if 'intermediate' in decomp['segments']:
            paths_by_segment_type['intermediate'] += 1
        if 'forward' in decomp['segments']:
            paths_by_segment_type['forward'] += 1
    
    # Count paths with missing relationships
    paths_with_missing_relations = 0
    total_missing_relations = 0

    # Calculate total elapsed time
    batch_elapsed = time.time() - batch_start_time
    avg_time_per_path = batch_elapsed / total_paths if total_paths > 0 else 0

    logger.info(f"\n{Fore.CYAN}╔{'═' * 78}╗{Fore.RESET}")
    logger.info(f"{Fore.CYAN}║ BATCH DECOMPOSITION COMPLETE{' ' * 49}║{Fore.RESET}")
    logger.info(f"{Fore.CYAN}╚{'═' * 78}╝{Fore.RESET}")
    logger.info(f"{Fore.GREEN}✓ Successfully processed {total_paths} paths in {batch_elapsed:.2f}s{Fore.RESET}")
    logger.info(f"{Fore.GREEN}  Average time per path: {avg_time_per_path:.2f}s{Fore.RESET}")
    logger.info(f"{Fore.GREEN}  Total segments generated: {total_segments}{Fore.RESET}")
    logger.info(f"\n  Segment count distribution:")
    for count, num_paths in sorted(segment_distribution.items()):
        logger.info(f"    Paths with {count} segments: {num_paths}")
    logger.info(f"\n  Paths by segment type:")
    for seg_type, count in paths_by_segment_type.items():
        logger.info(f"    Paths with {seg_type}: {count}")
    
    # Analyze segment patterns
    segment_patterns = {}
    virtual_intermediate_count = 0
    for decomp in path_decompositions.values():
        pattern = []
        if 'backward' in decomp['segments']:
            pattern.append('B')
        if 'intermediate' in decomp['segments']:
            pattern.append('I')
            # Check if it's virtual
            if 'intermediate_steps' in decomp and len(decomp['intermediate_steps']) == 1:
                step = decomp['intermediate_steps'][0]
                if hasattr(step, 'flowstep') and step.flowstep == 0:
                    virtual_intermediate_count += 1
        if 'forward' in decomp['segments']:
            pattern.append('F')
        pattern_str = '-'.join(pattern) if pattern else 'NONE'
        segment_patterns[pattern_str] = segment_patterns.get(pattern_str, 0) + 1
    
    logger.info(f"\n  Segment patterns:")
    for pattern, count in sorted(segment_patterns.items()):
        logger.info(f"    {pattern}: {count} paths")
    if virtual_intermediate_count > 0:
        logger.info(f"\n  Virtual intermediate steps: {virtual_intermediate_count}")
    
    # Check for any paths with relationship issues
    logger.info(f"\n=== RELATIONSHIP VALIDATION SUMMARY ===")
    for path_id, decomposition in path_decompositions.items():
        if '_flow_step' in decomposition:
            flow_step = decomposition['_flow_step']
            steps_relationships = decomposition.get('steps_relationships', {})
            
            missing_in_path = 0
            for step in flow_step.steps:
                key = create_step_key(step)
                if key not in steps_relationships:
                    missing_in_path += 1
            
            if missing_in_path > 0:
                paths_with_missing_relations += 1
                total_missing_relations += missing_in_path
                logger.warning(f"  Path {path_id}: {missing_in_path} steps missing relationships")
    
    if paths_with_missing_relations > 0:
        logger.error(f"  TOTAL: {paths_with_missing_relations} paths have missing relationships")
        logger.error(f"  TOTAL: {total_missing_relations} steps missing relationships across all paths")
    else:
        logger.info(f"  ALL PATHS VALIDATED SUCCESSFULLY ✓")
    
    return path_decompositions
