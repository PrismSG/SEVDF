"""
Logic Unit Management Tools
"""
from typing import Dict, List, Optional, Tuple
import logging
from .logic_unit_context import LogicUnit
from .._01_path_decomposition.path_decomposition_context import PathDecomposition

logger = logging.getLogger(__name__)


def aggregate_logic_units(
    all_decompositions: List[PathDecomposition],
    project_name: str = "default",
    cache_dir: Optional[str] = None
) -> Tuple[Dict[str, LogicUnit], Dict[str, Dict[str, str]]]:
    """
    Aggregate Logic Units from multiple decompositions
    
    Returns:
        tuple: (aggregated_units, path_segment_mappings)
            - aggregated_units: Dict of cache_key -> LogicUnit
            - path_segment_mappings: Dict of path_id -> segment mappings
    """
    aggregated_units = {}
    path_segment_mappings = {}
    
    logger.info(f"Starting aggregation of Logic Units from {len(all_decompositions)} paths")
    
    # First pass: collect all unique segments and their paths
    segment_info = {}  # (cache_key, segment_type) -> {paths: [], first_decomposition: PathDecomposition}
    
    # Debug counters
    debug_total_segments = 0
    debug_cache_key_samples = {'backward': set(), 'intermediate': set(), 'forward': set()}
    
    for decomposition in all_decompositions:
        path_id = decomposition.path_id
        path_segment_mappings[path_id] = decomposition.get_segment_mapping()
        
        # Process each segment type
        segments = [
            ('backward', decomposition.backward_cache_key, decomposition.backward_steps, decomposition.backward_is_virtual),
            ('intermediate', decomposition.intermediate_cache_key, decomposition.intermediate_steps, False),
            ('forward', decomposition.forward_cache_key, decomposition.forward_steps, decomposition.forward_is_virtual),
        ]
        
        for segment_type, cache_key, steps, is_virtual in segments:
            if cache_key and steps:
                debug_total_segments += 1
                
                # Collect samples of cache keys
                if len(debug_cache_key_samples[segment_type]) < 5:
                    debug_cache_key_samples[segment_type].add(cache_key[:32])
                # For intermediate segments, build a context-aware key that
                # captures which backward/forward units surround it.
                # Backward/forward cache_keys are already direction-unique
                # (segment_type is encoded in the hash), so no prefix needed.
                if segment_type == 'intermediate':
                    backward_key = decomposition.backward_cache_key or "none"
                    forward_key = decomposition.forward_cache_key or "none"
                    unit_key = f"{cache_key}__ctx_{backward_key[:8]}_{forward_key[:8]}"
                    path_segment_mappings[path_id]['intermediate'] = unit_key
                    decomposition.intermediate_cache_key = unit_key
                else:
                    unit_key = cache_key

                if unit_key not in segment_info:
                    segment_info[unit_key] = {
                        'segment_type': segment_type,
                        'cache_key': cache_key,
                        'paths': [],
                        'first_decomposition': decomposition,
                        'steps': steps,
                        'steps_relationships': decomposition.steps_relationships,
                        'all_steps_variants': [steps],
                        'all_variant_path_ids': [path_id],
                        'is_virtual': is_virtual,
                    }
                else:
                    segment_info[unit_key]['all_steps_variants'].append(steps)
                    segment_info[unit_key]['all_variant_path_ids'].append(path_id)
                segment_info[unit_key]['paths'].append(path_id)
    
    # Debug: Log aggregation info
    logger.info(f"\nDebug - First pass complete:")
    logger.info(f"  Total segments processed: {debug_total_segments}")
    logger.info(f"  Unique segments found: {len(segment_info)}")
    logger.info(f"  Cache key samples:")
    for seg_type, samples in debug_cache_key_samples.items():
        logger.info(f"    {seg_type}: {list(samples)[:3]}...")
    
    # Find segments with multiple paths
    multi_path_segments = [(k, v) for k, v in segment_info.items() if len(v['paths']) > 1]
    logger.info(f"  Segments used by multiple paths: {len(multi_path_segments)}")
    if multi_path_segments:
        for key, info in multi_path_segments[:5]:
            logger.info(f"    {info['segment_type']} segment {key[:32]}... used by {len(info['paths'])} paths")
    
    # Debug: Check intermediate context keys
    intermediate_original_keys = {}  # original key -> list of context keys
    for unit_key, info in segment_info.items():
        if info['segment_type'] == 'intermediate' and '__ctx_' in unit_key:
            original_key = unit_key.split('__ctx_')[0]
            if original_key not in intermediate_original_keys:
                intermediate_original_keys[original_key] = []
            intermediate_original_keys[original_key].append(unit_key)
    
    # Find intermediate keys with multiple contexts
    multi_context_intermediates = [(k, v) for k, v in intermediate_original_keys.items() if len(v) > 1]
    logger.info(f"\nIntermediate segments with multiple contexts: {len(multi_context_intermediates)}")
    if multi_context_intermediates:
        for orig_key, context_keys in sorted(multi_context_intermediates, key=lambda x: len(x[1]), reverse=True)[:5]:
            logger.info(f"\n  Original intermediate key: {orig_key[:32]}... has {len(context_keys)} different contexts")
            
            # Get the intermediate unit info
            first_context_key = context_keys[0]
            intermediate_info = segment_info[first_context_key]
            if intermediate_info['steps']:
                intermediate_chain = f"{intermediate_info['steps'][0].fromPoint.functionName} -> ... -> {intermediate_info['steps'][-1].toPoint.functionName}"
                logger.info(f"    Intermediate chain: {intermediate_chain}")
            
            # Show each context
            for i, context_key in enumerate(context_keys):
                # Extract backward and forward keys from context key
                if '__ctx_' in context_key:
                    ctx_part = context_key.split('__ctx_')[1]
                    parts = ctx_part.split('_')
                    if len(parts) >= 2:
                        backward_key_prefix = parts[0]
                        forward_key_prefix = parts[1]
                        
                        # Find the full backward and forward keys
                        backward_key = None
                        forward_key = None
                        
                        # Look through all segments to find matching keys
                        for seg_key, seg_info in segment_info.items():
                            if seg_info['segment_type'] == 'backward' and seg_key.startswith(backward_key_prefix):
                                backward_key = seg_key
                            elif seg_info['segment_type'] == 'forward' and seg_key.startswith(forward_key_prefix):
                                forward_key = seg_key
                        
                        logger.info(f"\n    Context {i+1}:")
                        paths_in_context = segment_info[context_key]['paths']
                        logger.info(f"      Paths: {paths_in_context}")
                        
                        # Show backward chain
                        if backward_key and backward_key in segment_info:
                            backward_info = segment_info[backward_key]
                            if backward_info['steps']:
                                backward_chain = f"{backward_info['steps'][0].fromPoint.functionName} -> ... -> {backward_info['steps'][-1].toPoint.functionName}"
                                logger.info(f"      Backward: {backward_chain}")
                        elif backward_key_prefix == "none":
                            logger.info(f"      Backward: (none)")
                        
                        # Show forward chain  
                        if forward_key and forward_key in segment_info:
                            forward_info = segment_info[forward_key]
                            if forward_info['steps']:
                                forward_chain = f"{forward_info['steps'][0].fromPoint.functionName} -> ... -> {forward_info['steps'][-1].toPoint.functionName}"
                                logger.info(f"      Forward: {forward_chain}")
                        elif forward_key_prefix == "none":
                            logger.info(f"      Forward: (none)")
                        
                        # Show complete path for each path in this context
                        for path_id in paths_in_context[:2]:  # Limit to first 2 paths to avoid too much output
                            logger.info(f"\n      Complete path for {path_id}:")
                            
                            # Get the decomposition for this path
                            path_decomposition = None
                            for decomp in all_decompositions:
                                if decomp.path_id == path_id:
                                    path_decomposition = decomp
                                    break
                            
                            if path_decomposition:
                                # Show all steps in order
                                all_path_steps = []
                                
                                # Add backward steps
                                if path_decomposition.backward_steps:
                                    all_path_steps.extend([(s, 'B') for s in path_decomposition.backward_steps])
                                
                                # Add intermediate steps
                                if path_decomposition.intermediate_steps:
                                    all_path_steps.extend([(s, 'I') for s in path_decomposition.intermediate_steps])
                                
                                # Add forward steps
                                if path_decomposition.forward_steps:
                                    all_path_steps.extend([(s, 'F') for s in path_decomposition.forward_steps])
                                
                                # Sort by flowstep to show in order
                                all_path_steps.sort(key=lambda x: x[0].flowstep)
                                
                                # Show first and last few steps
                                if len(all_path_steps) > 10:
                                    # Show first 5 steps
                                    for j, (step, seg_type) in enumerate(all_path_steps[:5]):
                                        logger.info(f"        Step {step.flowstep:3d} [{seg_type}]: {step.fromPoint.functionName}:{step.fromPoint.line} -> {step.toPoint.functionName}:{step.toPoint.line}")
                                    
                                    logger.info(f"        ... ({len(all_path_steps) - 10} more steps) ...")
                                    
                                    # Show last 5 steps
                                    for j, (step, seg_type) in enumerate(all_path_steps[-5:]):
                                        logger.info(f"        Step {step.flowstep:3d} [{seg_type}]: {step.fromPoint.functionName}:{step.fromPoint.line} -> {step.toPoint.functionName}:{step.toPoint.line}")
                                else:
                                    # Show all steps
                                    for j, (step, seg_type) in enumerate(all_path_steps):
                                        logger.info(f"        Step {step.flowstep:3d} [{seg_type}]: {step.fromPoint.functionName}:{step.fromPoint.line} -> {step.toPoint.functionName}:{step.toPoint.line}")
                        
                        if len(paths_in_context) > 2:
                            logger.info(f"      ... and {len(paths_in_context) - 2} more paths")
            
            total_paths = sum(len(segment_info[ck]['paths']) for ck in context_keys)
            logger.info(f"\n    Total paths using this intermediate: {total_paths}")

    # Second pass: create LogicUnit objects with correct path counts
    for unit_key, info in segment_info.items():
        unit = LogicUnit(
            cache_key=unit_key,
            segment_type=info['segment_type'],
            steps=info['steps'],
            steps_relationships=info['steps_relationships'],
            is_virtual=info.get('is_virtual', False),
        )
        unit.extract_shared_variables()

        for path_id in info['paths']:
            unit.add_path(path_id)

        aggregated_units[unit_key] = unit

        if len(info['paths']) > 1:
            logger.info(f"Aggregated {info['segment_type']} unit {unit_key[:16]}... used by {len(info['paths'])} paths: {info['paths'][:5]}...")

    # Merge constraints for units with multiple step variants
    from .constraint_merger import merge_constraints_for_units

    variants_by_key = {
        unit_key: info['all_steps_variants']
        for unit_key, info in segment_info.items()
    }
    path_ids_by_key = {
        unit_key: info['all_variant_path_ids']
        for unit_key, info in segment_info.items()
    }
    merge_constraints_for_units(
        aggregated_units, variants_by_key,
        path_ids_by_key=path_ids_by_key,
        project_name=project_name, cache_dir=cache_dir
    )

    # Log constraint merging statistics
    units_with_constraints = sum(
        1 for u in aggregated_units.values() if u.merged_constraints
    )
    units_with_variants = sum(
        1 for u in aggregated_units.values() if u.has_propagation_variants
    )
    if units_with_constraints > 0:
        logger.info(f"\n=== CONSTRAINT MERGING STATISTICS ===")
        logger.info(f"  Units with constraints: {units_with_constraints}/{len(aggregated_units)}")
        logger.info(f"  Units with propagation variants: {units_with_variants}")

        if units_with_variants > 0:
            total_merged_funcs = sum(
                sum(1 for v in u.merged_constraints.values() if v.get('is_merged'))
                for u in aggregated_units.values()
                if u.merged_constraints
            )
            logger.info(f"  Functions requiring merge: {total_merged_funcs}")

    # Log aggregation statistics with segment type breakdown
    unique_units = len(aggregated_units)
    # Count actual segments (non-None cache keys)
    total_segments = sum(
        sum(1 for v in decomposition.get_segment_mapping().values() if v is not None)
        for decomposition in all_decompositions
    )
    
    # Calculate detailed statistics by segment type
    segment_counts = {'backward': 0, 'intermediate': 0, 'forward': 0}
    segment_reuse = {'backward': [], 'intermediate': [], 'forward': []}
    
    # Track original segments before aggregation
    original_segment_counts = {'backward': 0, 'intermediate': 0, 'forward': 0}
    segment_path_counts = {'backward': set(), 'intermediate': set(), 'forward': set()}
    
    # Count original segments and paths from all decompositions
    for decomposition in all_decompositions:
        if decomposition.backward_cache_key and decomposition.backward_steps:
            original_segment_counts['backward'] += 1
            segment_path_counts['backward'].add(decomposition.path_id)
        if decomposition.intermediate_cache_key and decomposition.intermediate_steps:
            original_segment_counts['intermediate'] += 1
            segment_path_counts['intermediate'].add(decomposition.path_id)
        if decomposition.forward_cache_key and decomposition.forward_steps:
            original_segment_counts['forward'] += 1
            segment_path_counts['forward'].add(decomposition.path_id)
    
    # Collect unit statistics
    for unit in aggregated_units.values():
        segment_counts[unit.segment_type] += 1
        segment_reuse[unit.segment_type].append(unit.get_usage_count())
    
    logger.info(f"\n=== LOGIC UNIT AGGREGATION COMPLETE ===")
    logger.info(f"  Total paths: {len(all_decompositions)}")
    logger.info(f"  Total segments: {total_segments}")
    logger.info(f"  Unique Logic Units: {unique_units}")
    
    # Log segment-specific statistics
    logger.info(f"\n=== SEGMENT TYPE STATISTICS ===")
    for seg_type in ['backward', 'intermediate', 'forward']:
        count = segment_counts[seg_type]
        reuse_counts = segment_reuse[seg_type]
        original_count = original_segment_counts[seg_type]
        paths_with_segment = len(segment_path_counts[seg_type])
        
        logger.info(f"  {seg_type.capitalize()} segments:")
        logger.info(f"    Total segments in all paths: {original_count}")
        logger.info(f"    Paths containing this segment type: {paths_with_segment}")
        logger.info(f"    Unique units after aggregation: {count}")
        
        if count == 0:
            logger.info(f"    Total unit usage: 0")
            logger.info(f"    Average unit reuse: 0.00x")
            logger.info(f"    Max unit reuse: 0x")
            logger.info(f"    Aggregation ratio: N/A")
        else:
            avg_reuse = sum(reuse_counts) / len(reuse_counts) if reuse_counts else 0
            max_reuse = max(reuse_counts) if reuse_counts else 0
            total_unit_usage = sum(reuse_counts) if reuse_counts else 0
            aggregation_ratio = original_count / count if count > 0 else 0
            
            logger.info(f"    Total unit usage: {total_unit_usage}")
            logger.info(f"    Average unit reuse: {avg_reuse:.2f}x")
            logger.info(f"    Max unit reuse: {max_reuse}x")
            logger.info(f"    Aggregation ratio: {aggregation_ratio:.2f}x (from {original_count} to {count})")
    
    # Special analysis for intermediate segments
    logger.info(f"\n=== INTERMEDIATE CONTEXT ANALYSIS ===")
    logger.info(f"  Intermediate units with context: {len(multi_context_intermediates)}")
    logger.info(f"  Original intermediate keys (before context): {len(intermediate_original_keys)}")
    if intermediate_original_keys:
        total_intermediate_paths = sum(
            sum(len(segment_info[ck]['paths']) for ck in context_keys)
            for context_keys in intermediate_original_keys.values()
        )
        logger.info(f"  Potential intermediate reuse ratio: {total_intermediate_paths / max(len(intermediate_original_keys), 1):.2f}x")
    
    # Find units with actual reuse (not affected by context)
    truly_reused_units = []
    for k, v in aggregated_units.items():
        # Skip intermediate units with context keys
        if '__ctx_' not in k and v.get_usage_count() > 1:
            truly_reused_units.append((k, v, v.get_usage_count()))
    
    logger.info(f"\n=== TRULY REUSED UNITS (excluding contextualized intermediate) ===")
    logger.info(f"  Total units with true reuse: {len(truly_reused_units)}")
    
    if truly_reused_units:
        sorted_reused = sorted(truly_reused_units, key=lambda x: x[2], reverse=True)[:10]
        logger.info("\n  Top 10 most reused units:")
        for cache_key, unit, count in sorted_reused:
            func_chain = f"{unit.steps[0].fromPoint.functionName if unit.steps else 'N/A'} -> ... -> {unit.steps[-1].toPoint.functionName if unit.steps else 'N/A'}"
            # Show LCA variable from cache_key (format: "lca_var::hash" or just "hash")
            lca_var = cache_key.split("::")[0] if "::" in cache_key else "(no var)"
            logger.info(f"    [{count:3d} uses] {unit.segment_type:12s} unit: [{lca_var}] {func_chain}")
    else:
        logger.info("  No units are truly reused (all units used by only 1 path)")
    
    return aggregated_units, path_segment_mappings


def get_analysis_order(
    units: Dict[str, LogicUnit]
) -> Tuple[List[LogicUnit], List[LogicUnit], List[LogicUnit]]:
    """
    Get the order for analyzing Logic Units
    
    Returns:
        tuple: (backward_units, forward_units, intermediate_units)
    """
    backward_units = []
    forward_units = []
    intermediate_units = []
    
    for unit in units.values():
        if unit.is_cached:
            continue  # Skip cached units
            
        if unit.segment_type == 'backward':
            backward_units.append(unit)
        elif unit.segment_type == 'forward':
            forward_units.append(unit)
        elif unit.segment_type == 'intermediate':
            intermediate_units.append(unit)
    
    # Sort by usage count (descending) for better cache efficiency
    backward_units.sort(key=lambda u: u.get_usage_count(), reverse=True)
    forward_units.sort(key=lambda u: u.get_usage_count(), reverse=True)
    intermediate_units.sort(key=lambda u: u.get_usage_count(), reverse=True)
    
    return backward_units, forward_units, intermediate_units