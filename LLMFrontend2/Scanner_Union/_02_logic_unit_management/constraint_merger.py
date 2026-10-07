"""
Constraint Merger — Per-function constraint merging for LogicUnits

When multiple path segments are aggregated into a single LogicUnit,
they may have different intra-function propagation paths. This module:
1. Detects per-function propagation differences across step variants
2. Extracts constraints for each unique variant via ConstraintExtractor
3. Merges constraints (must=intersection, may=union+demoted)
"""
import os
import logging
from typing import Dict, List, Optional, Tuple, FrozenSet

from .logic_unit_context import LogicUnit
from .._01_path_decomposition.path_decomposition_context import Step

logger = logging.getLogger(__name__)

# Lazy import to avoid hard dependency if ConstraintExtractor is unavailable
CONSTRAINT_EXTRACTOR_AVAILABLE = False
try:
    from AdvancedTools.ConstraintAnalysis.constraint_extractor_interface import (
        ConstraintExtractor, ProgramPoint
    )
    CONSTRAINT_EXTRACTOR_AVAILABLE = True
except ImportError:
    logger.debug("ConstraintExtractor not available, constraint merging disabled")


def _extract_function_points(
    steps: List[Step]
) -> Dict[str, List[tuple]]:
    """
    Extract points grouped by function from a step list.

    Returns:
        Dict mapping "functionName@file" -> list of (line, startColumn, endColumn) tuples
    """
    function_points = {}

    for step in steps:
        for point in [step.fromPoint, step.toPoint]:
            func_key = f"{point.functionName}@{point.file}"
            if func_key not in function_points:
                function_points[func_key] = []

            start_col = getattr(point, 'startColumn', None) or 0
            end_col = getattr(point, 'endColumn', None) or 0
            function_points[func_key].append((point.line, start_col, end_col))

    # Deduplicate and sort within each function
    for func_key in function_points:
        function_points[func_key] = sorted(set(function_points[func_key]))

    return function_points


def _detect_propagation_variants(
    all_steps_variants: List[List[Step]]
) -> Tuple[Dict[str, List[FrozenSet[tuple]]], Dict[str, List[tuple]]]:
    """
    Detect per-function propagation differences across step variants.

    Returns:
        Tuple of:
        - differing_functions: Dict mapping func_key -> list of unique point sets
          (only functions with >1 unique variant)
        - common_points: Dict mapping func_key -> point list
          (functions identical across all variants, using the first variant's data)
    """
    # Collect per-function point sets from each variant
    all_variant_points = []
    for steps in all_steps_variants:
        all_variant_points.append(_extract_function_points(steps))

    # Gather all function keys across all variants
    all_func_keys = set()
    for vp in all_variant_points:
        all_func_keys.update(vp.keys())

    differing_functions = {}
    common_points = {}

    for func_key in all_func_keys:
        # Collect unique point sets for this function across variants
        unique_point_sets = set()
        for vp in all_variant_points:
            points = vp.get(func_key, [])
            unique_point_sets.add(frozenset(points))

        if len(unique_point_sets) > 1:
            differing_functions[func_key] = list(unique_point_sets)
        else:
            # All variants have the same points — use the first
            first_points = all_variant_points[0].get(func_key, [])
            common_points[func_key] = first_points

    return differing_functions, common_points


def _merge_constraints(
    all_dominator_lists: List[List[Dict]],
    all_optional_lists: List[List[Dict]]
) -> Tuple[List[Dict], List[Dict]]:
    """
    Merge constraints from multiple variants.

    Rules:
    - Must (dominator) remains must only if present in ALL variants (intersection)
    - Must present in some but not all variants is demoted to may
    - All optional constraints are unioned

    Constraint identity: (line, branch) tuple.
    """
    num_variants = len(all_dominator_lists)
    if num_variants == 0:
        return [], []
    if num_variants == 1:
        return all_dominator_lists[0], all_optional_lists[0]

    # Count how many variants each dominator constraint appears in
    dominator_counts = {}  # (line, branch) -> count
    dominator_examples = {}  # (line, branch) -> constraint dict (keep first seen)

    for dom_list in all_dominator_lists:
        seen_in_variant = set()
        for constraint in dom_list:
            key = (constraint.get('line', 0), constraint.get('branch', ''))
            if key in seen_in_variant:
                continue
            seen_in_variant.add(key)
            dominator_counts[key] = dominator_counts.get(key, 0) + 1
            if key not in dominator_examples:
                dominator_examples[key] = constraint

    # Intersection: must in ALL variants
    merged_must = []
    demoted_to_may = []

    for key, count in dominator_counts.items():
        if count == num_variants:
            merged_must.append(dominator_examples[key])
        else:
            # Demote to may — present in some but not all
            demoted = dict(dominator_examples[key])
            demoted['is_dominator'] = False
            demoted['demoted_from_must'] = True
            demoted['variant_coverage'] = f"{count}/{num_variants}"
            demoted_to_may.append(demoted)

    # Union all optional constraints
    seen_optional_keys = set()
    merged_may = list(demoted_to_may)

    # Track keys already in merged_may from demotion
    for c in demoted_to_may:
        seen_optional_keys.add((c.get('line', 0), c.get('branch', '')))

    for opt_list in all_optional_lists:
        for constraint in opt_list:
            key = (constraint.get('line', 0), constraint.get('branch', ''))
            if key not in seen_optional_keys:
                seen_optional_keys.add(key)
                merged_may.append(constraint)

    # Sort by line number
    merged_must.sort(key=lambda x: x.get('line', 0))
    merged_may.sort(key=lambda x: x.get('line', 0))

    return merged_must, merged_may


def _extract_constraints_for_function(
    extractor: 'ConstraintExtractor',
    func_key: str,
    point_tuples: List[tuple]
) -> Dict:
    """
    Extract constraints for a set of points in a single function.

    Args:
        extractor: Initialized ConstraintExtractor
        func_key: "functionName@filePath"
        point_tuples: List of (line, startColumn, endColumn) tuples

    Returns:
        Dict with 'dominator_constraints' and 'optional_constraints' lists
    """
    empty_result = {'dominator_constraints': [], 'optional_constraints': []}

    if not point_tuples:
        return empty_result

    # Parse func_key
    at_idx = func_key.rfind('@')
    if at_idx == -1:
        logger.warning(f"Invalid func_key format: {func_key}")
        return empty_result

    func_name = func_key[:at_idx]
    file_path = func_key[at_idx + 1:]

    # Resolve file path
    if not os.path.isabs(file_path):
        ai_analysis_dir = os.environ.get('AI_ANALYSIS_DIR', '')
        if ai_analysis_dir:
            possible_path = os.path.join(ai_analysis_dir, 'sourcecode', file_path)
            if os.path.exists(possible_path):
                file_path = possible_path

    # Create ProgramPoint objects
    target_points = []
    for line, start_col, end_col in point_tuples:
        if start_col and end_col:
            target_points.append(ProgramPoint.from_location(line, start_col, line, end_col))
        else:
            target_points.append(ProgramPoint.from_line(line))

    # Get function start line
    func_start = None
    if hasattr(extractor, 'cfg_db') and extractor.cfg_db:
        try:
            functions = extractor.cfg_db.get_function_info(func_name, file_path)
            if functions:
                func_start = int(functions[0][2])
        except Exception:
            pass

    if func_start is None:
        try:
            from AdvancedTools.CodeSearch.symbol_lookup import get_function_start_line_from_csv
            func_start = get_function_start_line_from_csv(func_name, file_path)
        except (ImportError, Exception):
            pass

    if func_start is None:
        logger.debug(f"Cannot find function start line for {func_name}, skipping constraints")
        return empty_result

    # Extract constraints
    try:
        result = extractor.extract_constraints_for_points(
            target_points=target_points,
            function_name=func_name,
            file_path=file_path,
            function_start_line=func_start,
            verbose=False
        )
        return {
            'dominator_constraints': result.get('dominator_constraints', []),
            'optional_constraints': result.get('optional_constraints', [])
        }
    except Exception as e:
        logger.debug(f"Constraint extraction failed for {func_name}: {e}")
        return empty_result


def _extract_single_variant_constraints(
    extractor: 'ConstraintExtractor',
    unit: LogicUnit,
    steps: List[Step]
) -> None:
    """Extract constraints for a unit with a single variant (no merging)."""
    function_points = _extract_function_points(steps)
    unit.merged_constraints = {}

    for func_key, points in function_points.items():
        result = _extract_constraints_for_function(extractor, func_key, points)
        unit.merged_constraints[func_key] = {
            'dominator_constraints': result['dominator_constraints'],
            'optional_constraints': result['optional_constraints'],
            'variant_count': 1,
            'is_merged': False
        }


def _extract_steps_for_function(steps: List[Step], func_key: str) -> List[Step]:
    """
    Filter steps whose fromPoint or toPoint belongs to the given function.

    Args:
        steps: List of Step objects from one variant.
        func_key: "functionName@filePath" identifying the function.

    Returns:
        List of Step objects that touch this function.
    """
    result = []
    for step in steps:
        from_key = f"{step.fromPoint.functionName}@{step.fromPoint.file}"
        to_key = f"{step.toPoint.functionName}@{step.toPoint.file}"
        if from_key == func_key or to_key == func_key:
            result.append(step)
    return result


def _build_variant_details(
    all_steps_variants: List[List[Step]],
    differing_functions: Dict[str, List[FrozenSet[tuple]]],
    path_ids: List[str]
) -> Dict[str, Dict]:
    """
    Build variant_details for differing functions.

    For each differing function, groups variants by their unique point sets,
    then extracts steps, line numbers, and code snippets for each group.

    Args:
        all_steps_variants: List of step lists, one per variant.
        differing_functions: Dict mapping func_key -> list of unique point sets.
        path_ids: List of path_id strings aligned with all_steps_variants.

    Returns:
        Dict mapping func_key -> { "variant_count": N, "variants": [...] }
    """
    # Pre-compute per-variant function points for grouping
    variant_point_sets = []
    for steps in all_steps_variants:
        variant_point_sets.append(_extract_function_points(steps))

    result = {}

    for func_key, unique_point_sets in differing_functions.items():
        # Group variants by their point set for this function
        groups = {}  # frozenset -> { "indices": [], "point_set": frozenset }
        for vi, vps in enumerate(variant_point_sets):
            points = vps.get(func_key, [])
            key = frozenset(points)
            if key not in groups:
                groups[key] = {"indices": []}
            groups[key]["indices"].append(vi)

        variants_list = []
        for point_set, group_info in groups.items():
            indices = group_info["indices"]
            # Use the first variant in this group as representative
            rep_idx = indices[0]
            rep_steps = all_steps_variants[rep_idx]

            # Filter steps belonging to this function
            func_steps = _extract_steps_for_function(rep_steps, func_key)

            # Collect sorted line numbers from the point set
            lines = sorted(set(pt[0] for pt in point_set)) if point_set else []

            # Extract code snippets from the function's steps
            code_snippets = {}
            at_idx = func_key.rfind('@')
            func_name = func_key[:at_idx] if at_idx != -1 else func_key

            for step in func_steps:
                if step.fromPoint.functionName == func_name and step.fromPoint.relatedCode:
                    if func_name not in code_snippets:
                        code_snippets[func_name] = step.fromPoint.relatedCode
                if step.toPoint.functionName == func_name and step.toPoint.relatedCode:
                    if func_name not in code_snippets:
                        code_snippets[func_name] = step.toPoint.relatedCode

            # Collect path_ids for this group
            group_path_ids = []
            for idx in indices:
                if idx < len(path_ids):
                    group_path_ids.append(path_ids[idx])

            variants_list.append({
                "path_ids": group_path_ids,
                "steps": func_steps,
                "lines": lines,
                "code_snippets": code_snippets
            })

        result[func_key] = {
            "variant_count": len(variants_list),
            "variants": variants_list
        }

    return result


def merge_constraints_for_units(
    aggregated_units: Dict[str, LogicUnit],
    variants_by_key: Dict[str, List[List[Step]]],
    path_ids_by_key: Optional[Dict[str, List[str]]] = None,
    project_name: str = "default",
    cache_dir: Optional[str] = None
) -> None:
    """
    For each LogicUnit with multiple step variants, detect per-function
    propagation differences, extract constraints for each variant,
    and merge (must=intersection, may=union+demoted).

    Mutates LogicUnit.merged_constraints and has_propagation_variants in place.
    """
    if not CONSTRAINT_EXTRACTOR_AVAILABLE:
        logger.info("[ConstraintMerger] ConstraintExtractor not available, skipping")
        return

    # Initialize extractor once for all units
    try:
        extractor = ConstraintExtractor(project_name=project_name, cache_dir=cache_dir)
    except Exception as e:
        logger.warning(f"[ConstraintMerger] Failed to initialize ConstraintExtractor: {e}")
        return

    units_with_variants = 0
    functions_merged = 0

    for key, unit in aggregated_units.items():
        variants = variants_by_key.get(key, [])

        if len(variants) <= 1:
            # Single variant — extract constraints directly, no merging needed
            _extract_single_variant_constraints(extractor, unit, variants[0] if variants else unit.steps)
            continue

        # Multiple variants — detect per-function differences
        differing_functions, common_points = _detect_propagation_variants(variants)

        if not differing_functions:
            # All variants have identical propagation in every function
            _extract_single_variant_constraints(extractor, unit, variants[0])
            continue

        units_with_variants += 1
        unit.has_propagation_variants = True
        unit.merged_constraints = {}

        # Build variant_details for this unit
        pids = (path_ids_by_key or {}).get(key, [])
        unit.variant_details = _build_variant_details(variants, differing_functions, pids)

        # Process functions with identical propagation (extract once)
        for func_key, points in common_points.items():
            result = _extract_constraints_for_function(extractor, func_key, points)
            unit.merged_constraints[func_key] = {
                'dominator_constraints': result['dominator_constraints'],
                'optional_constraints': result['optional_constraints'],
                'variant_count': 1,
                'is_merged': False
            }

        # Process functions with different propagation (extract per-variant, merge)
        for func_key, unique_point_sets in differing_functions.items():
            functions_merged += 1
            all_dominators = []
            all_optionals = []

            for point_set in unique_point_sets:
                sorted_points = sorted(point_set)
                result = _extract_constraints_for_function(extractor, func_key, sorted_points)
                all_dominators.append(result['dominator_constraints'])
                all_optionals.append(result['optional_constraints'])

            merged_must, merged_may = _merge_constraints(all_dominators, all_optionals)

            unit.merged_constraints[func_key] = {
                'dominator_constraints': merged_must,
                'optional_constraints': merged_may,
                'variant_count': len(unique_point_sets),
                'is_merged': True
            }

            logger.debug(
                f"[ConstraintMerger] {func_key}: merged {len(unique_point_sets)} variants "
                f"-> {len(merged_must)} must, {len(merged_may)} may"
            )

    logger.info(
        f"[ConstraintMerger] Complete: {units_with_variants} units with variants, "
        f"{functions_merged} functions merged"
    )
