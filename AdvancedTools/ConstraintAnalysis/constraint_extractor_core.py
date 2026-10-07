#!/usr/bin/env python3
"""
Constraint Extractor Core - Low-level constraint extraction implementation

This module provides the core constraint analysis functionality that uses pre-built CFGs
from the CFG Manager. It contains complex, low-level interfaces for advanced use cases.

For user-friendly API, use constraint_extractor.py instead of this module.
"""

import os
import json
import logging
import time
from typing import List, Tuple, Dict, Optional, NamedTuple
try:
    from .cfg.cfg_defs import Function, BasicBlock
except ImportError:
    from cfg.cfg_defs import Function, BasicBlock
# FunctionCFGManager import removed to avoid circular dependency
# It will be passed as a parameter instead

# Import cache configuration from project standards
try:
    from AdvancedTools.KnowledgeStorage.cache_config import log_cache_activity
except ImportError:
    def log_cache_activity(message):
        pass


class ProgramPoint(NamedTuple):
    """Represents a precise program point with line and column information."""
    start_line: int
    start_column: int
    end_line: int
    end_column: int
    
    @classmethod
    def from_line(cls, line_number: int) -> 'ProgramPoint':
        """Create a ProgramPoint from a simple line number (for backward compatibility).
        
        Uses -1 as end_column to indicate "entire line" for better matching logic.
        """
        return cls(start_line=line_number, start_column=0, end_line=line_number, end_column=-1)
    
    @classmethod
    def from_location(cls, start_line: int, start_column: int, end_line: int, end_column: int) -> 'ProgramPoint':
        """Create a ProgramPoint from precise location information."""
        return cls(start_line=start_line, start_column=start_column, end_line=end_line, end_column=end_column)
    
    def overlaps_with_block(self, basic_block) -> bool:
        """Check if this program point overlaps with the given basic block.
        
        This method checks for actual overlap between the program point's range and the block's range.
        """
        # Delegate to the module-level function
        return overlaps_with_block(self, basic_block)


class ConstraintExtractor:
    """
    Extracts path constraints using pre-built CFGs.
    
    This class assumes CFGs have already been built and cached by the CFG Manager.
    It focuses purely on constraint analysis without the overhead of CFG building.
    """
    
    def __init__(self, cfg_manager=None, project_name: str = "default_project", database_path: str = None):
        self.project_name = project_name
        self.cfg_manager = cfg_manager
        self.database_path = database_path  # Store database path for source file resolution
    
    def _detect_cycles_in_cfg(self, function_cfg) -> list:
        """Detect cycles in a CFG using DFS.
        
        Returns:
            List of cycles found, where each cycle is a list of block IDs
        """
        cycles = []
        
        # Build adjacency list
        adjacency = {}
        for bb in function_cfg.basic_blocks:
            adjacency[bb.block_id] = []
            for succ_bb, edge_type in bb.successor_blocks.items():
                adjacency[bb.block_id].append(succ_bb.block_id)
        
        # DFS to detect cycles
        visited = set()
        rec_stack = set()
        current_path = []
        
        def dfs(node):
            visited.add(node)
            rec_stack.add(node)
            current_path.append(node)
            
            if node in adjacency:
                for neighbor in adjacency[node]:
                    if neighbor not in visited:
                        if dfs(neighbor):
                            return True
                    elif neighbor in rec_stack:
                        # Found a cycle - extract it from current path
                        cycle_start = current_path.index(neighbor)
                        cycle = current_path[cycle_start:] + [neighbor]
                        # Only record if this is an unrolled cycle (no _L suffix)
                        if not any('_L' in block_id for block_id in cycle):
                            cycles.append(cycle)
            
            current_path.pop()
            rec_stack.remove(node)
            return False
        
        # Check all nodes
        for bb in function_cfg.basic_blocks:
            if bb.block_id not in visited:
                dfs(bb.block_id)
        
        return cycles
        
    def extract_path_constraints_from_cached_cfg(
        self,
        function_name: str,
        file_path: str,
        start_line: int,
        target_program_points: List[ProgramPoint],
        required_program_points: List[ProgramPoint] = None,
        verbose: bool = False,
        ignore_unrolled: bool = False,
        limit_paths: bool = True
    ) -> Tuple[List[Tuple], List[Dict]]:
        """
        Extract path constraints using a cached CFG.

        Args:
            function_name: Name of the function
            file_path: Path to the source file
            start_line: Starting line number of the function
            target_program_points: List of ProgramPoint objects to analyze constraints for
            required_program_points: List of ProgramPoint objects that paths must pass through
            verbose: Whether to enable verbose DEBUG logging (does not affect path exploration)
            ignore_unrolled: Whether to skip loop-unrolled blocks (_L suffix)
            limit_paths: Whether to limit path exploration to max_paths (default True for performance)

        Returns:
            Tuple containing:
            - List of path tuples (execution paths that pass through required points)
            - List of constraint dictionaries with dominator constraints
        """
        # Get cached function CFG
        logging.debug(f"[CFG] Looking for cached CFG for function '{function_name}' in '{file_path}' starting at line {start_line}")
        function_cfg = self.cfg_manager.get_cached_function(function_name, file_path, start_line)
        
        # Log CFG complexity statistics
        if function_cfg and verbose:
            total_blocks = len(function_cfg.basic_blocks)
            level0_blocks = sum(1 for bb in function_cfg.basic_blocks if '_L' not in bb.block_id)
            level1_blocks = sum(1 for bb in function_cfg.basic_blocks if bb.block_id.count('_L') == 1)
            level2plus_blocks = sum(1 for bb in function_cfg.basic_blocks if bb.block_id.count('_L') >= 2)
            
            if level2plus_blocks > 0:
                logging.debug(f"CFG complexity for {function_name}: {total_blocks} blocks total")
                logging.debug(f"  - Level 0 (original): {level0_blocks} blocks")
                logging.debug(f"  - Level 1 unrolled: {level1_blocks} blocks")
                logging.debug(f"  - Level 2+ unrolled: {level2plus_blocks} blocks (may limit path exploration)")
        
        if not function_cfg:
            logging.warning(f"[CFG] No cached CFG found for {function_name}@{file_path}:{start_line}")
            return [], []
        
        logging.debug(f"[CFG] Found cached CFG with {len(function_cfg.basic_blocks)} basic blocks")
        
        # Detect cycles in the CFG
        cycles = self._detect_cycles_in_cfg(function_cfg)
        has_many_cycles = len(cycles) > 10  # Flag for functions with many cycles
        
        if cycles:
            logging.debug(f"\n[WARNING] Detected {len(cycles)} cycles in CFG for {function_name}:")
            for i, cycle in enumerate(cycles[:3]):  # Show first 3 cycles
                logging.debug(f"  Cycle {i+1}: {' -> '.join(cycle[:5])}" + 
                      (f" ... ({len(cycle)} blocks total)" if len(cycle) > 5 else ""))
            if len(cycles) > 3:
                logging.debug(f"  ... and {len(cycles) - 3} more cycles")
            logging.debug("  Note: These are non-unrolled cycles (may cause deep recursion)")
            
            if has_many_cycles:
                logging.debug("\n[IMPORTANT] This function has many cycles which will cause path explosion")
                logging.debug("  Consider using a different analysis approach for this function")
                
                # Note: We could force ignore_unrolled=True here for functions with many cycles,
                # but we'll let the caller decide whether to use fallback strategies
        else:
            if verbose:
                logging.debug(f"No cycles detected in CFG for {function_name} (loop unrolling successful)")
        
        log_cache_activity(f"CONSTRAINT EXTRACTION: Using cached CFG for {function_name}")
        
        # Find target basic blocks - use SMALLEST blocks for each program point
        target_blocks = []
        logging.debug(f"[CFG] Looking for blocks containing {len(target_program_points)} target points")
        for target_point in target_program_points:
            # First show ALL blocks containing this point
            all_matching_blocks = []
            for bb in function_cfg.basic_blocks:
                if self._program_point_overlaps_with_block(target_point, bb):
                    all_matching_blocks.append(bb)
            
            if verbose and all_matching_blocks:
                # Format target point for better display
                if hasattr(target_point, 'end_column') and target_point.end_column == -1:
                    point_desc = f"line {target_point.start_line}"
                else:
                    point_desc = str(target_point)
                
                logging.debug(f"\nALL blocks containing target {point_desc}:")
                # Sort by block size (approximated by block ID length since it contains line ranges)
                sorted_blocks = sorted(all_matching_blocks, 
                                     key=lambda b: self._estimate_block_size(b))
                for bb in sorted_blocks:
                    pred_count = self._count_predecessors(bb, function_cfg)
                    logging.debug(f"  - {bb.block_id} (size: {self._estimate_block_size(bb)} lines, {pred_count} predecessors)")
            
            # Select SMALLEST blocks for each target point to maximize precision
            smallest_blocks = self._select_smallest_blocks_for_point(target_point, function_cfg, verbose)
            if verbose:
                logging.debug(f"\nSelected {len(smallest_blocks)} smallest blocks:")
                for bb in smallest_blocks:
                    logging.debug(f"  - {bb.block_id} (size: {self._estimate_block_size(bb)} lines)")
            target_blocks.extend(smallest_blocks)
        
        if not target_blocks:
            logging.debug(f"[CFG] No basic blocks found for any target points")
            logging.debug(f"[CFG] Searched {len(function_cfg.basic_blocks)} blocks in function {function_name}")
            # Log first 10 blocks to understand the CFG structure
            logging.debug(f"[CFG] First 10 blocks in CFG:")
            # Convert set to list for slicing
            blocks_list = list(function_cfg.basic_blocks)
            for i, bb in enumerate(blocks_list[:10]):
                logging.debug(f"  Block {i}: {bb.block_id}")
            return [], []
        
        # Remove duplicates while preserving order
        seen = set()
        unique_target_blocks = []
        for block in target_blocks:
            if block.block_id not in seen:
                seen.add(block.block_id)
                unique_target_blocks.append(block)
        target_blocks = unique_target_blocks
        
        # Find required basic blocks (if any)
        required_blocks_by_point = []
        if required_program_points:
            for required_point in required_program_points:
                # Use the same selection logic as target points
                matching_blocks = self._select_smallest_blocks_for_point(required_point, function_cfg, verbose)
                
                if matching_blocks:
                    required_blocks_by_point.append(matching_blocks)
                else:
                    if verbose:
                        logging.warning(f"No basic block found for required program point {required_point}")
                    # If we can't find a required block, we can't satisfy the constraint
                    return [], []
        
        # Analyze paths using the cached CFG
        all_paths = []
        all_dominator_constraints = []
        all_optional_constraints = []
        all_constraints = []  # Collect all constraints from valid paths
        paths_with_constraints = []  # Store (path, constraints) tuples
        
        # Add timeout tracking - 10 seconds for path collection
        start_time = time.time()
        timeout_seconds = 10.0
        timeout_reached = False

        # Create a CFG builder instance from the cached function for traversal
        cfg_builder = self._create_cfg_builder_from_function(function_cfg, limit_paths=limit_paths)
        
        # Process each target block
        logging.debug(f"[PATHS] Processing {len(target_blocks)} target blocks for constraint extraction")
        logging.debug(f"[PATHS] Note: All target blocks share the same path limit ({cfg_builder.max_paths if cfg_builder.limit_paths else 'unlimited'})")
        for i, target_block in enumerate(target_blocks):
            logging.debug(f"[PATHS] Processing target block {i+1}/{len(target_blocks)}: {target_block.block_id}")

            # Check if path limit already reached from previous target blocks
            if cfg_builder.path_limit_reached:
                logging.info(f"[PATHS] Skipping target block {target_block.block_id} - path limit already reached from previous blocks")
                continue
            # Skip invalid starting points for backward traversal
            if not self._is_valid_path_start(target_block, function_cfg):
                if verbose:
                    logging.debug(f"Skipping invalid path start: {target_block.block_id} (no predecessors)")
                continue
            
            # For smallest blocks, we want to analyze ALL iterations, even if some seem orphaned
            # This is because loop unrolling creates multiple versions and we need complete analysis
            if verbose and '_L' in target_block.block_id:
                # Still check if it has a path to entry for debugging
                cfg_builder_test = self._create_cfg_builder_from_function(function_cfg, limit_paths=limit_paths)
                test_paths = list(cfg_builder_test.traverse_backward_with_constraints(target_block, False, ignore_unrolled))
                has_valid_path = any(len(path) > 3 for path, _ in test_paths)
                if not has_valid_path:
                    logging.warning(f"Block {target_block.block_id} may have limited paths to entry")
            
            
            # Traverse backward from target block
            path_count = 0
            if verbose:
                logging.debug(f"Starting backward traversal from {target_block.block_id}")
            
            for path, constraints in cfg_builder.traverse_backward_with_constraints(target_block, verbose, ignore_unrolled):
                path_count += 1
                if verbose and path_count % 10 == 0:
                    logging.debug(f"[TRAVERSAL] Examined {path_count} paths from {target_block.block_id}")
                
                # Check for timeout
                elapsed_time = time.time() - start_time
                if elapsed_time > timeout_seconds:
                    timeout_reached = True
                    if verbose:
                        logging.warning(f"Timeout reached after {elapsed_time:.1f} seconds. Collected {len(all_paths)} valid paths so far.")
                    break
                
                # Log progress periodically
                if verbose and path_count % 50 == 0:
                    logging.debug(f"Processed {path_count} paths, collected {len(all_paths)} valid paths so far...")
                
                # Check if path passes through all required points
                if required_blocks_by_point:
                    if not self._path_passes_through_required_points(path, required_blocks_by_point, verbose and path_count <= 10):
                        if verbose and path_count <= 10:
                            logging.debug(f"[PATH] Path {path_count} doesn't pass through all required points")
                        continue
                
                # Validate path
                if self._is_valid_path(path):
                    all_paths.append(path)
                    if verbose and len(all_paths) % 10 == 0:
                        logging.debug(f"[VALID] Collected {len(all_paths)} valid paths so far")
                    
                    # Collect constraints from this valid path with iteration context
                    path_constraints = []
                    for constraint in constraints:
                        # Extract iteration context from the block ID
                        block_id = constraint.get('block_id', '')
                        iteration_context = self._extract_iteration_context(block_id)
                        
                        # Add iteration context to constraint
                        constraint_with_context = constraint.copy()
                        constraint_with_context['iteration_context'] = iteration_context
                        
                        # Track this specific path's constraints
                        path_constraints.append(constraint_with_context)
                    
                    # Store path with its constraints
                    paths_with_constraints.append((path, path_constraints))
                    
                    # Stop if we've collected enough paths
                    if len(all_paths) >= 200:
                        if verbose:
                            logging.debug(f"Collected {len(all_paths)} valid paths, stopping early")
                        break
                else:
                    if verbose and path_count <= 10:
                        logging.debug(f"[PATH] Path {path_count} failed validation")
            
            # Break outer loop if timeout or enough paths
            if timeout_reached or len(all_paths) >= 200:
                break

        # ADAPTIVE DEPTH: If no paths found, retry with increased depth
        # This handles cases where all paths are deeper than max_depth
        current_max_depth = 20  # Track the depth we're using
        max_depth_retries = 0
        max_depth_retry_limit = 3

        while len(all_paths) == 0 and not timeout_reached and max_depth_retries < max_depth_retry_limit:
            # Check if we hit depth limits many times (suggests paths are deeper)
            if cfg_builder.depth_exceeded_count > 0:
                max_depth_retries += 1
                current_max_depth *= 2  # Double the depth each time (20 -> 40 -> 80 -> 160)

                logging.warning(f"[ADAPTIVE_DEPTH] No paths found with max_depth={current_max_depth//2}. Hit depth limit {cfg_builder.depth_exceeded_count} times.")
                logging.info(f"[ADAPTIVE_DEPTH] Retry #{max_depth_retries}/{max_depth_retry_limit} with increased max_depth={current_max_depth}")

                # Create new CFG builder with increased depth
                cfg_builder = self._create_cfg_builder_from_function(function_cfg, limit_paths=limit_paths, max_depth=current_max_depth)

                # Retry traversal with same target blocks
                for target_block in target_blocks:
                    if not self._is_valid_path_start(target_block, function_cfg):
                        continue

                    for path, constraints in cfg_builder.traverse_backward_with_constraints(target_block, verbose, ignore_unrolled):
                        # Check for timeout
                        elapsed_time = time.time() - start_time
                        if elapsed_time > timeout_seconds:
                            timeout_reached = True
                            logging.warning(f"[ADAPTIVE_DEPTH] Timeout during depth retry after {elapsed_time:.1f}s")
                            break

                        # Same validation logic
                        if required_blocks_by_point:
                            if not self._path_passes_through_required_points(path, required_blocks_by_point, False):
                                continue

                        if self._is_valid_path(path):
                            all_paths.append(path)

                            # Collect constraints
                            path_constraints = []
                            for constraint in constraints:
                                block_id = constraint.get('block_id', '')
                                iteration_context = self._extract_iteration_context(block_id)
                                constraint_with_context = constraint.copy()
                                constraint_with_context['iteration_context'] = iteration_context
                                path_constraints.append(constraint_with_context)

                            all_constraints.extend(path_constraints)
                            paths_with_constraints.append((path, path_constraints))

                    if timeout_reached or len(all_paths) >= 200:
                        break

                if len(all_paths) > 0:
                    logging.info(f"[ADAPTIVE_DEPTH] Success! Found {len(all_paths)} paths with max_depth={current_max_depth}")
                    break
            else:
                # No depth limits hit, so increasing depth won't help
                logging.debug(f"[ADAPTIVE_DEPTH] No paths found but depth limit never hit. Increasing depth won't help.")
                break

        # Check if we should retry with ignore_unrolled=True
        # Only retry if:
        # 1. We found very few paths (suggesting the depth limit blocked most exploration)
        # 2. We hit depth limits many times
        # 3. We haven't reached timeout yet (still have time to retry)
        if not ignore_unrolled and cfg_builder.suggest_ignore_unrolled and len(all_paths) < 10 and not timeout_reached:
            if verbose:
                logging.debug(f"Found only {len(all_paths)} paths with excessive depth limits. Automatically retrying with ignore_unrolled=True...")
            
            # Clear and retry with simplified analysis
            all_paths = []
            all_constraints = []
            paths_with_constraints = []

            # Create new CFG builder for retry
            cfg_builder_retry = self._create_cfg_builder_from_function(
                function_cfg, limit_paths=limit_paths, max_depth=cfg_builder.max_depth
            )
            
            # Retry with ignore_unrolled=True
            for target_block in target_blocks:
                if not self._is_valid_path_start(target_block, function_cfg):
                    if verbose:
                        logging.debug(f"Skipping non-conditional block: {target_block.block_id}")
                    continue
                
                for path, constraints in cfg_builder_retry.traverse_backward_with_constraints(target_block, verbose, True):
                    # Check for timeout even in retry
                    elapsed_time = time.time() - start_time
                    if elapsed_time > timeout_seconds:
                        if verbose:
                            logging.warning(f"Timeout reached during retry after {elapsed_time:.1f} seconds total.")
                        timeout_reached = True
                        break
                    
                    # Same processing logic as above
                    if required_blocks_by_point:
                        if not self._path_passes_through_required_points(path, required_blocks_by_point, False):
                            continue
                    
                    if self._is_valid_path(path):
                        all_paths.append(path)
                        
                        if len(all_paths) >= 200:
                            if verbose:
                                logging.debug(f"Collected {len(all_paths)} valid paths in retry, stopping early")
                            break
                        
                        # Collect constraints with iteration context
                        path_constraints = []
                        for constraint in constraints:
                            block_id = constraint.get('block_id', '')
                            iteration_context = self._extract_iteration_context(block_id)
                            
                            constraint_with_context = constraint.copy()
                            constraint_with_context['iteration_context'] = iteration_context
                            path_constraints.append(constraint_with_context)
                        
                        paths_with_constraints.append((path, path_constraints))
                
                if timeout_reached or len(all_paths) >= 200:
                    break
        
        # Log timeout situation if we couldn't find enough paths
        if timeout_reached and len(all_paths) < 10 and verbose:
            logging.warning(f"Analysis stopped due to timeout after {timeout_seconds} seconds. Only found {len(all_paths)} valid paths.")
            logging.debug("Consider using ignore_unrolled=True or increasing timeout for complex functions.")
        
        # Analyze constraints across all paths to find dominators
        if all_paths:
            logging.debug(f"[ANALYSIS] Starting constraint analysis on {len(all_paths)} valid paths")
            # Limit analysis to first 200 paths for efficiency
            MAX_PATHS_TO_ANALYZE = 200
            if len(all_paths) > MAX_PATHS_TO_ANALYZE:
                if verbose:
                    logging.debug(f"Limiting analysis to first {MAX_PATHS_TO_ANALYZE} paths out of {len(all_paths)} total paths")
                all_paths = all_paths[:MAX_PATHS_TO_ANALYZE]
                paths_with_constraints = paths_with_constraints[:MAX_PATHS_TO_ANALYZE]
            
            # Group constraints by (condition_line, branch_taken) for dominator analysis
            # NOTE: We intentionally ignore iteration_context here because a dominator
            # constraint should hold regardless of which loop iteration it appears in
            constraint_groups = {}
            total_paths = len(all_paths)
            
            # First pass: count occurrences
            for i, (path, path_constraints) in enumerate(paths_with_constraints):
                # Log path details
                logging.debug(f"\n[PATH {i+1}/{total_paths}] Path length: {len(path)} blocks")
                logging.debug(f"[PATH {i+1}/{total_paths}] Blocks: {' -> '.join([bb.block_id for bb in path[:10]])}{'...' if len(path) > 10 else ''}")
                logging.debug(f"[PATH {i+1}/{total_paths}] Constraints in path: {len(path_constraints)}")
                
                # Process each constraint in this specific path
                seen_in_path = set()
                for constraint in path_constraints:
                    # Key without iteration context for dominator analysis
                    key = (
                        constraint.get('line'),      # Use the correct field name
                        constraint.get('branch')     # Use the correct field name
                    )
                    
                    if key not in seen_in_path:
                        seen_in_path.add(key)
                        if key not in constraint_groups:
                            constraint_groups[key] = {
                                'count': 0,
                                'constraint': constraint,
                                'contexts': set()  # Track all contexts where this appears
                            }
                        constraint_groups[key]['count'] += 1
                        # Track the iteration context for reporting
                        constraint_groups[key]['contexts'].add(
                            constraint.get('iteration_context', 'unknown')
                        )
            
            # Separate dominators (on all paths) from optional constraints
            # Also identify "must-take branches" - conditions where only one branch can reach the target
            if verbose:
                logging.debug(f"\nConstraint analysis summary:")
                logging.debug(f"Total paths analyzed: {total_paths}")
                logging.debug(f"Constraint groups found: {len(constraint_groups)}")
            
            # Group by line number to check for must-take branches
            constraints_by_line = {}
            logging.debug(f"\n[MUST_CONSTRAINT] Building constraints_by_line from {len(constraint_groups)} constraint groups")
            for key, group in constraint_groups.items():
                line, branch = key
                if line not in constraints_by_line:
                    constraints_by_line[line] = {}
                constraints_by_line[line][branch] = group
                logging.debug(f"[MUST_CONSTRAINT] Line {line}: added {branch} branch")
            
            logging.debug(f"\n[MUST_CONSTRAINT] Analyzing {len(constraint_groups)} constraint groups")
            
            # First, identify all lines that have unpaired branches (for must-take analysis)
            unpaired_lines = set()
            for line_num, branches in constraints_by_line.items():
                if len(branches) == 1:  # Only one branch direction exists
                    unpaired_lines.add(line_num)
                    logging.debug(f"[MUST_CONSTRAINT] Line {line_num} is unpaired - only has {list(branches.keys())[0]} branch")
            
            # Now analyze each constraint group
            for key, group in constraint_groups.items():
                line, branch = key
                contexts = group['contexts']
                context_str = ", ".join(sorted(contexts)) if contexts else "none"
                logging.debug(f"\n[MUST_CONSTRAINT] Processing Line {line}: {branch}")
                logging.debug(f"  - Appears in {group['count']}/{total_paths} paths")
                logging.debug(f"  - Contexts: {context_str}")
                    
                if group['count'] == total_paths:
                    # Type 1: This constraint appears in ALL paths (dominator)
                    logging.debug(f"  - DECISION: Dominator (appears in ALL paths)")
                    constraint = group['constraint'].copy()
                    constraint['is_dominator'] = True
                    all_dominator_constraints.append(constraint)
                elif line in unpaired_lines:
                    # Type 2: This is an unpaired branch (must-take)
                    line_constraints = constraints_by_line.get(line, {})
                    logging.debug(f"  - Branches at line {line}: {list(line_constraints.keys())}")
                    logging.debug(f"  - DECISION: Must-take branch (no pair - other branch doesn't reach target)")
                    constraint = group['constraint'].copy()
                    constraint['must_take'] = True
                    constraint['description'] = f"Must take {branch} branch (other branch doesn't lead to target)"
                    all_dominator_constraints.append(constraint)
                else:
                    # Regular optional constraint - has pairs and not in all paths
                    line_constraints = constraints_by_line.get(line, {})
                    logging.debug(f"  - Branches at line {line}: {list(line_constraints.keys())}")
                    logging.debug(f"  - DECISION: Optional constraint (has pairs, not in all paths)")
                    constraint = group['constraint'].copy()
                    constraint['path_coverage'] = f"{group['count']}/{total_paths}"
                    all_optional_constraints.append(constraint)
            
            # Sort constraints by line number for readability
            all_dominator_constraints.sort(key=lambda x: x.get('line', 0))
            all_optional_constraints.sort(key=lambda x: x.get('line', 0))
        
        if verbose:
            # Note: paths may have been limited for analysis
            logging.debug(f"Analyzed {len(all_paths)} paths with {len(all_dominator_constraints)} dominator constraints " +
                  f"and {len(all_optional_constraints)} optional constraints")
            
            # Group paths by target block for summary
            paths_by_target = {}
            for path in all_paths:
                if path:
                    target = path[0].block_id  # First block in backward path is the target
                    paths_by_target[target] = paths_by_target.get(target, 0) + 1
            
            logging.debug("\nPaths grouped by target block:")
            for target, count in sorted(paths_by_target.items()):
                logging.debug(f"  - {target}: {count} paths")
        
        # Collect all constraints for backward compatibility
        all_path_constraints = []
        for path, constraints in paths_with_constraints:
            all_path_constraints.extend(constraints)
        
        # Return results in the expected format
        if verbose:
            logging.debug(f"Constraint extraction complete. Returning {len(all_paths)} paths")
        
        # Log if no paths found
        if not all_paths:
            logging.debug(f"[ANALYSIS] No valid paths found from target points to function entry")
            logging.debug(f"[ANALYSIS] Target blocks were: {[b.block_id for b in target_blocks]}")
            if required_blocks_by_point:
                logging.debug(f"[ANALYSIS] Required waypoints: {len(required_blocks_by_point)} points")
            
            # Check if timeout already reached - no point in trying fallback
            if timeout_reached:
                logging.debug(f"[FALLBACK] Skipping fallback strategy due to timeout")
                return all_paths, [{
                    'dominator_constraints': all_dominator_constraints,
                    'optional_constraints': all_optional_constraints,
                    'path_constraints': all_path_constraints
                }]
            
            # FALLBACK STRATEGY: Retry with all unrolled blocks when 0 paths found
            logging.debug(f"\n[FALLBACK] Attempting to use ALL unrolled blocks as fallback strategy...")
            
            # Re-find target blocks with use_all_unrolled=True
            target_blocks_fallback = []
            for target_point in target_program_points:
                fallback_blocks = self._select_smallest_blocks_for_point(
                    target_point, function_cfg, verbose, use_all_unrolled=True
                )
                target_blocks_fallback.extend(fallback_blocks)
            
            # Remove duplicates while preserving order
            seen_fallback = set()
            unique_fallback_blocks = []
            for block in target_blocks_fallback:
                if block.block_id not in seen_fallback:
                    seen_fallback.add(block.block_id)
                    unique_fallback_blocks.append(block)
            target_blocks_fallback = unique_fallback_blocks
            
            logging.debug(f"[FALLBACK] Found {len(target_blocks_fallback)} target blocks with unrolled versions")
            
            # Re-find required blocks with use_all_unrolled=True
            required_blocks_by_point_fallback = []
            if required_program_points:
                for required_point in required_program_points:
                    fallback_blocks = self._select_smallest_blocks_for_point(
                        required_point, function_cfg, verbose, use_all_unrolled=True
                    )
                    if fallback_blocks:
                        required_blocks_by_point_fallback.append(fallback_blocks)
                    else:
                        # If we still can't find required blocks, can't continue
                        logging.warning(f"[FALLBACK] Still no blocks found for required point even with fallback")
                        return all_paths, [{
                            'dominator_constraints': all_dominator_constraints,
                            'optional_constraints': all_optional_constraints,
                            'path_constraints': all_path_constraints
                        }]
            
            # Retry path traversal with fallback blocks
            logging.debug(f"[FALLBACK] Retrying path traversal with {len(target_blocks_fallback)} fallback target blocks")
            
            # Reset path collections
            all_paths_fallback = []
            paths_with_constraints_fallback = []

            # Create new CFG builder for fallback traversal
            cfg_builder_fallback = self._create_cfg_builder_from_function(
                function_cfg, limit_paths=limit_paths, max_depth=cfg_builder.max_depth
            )
            
            for target_block in target_blocks_fallback:
                if not self._is_valid_path_start(target_block, function_cfg):
                    continue
                
                if verbose:
                    logging.debug(f"[FALLBACK] Traversing from fallback block {target_block.block_id}")
                
                # Limit paths per block in fallback mode
                paths_from_block = 0
                max_paths_per_block = 50
                
                for path, constraints in cfg_builder_fallback.traverse_backward_with_constraints(
                    target_block, verbose, False  # Always use unrolled blocks in fallback
                ):
                    paths_from_block += 1
                    
                    # Check if path passes through required points
                    if required_blocks_by_point_fallback:
                        if not self._path_passes_through_required_points(
                            path, required_blocks_by_point_fallback, False
                        ):
                            continue
                    
                    # Validate path
                    if self._is_valid_path(path):
                        all_paths_fallback.append(path)
                        
                        # Collect constraints
                        path_constraints = []
                        for constraint in constraints:
                            block_id = constraint.get('block_id', '')
                            iteration_context = self._extract_iteration_context(block_id)
                            
                            constraint_with_context = constraint.copy()
                            constraint_with_context['iteration_context'] = iteration_context
                            path_constraints.append(constraint_with_context)
                        
                        paths_with_constraints_fallback.append((path, path_constraints))
                        
                        if len(all_paths_fallback) >= 50:  # Limit fallback paths
                            logging.debug(f"[FALLBACK] Collected enough fallback paths, stopping")
                            break
                    
                    if paths_from_block >= max_paths_per_block:
                        break
                
                if len(all_paths_fallback) >= 50:
                    break
            
            if all_paths_fallback:
                logging.debug(f"[FALLBACK] SUCCESS! Found {len(all_paths_fallback)} paths using unrolled blocks")
                all_paths = all_paths_fallback
                paths_with_constraints = paths_with_constraints_fallback
                
                # Re-analyze constraints with fallback paths
                constraint_groups = {}
                total_paths = len(all_paths)
                
                for i, (path, path_constraints) in enumerate(paths_with_constraints):
                    seen_in_path = set()
                    for constraint in path_constraints:
                        key = (constraint.get('line'), constraint.get('branch'))
                        
                        if key not in seen_in_path:
                            seen_in_path.add(key)
                            if key not in constraint_groups:
                                constraint_groups[key] = {
                                    'count': 0,
                                    'constraint': constraint,
                                    'contexts': set()
                                }
                            constraint_groups[key]['count'] += 1
                            constraint_groups[key]['contexts'].add(
                                constraint.get('iteration_context', 'unknown')
                            )
                
                # Re-identify dominators and must-take constraints
                all_dominator_constraints = []
                all_optional_constraints = []
                
                constraints_by_line = {}
                for key, group in constraint_groups.items():
                    line, branch = key
                    if line not in constraints_by_line:
                        constraints_by_line[line] = {}
                    constraints_by_line[line][branch] = group
                
                unpaired_lines = set()
                for line_num, branches in constraints_by_line.items():
                    if len(branches) == 1:
                        unpaired_lines.add(line_num)
                
                for key, group in constraint_groups.items():
                    line, branch = key
                    
                    if group['count'] == total_paths:
                        # Dominator constraint
                        constraint = group['constraint'].copy()
                        constraint['is_dominator'] = True
                        all_dominator_constraints.append(constraint)
                    elif line in unpaired_lines:
                        # Must-take constraint
                        constraint = group['constraint'].copy()
                        constraint['must_take'] = True
                        constraint['description'] = f"Must take {branch} branch (other branch doesn't lead to target)"
                        all_dominator_constraints.append(constraint)
                    else:
                        # Optional constraint
                        constraint = group['constraint'].copy()
                        constraint['occurrences'] = group['count']
                        constraint['percentage'] = (group['count'] / total_paths) * 100
                        all_optional_constraints.append(constraint)
                
                # Sort constraints
                all_dominator_constraints.sort(key=lambda x: x.get('line', 0))
                all_optional_constraints.sort(key=lambda x: x.get('line', 0))
                
                logging.debug(f"[FALLBACK] Analyzed {len(all_paths)} fallback paths with "
                           f"{len(all_dominator_constraints)} dominator constraints")
            else:
                logging.warning(f"[FALLBACK] Failed to find paths even with unrolled blocks")
        
        return all_paths, [{
            'dominator_constraints': all_dominator_constraints,
            'optional_constraints': all_optional_constraints,
            'path_constraints': all_path_constraints
        }]
    
    def _count_predecessors(self, block: BasicBlock, function_cfg: Function) -> int:
        """Count the number of predecessors for a block."""
        count = 0
        for other_bb in function_cfg.basic_blocks:
            if block in other_bb.successor_blocks:
                count += 1
        return count
    
    def _extract_iteration_context(self, block_id: str) -> str:
        """Extract iteration context from block ID.
        
        Examples:
        - "9199.10_9199.15" -> "original"
        - "9199.10_9199.15_L9172i2" -> "_L9172i2"
        - "9199.10_9199.15_L9197i2_L9182i2" -> "_L9197i2_L9182i2"
        """
        if '_L' not in block_id:
            return "original"
        
        # Extract everything after the first _L
        parts = block_id.split('_L')
        if len(parts) > 1:
            return "_L" + "_L".join(parts[1:])
        
        return "original"
    
    def _select_smallest_blocks_for_point(self, program_point: ProgramPoint, 
                                         function_cfg: Function, verbose: bool = False,
                                         use_all_unrolled: bool = False) -> List[BasicBlock]:
        """Select the smallest blocks that contain the given program point.
        
        This ensures we get the most precise constraint analysis by choosing
        blocks that represent the most specific program locations.
        
        Args:
            program_point: The program point to find blocks for
            function_cfg: The function CFG to search in
            verbose: Whether to enable verbose logging
            use_all_unrolled: If True, return all unrolled versions when multiple exist
        """
        matching_blocks = []
        
        logging.debug(f"[BLOCKS] Searching for blocks containing line {program_point.start_line} (cols {program_point.start_column}-{program_point.end_column})")
        logging.debug(f"[BLOCKS] Total blocks in CFG: {len(function_cfg.basic_blocks)}")
        if use_all_unrolled:
            logging.debug(f"[BLOCKS] Using ALL unrolled blocks mode (fallback strategy)")
        
        # First pass: find all blocks containing the point
        all_containing_blocks = []
        reversed_blocks = []
        skipped_invalid_blocks = 0  # Count 0.0_ blocks
        
        for bb in function_cfg.basic_blocks:
            # Skip blocks that start with 0.0 (invalid/special blocks)
            if bb.block_id.startswith('0.0_'):
                skipped_invalid_blocks += 1
                continue
                
            if self._program_point_overlaps_with_block(program_point, bb):
                all_containing_blocks.append(bb)
                # Check if this is a reversed block (indicates potential CFG issue)
                if self._is_reversed_block(bb):
                    reversed_blocks.append(bb)
                    logging.debug(f"[BLOCKS] Block {bb.block_id} - REVERSED BLOCK (start > end), will be filtered out")
                    continue
                logging.debug(f"[BLOCKS] Block {bb.block_id} contains the target point (size: {self._estimate_block_size(bb)} lines)")
                matching_blocks.append(bb)
        
        # Log summary statistics
        if skipped_invalid_blocks > 0:
            logging.debug(f"[BLOCKS] Skipped {skipped_invalid_blocks} invalid blocks (starting with 0.0)")
        logging.debug(f"[BLOCKS] Found {len(all_containing_blocks)} total blocks containing the point")
        if len(reversed_blocks) > 0:
            logging.debug(f"[BLOCKS] Filtered out {len(reversed_blocks)} reversed blocks")
        logging.debug(f"[BLOCKS] After filtering: {len(matching_blocks)} blocks remain")
        
        if not matching_blocks:
            if verbose:
                logging.debug(f"[BLOCKS] No blocks found containing program point at line {program_point.start_line}")
            return []
        
        # Sort by estimated block size (smallest first)
        logging.debug(f"[BLOCKS] Sorting {len(matching_blocks)} blocks by size...")
        matching_blocks.sort(key=lambda b: self._estimate_block_size(b))
        
        # Log sorted blocks
        for i, bb in enumerate(matching_blocks[:10]):  # Show first 10
            logging.debug(f"[BLOCKS]   {i+1}. {bb.block_id} - size: {self._estimate_block_size(bb)} lines")
        if len(matching_blocks) > 10:
            logging.debug(f"[BLOCKS]   ... and {len(matching_blocks) - 10} more blocks")
        
        # Get the size of the smallest block
        min_size = self._estimate_block_size(matching_blocks[0])
        logging.debug(f"[BLOCKS] Minimum block size: {min_size} lines")
        
        # Return all blocks with the minimum size
        # This handles cases where multiple iteration contexts have the same size
        smallest_blocks = [b for b in matching_blocks 
                          if self._estimate_block_size(b) == min_size]
        
        logging.debug(f"[BLOCKS] Selected {len(smallest_blocks)} blocks with size {min_size}")
        
        # OPTIMIZATION: Handle loop unrolling explosion
        if len(smallest_blocks) > 1 and not use_all_unrolled:
            logging.debug(f"[BLOCKS] Multiple blocks with same size - checking for loop unrolling optimization...")
            # Check if these are all the same location with different loop contexts
            base_locations = {}
            for bb in smallest_blocks:
                # Extract base location (remove _L suffixes)
                base_id = bb.block_id.split('_L')[0]
                if base_id not in base_locations:
                    base_locations[base_id] = []
                base_locations[base_id].append(bb)
            
            # If all blocks are from the same base location
            if len(base_locations) == 1:
                base_id = list(base_locations.keys())[0]
                blocks_for_location = base_locations[base_id]
                
                # Find the original block (no _L suffix)
                original_block = None
                for bb in blocks_for_location:
                    if '_L' not in bb.block_id:
                        original_block = bb
                        break
                
                if original_block:
                    # Use only the original block
                    smallest_blocks = [original_block]
                    logging.debug(f"[BLOCKS-OPT] Found original block among {len(blocks_for_location)} unrolled versions")
                else:
                    # No original block found - this point only exists in loops
                    # Just use one representative block
                    smallest_blocks = [blocks_for_location[0]]
                    logging.debug(f"[BLOCKS-OPT] No original block found, using one representative from {len(blocks_for_location)} versions")
        elif use_all_unrolled and len(smallest_blocks) > 1:
            logging.debug(f"[BLOCKS-FALLBACK] Keeping ALL {len(smallest_blocks)} unrolled blocks (fallback mode)")
        
        logging.debug(f"[BLOCKS] Final selection: {len(smallest_blocks)} blocks")
        for bb in smallest_blocks:
            logging.debug(f"[BLOCKS]   - {bb.block_id}")
        
        return smallest_blocks
    
    def _is_reversed_block(self, block: BasicBlock) -> bool:
        """Check if a basic block has reversed line numbers (end before start).
        
        Such blocks may indicate CFG construction issues or special control flow
        that should not be used for normal constraint analysis.
        """
        try:
            block_id = block.block_id.split('_L')[0]  # Remove iteration context
            parts = block_id.split('_')
            
            if len(parts) >= 2:
                start_line = int(parts[0].split('.')[0])
                end_line = int(parts[1].split('.')[0])
                is_reversed = start_line > end_line
                if is_reversed:
                    logging.debug(f"[BLOCKS-FILTER] Block {block.block_id} is reversed: start {start_line} > end {end_line}")
                return is_reversed
            
            return False
        except Exception as e:
            logging.debug(f"[BLOCKS-FILTER] Error checking if block {block.block_id} is reversed: {e}")
            return False
    
    def _estimate_block_size(self, block: BasicBlock) -> int:
        """Estimate the size of a basic block based on its ID.
        
        Block IDs are in format: startLine.startCol_endLine.endCol[_context]
        This returns the line span of the block.
        """
        try:
            # Remove iteration context if present
            block_id = block.block_id.split('_L')[0]
            
            # Parse start and end lines
            parts = block_id.split('_')
            if len(parts) >= 2:
                start_line = int(parts[0].split('.')[0])
                end_line = int(parts[1].split('.')[0])
                # Handle reversed ranges (e.g., 615.4_612.10)
                actual_start = min(start_line, end_line)
                actual_end = max(start_line, end_line)
                return actual_end - actual_start + 1
            else:
                # Single line block
                return 1
        except:
            # If parsing fails, return a large number so it's deprioritized
            return 999
    
    def _program_point_overlaps_with_block(self, program_point: ProgramPoint, basic_block: BasicBlock) -> bool:
        """Check if a program point overlaps with a basic block's location."""
        result = program_point.overlaps_with_block(basic_block)
        if result:
            logging.debug(f"[OVERLAP] Point {program_point} overlaps with block {basic_block.block_id}")
        return result

    def _is_valid_path(self, path: Tuple[BasicBlock]) -> bool:
        """Validate if a path is reasonable (not too short, not circular, etc.)"""
        if not path or len(path) < 1:
            return False
        
        # Check for obvious circular paths
        if len(set(bb.block_id for bb in path)) < len(path) * 0.8:
            return False
        
        return True
    
    def _path_passes_through_required_points(self, path, required_blocks_by_point, verbose=False) -> bool:
        """Check if a path passes through all required program points IN ORDER.
        
        For each required program point, the path must pass through at least ONE
        of the blocks containing that point (to handle loop unrolling cases).
        The points must be visited in the order they are specified.
        
        NOTE: Paths are in BACKWARD order (from target to entry), so we need to
        check required points in reverse order to match execution order.
        
        IMPORTANT: Multiple consecutive waypoints may be in the same block!
        """
        if not required_blocks_by_point:
            return True
        
        # Since paths are backward (target → entry), we need to check required points
        # in reverse order to match the execution order
        # E.g., if execution order is A→B→C, the path will be [C, B, A]
        # So we check required points in reverse
        
        # First, merge consecutive waypoints that share the same blocks
        # This handles the case where multiple points are in the same basic block
        merged_waypoints = []
        i = 0
        while i < len(required_blocks_by_point):
            current_blocks = set(required_blocks_by_point[i])
            merged_indices = [i]
            
            # Check if next waypoints share any blocks with current
            j = i + 1
            while j < len(required_blocks_by_point):
                next_blocks = set(required_blocks_by_point[j])
                if current_blocks & next_blocks:  # If there's any intersection
                    # Merge the blocks
                    current_blocks = current_blocks & next_blocks  # Use intersection
                    merged_indices.append(j)
                    j += 1
                else:
                    break
            
            if verbose and len(merged_indices) > 1:
                logging.debug(f"[WAYPOINT] Merging {len(merged_indices)} consecutive waypoints that share blocks")
            
            # Add the merged waypoint (with blocks that are common to all merged points)
            merged_waypoints.append(list(current_blocks))
            i = j
        
        # Track position in path
        path_position = 0
        
        if verbose:
            logging.debug(f"[WAYPOINT] Checking if path passes through {len(merged_waypoints)} required waypoints (merged from {len(required_blocks_by_point)})")
            logging.debug(f"[WAYPOINT] Path has {len(path)} blocks: {[b.block_id for b in path[:5]]}..." if len(path) > 5 else f"[WAYPOINT] Path has {len(path)} blocks: {[b.block_id for b in path]}")
        
        # Check required points in REVERSE order because path is backward
        for point_idx, blocks_for_point in enumerate(reversed(merged_waypoints)):
            found = False
            if verbose:
                logging.debug(f"[WAYPOINT] Checking waypoint {point_idx+1}/{len(merged_waypoints)}: need one of {[b.block_id for b in blocks_for_point]}")
            
            # Look for any of the blocks for this point starting from current position
            for i in range(path_position, len(path)):
                if path[i] in blocks_for_point:
                    # Found this required point at position i
                    found = True
                    path_position = i + 1  # Next search starts after this position
                    if verbose:
                        logging.debug(f"[WAYPOINT]   ✓ Found at position {i}: {path[i].block_id}")
                    break
            
            if not found:
                # This required point is not found in the remaining path
                if verbose:
                    logging.debug(f"[WAYPOINT]   ✗ Not found in remaining path (positions {path_position}-{len(path)-1})")
                return False
        
        if verbose:
            logging.debug(f"[WAYPOINT] All required waypoints found in path")
        return True
    
    def _is_valid_path_start(self, block: BasicBlock, function_cfg: Function) -> bool:
        """Check if a block is a valid starting point for backward path traversal.
        
        Valid starting points are:
        1. Blocks with predecessors (normal case)
        2. The designated entry block
        3. Blocks that are reachable from the entry block
        
        Invalid starting points are orphaned blocks that create artificial paths.
        """
        # If block has predecessors, it's definitely valid
        if hasattr(block, 'predecessor_blocks') and len(block.predecessor_blocks) > 0:
            return True
        
        # If it's the designated entry block, it's valid
        if hasattr(function_cfg, 'entry_block') and function_cfg.entry_block and block == function_cfg.entry_block:
            return True
        
        # Also check if the block itself is marked as entry
        # This handles cases where entry_block attribute is None
        if hasattr(block, 'is_entry') and block.is_entry:
            return True
        
        # If no entry block is designated, we can't determine validity based on that
        # In this case, only blocks with predecessors are considered valid
        # This prevents orphaned blocks from being used as path starts
        
        return False
    
    def _create_simplified_cfg(self, function_cfg):
        """Create a simplified CFG by removing all unrolled blocks (blocks with _L suffix)"""
        from AdvancedTools.CFGExtractor.models import Function, BasicBlock
        
        # Create a new function with only original blocks
        simplified_func = Function(
            function_name=function_cfg.function_name,
            file_path=function_cfg.file_path,
            start_line=function_cfg.start_line,
            end_line=function_cfg.end_line
        )
        
        # Copy only original blocks (without _L suffix)
        original_blocks = {}
        for bb in function_cfg.basic_blocks:
            if '_L' not in bb.block_id:
                # Create a copy of the block
                new_bb = BasicBlock(
                    block_id=bb.block_id,
                    start_line=bb.start_line,
                    end_line=bb.end_line,
                    start_column=bb.start_column,
                    end_column=bb.end_column
                )
                new_bb.line_numbers = bb.line_numbers.copy() if hasattr(bb, 'line_numbers') else []
                new_bb.successor_blocks = {}
                new_bb.predecessor_blocks = {}
                
                # Copy is_entry attribute if exists
                if hasattr(bb, 'is_entry'):
                    new_bb.is_entry = bb.is_entry
                
                simplified_func.basic_blocks.append(new_bb)
                original_blocks[bb.block_id] = new_bb
        
        # Rebuild connections between original blocks only
        for bb in function_cfg.basic_blocks:
            if '_L' not in bb.block_id and bb.block_id in original_blocks:
                new_bb = original_blocks[bb.block_id]
                
                # Add successors that are also original blocks
                for succ_bb, edge_type in bb.successor_blocks.items():
                    if '_L' not in succ_bb.block_id and succ_bb.block_id in original_blocks:
                        new_bb.successor_blocks[original_blocks[succ_bb.block_id]] = edge_type
                
                # Add predecessors that are also original blocks  
                for pred_bb, edge_type in bb.predecessor_blocks.items():
                    if '_L' not in pred_bb.block_id and pred_bb.block_id in original_blocks:
                        new_bb.predecessor_blocks[original_blocks[pred_bb.block_id]] = edge_type
        
        # Set entry and exit blocks
        if function_cfg.entry_block and '_L' not in function_cfg.entry_block.block_id:
            simplified_func.entry_block = original_blocks.get(function_cfg.entry_block.block_id)
        
        if function_cfg.exit_block and '_L' not in function_cfg.exit_block.block_id:
            simplified_func.exit_block = original_blocks.get(function_cfg.exit_block.block_id)
        
        logging.debug(f"Created simplified CFG: {len(simplified_func.basic_blocks)} blocks (reduced from {len(function_cfg.basic_blocks)})")
        
        return simplified_func
    
    def _create_cfg_builder_from_function(self, function_cfg: Function, limit_paths: bool = True, max_depth: int = 20):
        """Create a path traversal and constraint extractor from a cached function."""
        # This class provides backward path traversal and constraint extraction
        # capabilities using an existing CFG structure

        class PathConstraintTraverser:
            def __init__(self, entry_function, source_root=None, limit_paths=True, max_depth=20):
                self.entry_function = entry_function
                self.functions = {entry_function}
                self.max_depth = max_depth  # Configurable max depth for path traversal
                self.max_paths = 200  # Limit number of paths for efficiency (increased from 100)
                self.limit_paths = limit_paths  # Whether to enforce max_paths limit
                self.max_recursive_calls = 100000  # Hard limit on recursive calls (safety measure)
                self.path_count = 0
                self.path_limit_reached = False  # Flag to stop all exploration when limit is hit
                self.recursion_limit_reached = False  # Flag when hitting max_recursive_calls
                # Store file path for condition extraction
                self.file_path = entry_function.file_path if hasattr(entry_function, 'file_path') else None
                self.depth_exceeded_blocks = set()  # Track blocks where we've already logged depth exceeded
                self.depth_exceeded_count = 0  # Count how many times we hit depth limit
                self.suggest_ignore_unrolled = False  # Flag to suggest retrying with ignore_unrolled=True
                self.source_root = source_root  # Root directory for source files
                # Cache for condition text to avoid repeated file reads
                self.condition_cache = {}  # (file_path, line_number) -> condition_text
                self.file_path_resolution_cache = {}  # filename -> absolute_path (for glob caching)
                self.glob_call_count = 0  # Track how many times glob is called
                self.cache_hit_count = 0  # Track cache hits
                self.cache_miss_count = 0  # Track cache misses
                self.total_recursive_calls = 0  # Track total recursive_traverse calls
                # Counters for skipped blocks
                self.skipped_invalid_blocks = 0  # Count of 0.0_ blocks skipped
            
            def traverse_backward_with_constraints(self, start_bb, verbose=False, ignore_unrolled=False):
                """Traverse backward and collect path constraints (from cfg_builder.py)
                
                Args:
                    start_bb: The starting basic block
                    verbose: Whether to log verbose information
                    ignore_unrolled: If True, skip blocks with _L suffix (unrolled blocks)
                """
                # Reset counters for this traversal
                self.skipped_invalid_blocks = 0
                
                def recursive_traverse(current_bb, path, constraints, depth, visited_in_path):
                    # Track total recursive calls
                    self.total_recursive_calls += 1

                    # SAFETY: Hard limit on recursive calls to prevent infinite exploration
                    if self.total_recursive_calls > self.max_recursive_calls:
                        if not self.recursion_limit_reached:
                            logging.error(f"[RECURSION_LIMIT] EMERGENCY STOP: Exceeded max recursive calls ({self.max_recursive_calls:,})")
                            logging.error(f"[RECURSION_LIMIT] Paths found so far: {self.path_count}")
                            logging.error(f"[RECURSION_LIMIT] This likely indicates: (1) No entry blocks found, (2) All paths hit depth limit, or (3) Complex CFG")
                            logging.error(f"[RECURSION_LIMIT] Current block: {current_bb.block_id}, Depth: {depth}")
                            self.recursion_limit_reached = True
                        return

                    # Log progress every 1000 calls (more frequent for debugging)
                    if self.total_recursive_calls % 1000 == 0:
                        logging.info(f"[RECURSION_PROGRESS] Total calls: {self.total_recursive_calls:,}, Paths found: {self.path_count}, Current depth: {depth}, Limit reached: {self.path_limit_reached}")

                    # Stop if path limit reached
                    if self.path_limit_reached:
                        if self.total_recursive_calls % 100 == 0:
                            logging.info(f"[RECURSION_STOPPED] Call #{self.total_recursive_calls}: Stopped due to path_limit_reached at block {current_bb.block_id}")
                        return

                    # Skip invalid blocks that start with 0.0
                    # This should be rare as we filter during CFG construction, but keep as defensive check
                    if current_bb.block_id.startswith('0.0_'):
                        self.skipped_invalid_blocks += 1
                        return
                        
                    # Check if we've already visited this block in this path (cycle detection)
                    block_key = current_bb.block_id
                    if block_key in visited_in_path:
                        return
                    
                    # CRITICAL: Break cycles more aggressively
                    # If we see the same base block (without _L suffix) multiple times, stop
                    base_block_id = block_key.split('_L')[0] if '_L' in block_key else block_key
                    base_blocks_in_path = []
                    for bb in path:
                        base_id = bb.block_id.split('_L')[0] if '_L' in bb.block_id else bb.block_id
                        base_blocks_in_path.append(base_id)
                    
                    # Count how many times this base block appears
                    base_block_count = base_blocks_in_path.count(base_block_id)
                    if base_block_count >= 2:  # Already visited this base block twice
                        if verbose and base_block_count == 2:
                            logging.debug(f"Breaking cycle: base block {base_block_id} already visited twice")
                        return
                    
                    # Check if we've exceeded max depth
                    # Reduce max depth to avoid excessive recursion
                    max_allowed_depth = self.max_depth * 2  # Was 3, now 2 (40 instead of 60)
                    if depth > max_allowed_depth:
                        # Count every time we hit depth limit
                        self.depth_exceeded_count += 1
                        
                        if verbose and current_bb.block_id not in self.depth_exceeded_blocks:
                            # Only log the first time we hit depth limit for this block
                            self.depth_exceeded_blocks.add(current_bb.block_id)
                            logging.debug(f"Max depth exceeded at block {current_bb.block_id} (depth: {depth}, max: {max_allowed_depth})")
                            # Debug: show if this is a loop-unrolled block
                            if '_L' in current_bb.block_id:
                                logging.debug(f"  Note: This is a loop-unrolled block")
                        
                        # Check if we should suggest ignore_unrolled
                        if not ignore_unrolled and self.depth_exceeded_count >= 10:
                            self.suggest_ignore_unrolled = True
                            if verbose and self.depth_exceeded_count == 10:
                                logging.debug(f"Hit depth limit 10+ times. Setting flag to retry with ignore_unrolled=True")
                        
                        return
                    
                    # Add current block to path
                    new_path = path + [current_bb]
                    new_visited = visited_in_path | {block_key}
                    
                    # Check if this is an entry block (base case)
                    if hasattr(current_bb, 'is_entry') and current_bb.is_entry:
                        self.path_count += 1

                        # Log every path found (with path length info)
                        path_length = len(new_path)
                        limit_str = f"/{self.max_paths}" if self.limit_paths else " (unlimited)"
                        logging.info(f"[PATH_FOUND] Path #{self.path_count}{limit_str} - Length: {path_length} blocks, Depth: {depth}, Recursive calls so far: {self.total_recursive_calls:,}")

                        # Only enforce path limit if limit_paths is True
                        if self.limit_paths and self.path_count > self.max_paths:
                            # Already exceeded limit (shouldn't happen often due to early flag check)
                            logging.info(f"[PATH_LIMIT] Path #{self.path_count} exceeds limit, not yielding")
                            return

                        # Yield this path
                        yield (tuple(new_path), constraints)

                        # Set flag if we just reached the limit (so future recursions stop early)
                        if self.limit_paths and self.path_count == self.max_paths:
                            logging.warning(f"[PATH_LIMIT] STOPPING: Reached path limit ({self.max_paths}). Setting path_limit_reached=True")
                            logging.info(f"[PATH_LIMIT] Stats at limit: Recursive calls={self.total_recursive_calls:,}, Glob calls={self.glob_call_count}, Cache hits={self.cache_hit_count:,}")
                            self.path_limit_reached = True  # Set flag to stop all exploration

                        return
                    
                    # Get predecessors
                    predecessors = []
                    for bb in self.entry_function.basic_blocks:
                        # Skip unrolled blocks if ignore_unrolled is True
                        if ignore_unrolled and '_L' in bb.block_id:
                            continue
                        for succ_bb, edge_type in bb.successor_blocks.items():
                            if succ_bb.block_id == current_bb.block_id:
                                predecessors.append((bb, edge_type))

                    # Log predecessor exploration
                    if len(predecessors) > 0:
                        logging.debug(f"[EXPLORE] Block {current_bb.block_id} has {len(predecessors)} predecessor(s) at depth {depth}")
                    
                    if not predecessors:
                        # No predecessors but not marked as entry - might be an issue
                        # But yield the path anyway if it's long enough
                        if len(new_path) > 1:
                            self.path_count += 1

                            # Log partial path
                            path_length = len(new_path)
                            limit_str = f"/{self.max_paths}" if self.limit_paths else " (unlimited)"
                            logging.info(f"[PARTIAL_PATH] Path #{self.path_count}{limit_str} - Length: {path_length}, stopped at {current_bb.block_id} (no predecessors)")

                            # Only enforce path limit if limit_paths is True
                            if self.limit_paths and self.path_count > self.max_paths:
                                # Already exceeded limit
                                logging.info(f"[PATH_LIMIT] Partial path #{self.path_count} exceeds limit, not yielding")
                                return

                            # Yield this partial path
                            yield (tuple(new_path), constraints)

                            # Set flag if we just reached the limit
                            if self.limit_paths and self.path_count == self.max_paths:
                                logging.warning(f"[PATH_LIMIT] STOPPING: Reached limit ({self.max_paths}) on partial path. Setting path_limit_reached=True")
                                self.path_limit_reached = True
                        else:
                            logging.debug(f"[PATH_SHORT] Not yielding path at {current_bb.block_id} - too short (length={len(new_path)})")
                        return
                    
                    # Traverse each predecessor
                    for pred_bb, edge_type in predecessors:
                        # Skip invalid predecessor blocks that start with 0.0
                        # This should be rare as we filter during CFG construction, but keep as defensive check
                        if pred_bb.block_id.startswith('0.0_'):
                            self.skipped_invalid_blocks += 1
                            continue
                        
                        new_constraints = constraints.copy()
                        
                        # Log all edge types to see what we're getting (debug level to reduce spam)
                        logging.debug(f"[EDGE_TYPE] From {pred_bb.block_id} to {current_bb.block_id}: edge_type = '{edge_type}'")
                        
                        # Add constraint if this is a conditional branch
                        if edge_type in ['TRUE', 'FALSE']:
                            # Find the condition location from the predecessor block
                            condition_line = self._extract_line_from_block_id(pred_bb.block_id)
                            logging.debug(f"[CONSTRAINT] Extracting condition for block {pred_bb.block_id}, line {condition_line}")
                            if condition_line == 0:
                                logging.warning(f"[CONSTRAINT] Skipping invalid condition line 0 from block_id: {pred_bb.block_id}")
                                continue  # Skip this constraint instead of proceeding with line 0
                            condition_text = self._extract_condition_text(pred_bb, condition_line)
                            
                            constraint_dict = {
                                'type': 'branch',
                                'block_id': pred_bb.block_id,
                                'line': condition_line,  # Changed from condition_line to line for consistency
                                'branch': edge_type,  # Changed from branch_taken to branch for consistency
                                'condition_text': condition_text,
                                'iteration_context': self._extract_iteration_context(pred_bb.block_id)
                            }
                            
                            # Log for debugging (use debug level to reduce spam)
                            if condition_text:
                                logging.debug(f"[CONSTRAINT] Created constraint with condition at line {condition_line}: {condition_text}")
                            else:
                                logging.debug(f"[CONSTRAINT] Created constraint at line {condition_line} but no condition text extracted")
                            
                            new_constraints.append(constraint_dict)
                        
                        # Stop if path limit reached
                        if self.path_limit_reached:
                            return
                            
                        # Recursively traverse
                        yield from recursive_traverse(pred_bb, new_path, new_constraints, 
                                                    depth + 1, new_visited)
                
                # Start traversal
                import time
                traversal_start = time.time()

                # Check for entry blocks
                entry_blocks = [bb for bb in self.entry_function.basic_blocks if hasattr(bb, 'is_entry') and bb.is_entry]

                logging.info(f"[TRAVERSAL_START] ========================================")
                logging.info(f"[TRAVERSAL_START] Starting backward traversal from {start_bb.block_id}")
                logging.info(f"[TRAVERSAL_START] limit_paths={self.limit_paths}, max_paths={self.max_paths}, max_recursive_calls={self.max_recursive_calls:,}")
                logging.info(f"[TRAVERSAL_START] Total blocks in CFG: {len(self.entry_function.basic_blocks)}")
                logging.info(f"[TRAVERSAL_START] Entry blocks in CFG: {len(entry_blocks)}")
                if entry_blocks:
                    for eb in entry_blocks[:3]:  # Show first 3
                        logging.info(f"[TRAVERSAL_START]   - Entry: {eb.block_id}")
                else:
                    logging.warning(f"[TRAVERSAL_START] WARNING: No entry blocks found! Paths may not complete.")
                logging.info(f"[TRAVERSAL_START] ========================================")

                for result in recursive_traverse(start_bb, [], [], 0, set()):
                    yield result

                traversal_elapsed = time.time() - traversal_start
                logging.info(f"[TRAVERSAL_COMPLETE] ========================================")
                logging.info(f"[TRAVERSAL_COMPLETE] Finished in {traversal_elapsed:.2f}s")
                logging.info(f"[TRAVERSAL_COMPLETE] Total recursive calls: {self.total_recursive_calls:,}")
                logging.info(f"[TRAVERSAL_COMPLETE] Paths yielded: {self.path_count}")
                logging.info(f"[TRAVERSAL_COMPLETE] path_limit_reached: {self.path_limit_reached}")
                logging.info(f"[TRAVERSAL_COMPLETE] recursion_limit_reached: {self.recursion_limit_reached}")

                # Diagnostic info if no paths found
                if self.path_count == 0:
                    logging.warning(f"[TRAVERSAL_COMPLETE] WARNING: No paths found! Diagnostics:")
                    logging.warning(f"[TRAVERSAL_COMPLETE]   - Entry blocks: {len(entry_blocks)}")
                    logging.warning(f"[TRAVERSAL_COMPLETE]   - Depth exceeded count: {self.depth_exceeded_count}")
                    logging.warning(f"[TRAVERSAL_COMPLETE]   - Total recursive calls: {self.total_recursive_calls:,}")
                    logging.warning(f"[TRAVERSAL_COMPLETE]   - Recursion limit hit: {self.recursion_limit_reached}")

                logging.info(f"[TRAVERSAL_COMPLETE] Cache - Hits: {self.cache_hit_count:,}, Misses: {self.cache_miss_count}, Hit rate: {100*self.cache_hit_count/(self.cache_hit_count+self.cache_miss_count) if self.cache_miss_count > 0 else 0:.2f}%")
                logging.info(f"[TRAVERSAL_COMPLETE] Glob calls: {self.glob_call_count}")
                logging.info(f"[TRAVERSAL_COMPLETE] File resolution cache: {len(self.file_path_resolution_cache)} entries, Condition cache: {len(self.condition_cache)} entries")
                logging.info(f"[TRAVERSAL_COMPLETE] ========================================")
                
                # Log summary after traversal completes
                # This should be rare now that we filter during CFG construction
                if self.skipped_invalid_blocks > 0 and verbose:
                    logging.debug(f"[TRAVERSE] Skipped {self.skipped_invalid_blocks} invalid blocks (starting with 0.0) during traversal (defensive check)")
            
            def _extract_line_from_block_id(self, block_id):
                """Extract line number from block ID.
                
                For condition blocks, we should use the END line since conditions
                are typically at the end of a block (e.g., if statement).
                """
                try:
                    # Remove loop iteration suffixes first
                    clean_id = block_id.split('_L')[0]
                    
                    # Handle format: "startline.col_endline.col"
                    parts = clean_id.split('_')
                    if len(parts) >= 2:
                        # Use the end line for conditions
                        end_part = parts[1]
                        line_num = int(end_part.split('.')[0])
                        return line_num
                    else:
                        # Fallback to first line if format is different
                        first_part = parts[0]
                        line_num = int(first_part.split('.')[0])
                        return line_num
                except Exception as e:
                    logging.debug(f"Failed to extract line from block_id {block_id}: {e}")
                    return 0
            
            def _extract_iteration_context(self, block_id: str) -> str:
                """Extract iteration context from block ID.
                
                Examples:
                - "9199.10_9199.15" -> "original"
                - "9199.10_9199.15_L9172i2" -> "_L9172i2"
                - "9199.10_9199.15_L9197i2_L9182i2" -> "_L9197i2_L9182i2"
                """
                if '_L' not in block_id:
                    return "original"
                
                # Extract everything after the first _L
                parts = block_id.split('_L')
                if len(parts) > 1:
                    return "_L" + "_L".join(parts[1:])
                
                return "original"
            
            def _extract_condition_text(self, block, condition_line):
                """Extract the condition text from the source code."""
                try:
                    # Try to get the file path
                    file_path = self.file_path  # Use the stored file path
                    
                    if not file_path:
                        # Fallback: try to get from entry function or block
                        if hasattr(self.entry_function, 'file_path'):
                            file_path = self.entry_function.file_path
                        elif hasattr(block, 'file_path'):
                            file_path = block.file_path
                    
                    if not file_path:
                        logging.debug(f"[CONDITION_TEXT] No file path available for condition extraction")
                        return None
                    
                    if not condition_line:
                        logging.debug(f"[CONDITION_TEXT] No condition line available")
                        return None

                    # Resolve file path FIRST before checking cache
                    import os
                    resolved_file_path = file_path
                    
                    # If relative path, try to find the actual file
                    if not os.path.isabs(file_path):
                        search_path = os.environ.get('OPENGROK_SEARCH_PATH')
                        if search_path:
                            import glob
                            import time
                            filename = os.path.basename(file_path)

                            # Check file path resolution cache first
                            if filename in self.file_path_resolution_cache:
                                resolved_file_path = self.file_path_resolution_cache[filename]
                                logging.debug(f"[FILE_RESOLUTION] Cache hit for filename: {filename}")
                            else:
                                # Cache miss - need to glob search
                                pattern = os.path.join(search_path, '**', filename)
                                self.glob_call_count += 1

                                glob_start = time.time()
                                logging.info(f"[GLOB #{self.glob_call_count}] Searching for: {filename} (pattern: {pattern})")
                                matches = glob.glob(pattern, recursive=True)
                                glob_elapsed = time.time() - glob_start

                                if matches:
                                    resolved_file_path = matches[0]
                                    self.file_path_resolution_cache[filename] = resolved_file_path
                                    logging.info(f"[GLOB #{self.glob_call_count}] Found {filename} in {glob_elapsed:.3f}s -> {resolved_file_path}")
                                else:
                                    logging.warning(f"[GLOB #{self.glob_call_count}] NOT FOUND: {filename} (took {glob_elapsed:.3f}s)")

                                if self.glob_call_count % 10 == 0:
                                    logging.info(f"[GLOB_STATS] Total glob calls: {self.glob_call_count}, File resolution cache size: {len(self.file_path_resolution_cache)}")
                    
                    # Use text-based extraction
                    # Use the resolved file path
                    file_path = resolved_file_path
                    
                    # Log initial file check (only in debug mode)
                    logging.debug(f"[CONDITION_TEXT] Initial file path: {file_path}")
                    logging.debug(f"[CONDITION_TEXT] File exists: {os.path.exists(file_path)}")
                    logging.debug(f"[CONDITION_TEXT] Is absolute path: {os.path.isabs(file_path)}")
                    
                    # Check if we still need to resolve the path
                    if not os.path.exists(file_path) and not os.path.isabs(file_path):
                        # Build list of possible base directories
                        possible_bases = []
                        
                        # Note: self refers to PathConstraintTraverser instance
                        # We don't have direct access to database_path here
                        # So we'll rely on the common base directories
                        
                        # Use OPENGROK_SEARCH_PATH environment variable
                        search_path = os.environ.get('OPENGROK_SEARCH_PATH')
                        if search_path:
                            logging.debug(f"[CONDITION_TEXT] OPENGROK_SEARCH_PATH is set to: {search_path}")
                            # Search for the file in subdirectories
                            import glob
                            import time
                            # Get just the filename
                            filename = os.path.basename(file_path)

                            # Check file path resolution cache first (second chance)
                            if filename in self.file_path_resolution_cache:
                                file_path = self.file_path_resolution_cache[filename]
                                logging.debug(f"[FILE_RESOLUTION] Second cache hit for filename: {filename}")
                            else:
                                # Really need to glob search now
                                pattern = os.path.join(search_path, '**', filename)
                                self.glob_call_count += 1

                                glob_start = time.time()
                                logging.info(f"[GLOB #{self.glob_call_count}] (2nd attempt) Searching for: {filename}")
                                matches = glob.glob(pattern, recursive=True)
                                glob_elapsed = time.time() - glob_start

                                if matches:
                                    # Use the first match
                                    file_path = matches[0]
                                    self.file_path_resolution_cache[filename] = file_path
                                    logging.info(f"[GLOB #{self.glob_call_count}] (2nd attempt) Found {filename} in {glob_elapsed:.3f}s")
                                    if len(matches) > 1:
                                        logging.debug(f"[CONDITION_TEXT] Multiple matches found ({len(matches)} total), using first")
                                else:
                                    logging.warning(f"[GLOB #{self.glob_call_count}] (2nd attempt) NOT FOUND: {filename} (took {glob_elapsed:.3f}s)")

                                if self.glob_call_count % 10 == 0:
                                    logging.info(f"[GLOB_STATS] Total glob calls: {self.glob_call_count}, File resolution cache size: {len(self.file_path_resolution_cache)}")
                        else:
                            logging.debug("[CONDITION_TEXT] OPENGROK_SEARCH_PATH not set")
                    
                    if not os.path.exists(file_path):
                        logging.debug(f"[CONDITION_TEXT] File not found after search: {file_path}")
                        return None

                    # NOW check cache with the resolved absolute path
                    cache_key = (file_path, condition_line)

                    # Debug: log first 20 cache lookups to understand the pattern
                    if (self.cache_hit_count + self.cache_miss_count) < 20:
                        lookup_num = self.cache_hit_count + self.cache_miss_count + 1
                        logging.info(f"[CACHE_DEBUG #{lookup_num}] Looking for cache_key: ({file_path}, {condition_line})")
                        logging.info(f"[CACHE_DEBUG #{lookup_num}] Cache size: {len(self.condition_cache)}")

                    if cache_key in self.condition_cache:
                        self.cache_hit_count += 1
                        if self.cache_hit_count % 100 == 0:
                            logging.info(f"[CACHE_STATS] Hits: {self.cache_hit_count}, Misses: {self.cache_miss_count}, Glob calls: {self.glob_call_count}")
                        logging.debug(f"[CONDITION_TEXT] Cache hit for {file_path}:{condition_line}")
                        return self.condition_cache[cache_key]

                    self.cache_miss_count += 1
                    if self.cache_miss_count % 100 == 0:
                        logging.info(f"[CACHE_STATS] Cache misses: {self.cache_miss_count}, Hits: {self.cache_hit_count}, Glob calls: {self.glob_call_count}")
                    logging.debug(f"[CONDITION_TEXT] Cache miss, reading from file {file_path}:{condition_line}")

                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                    
                    if condition_line <= 0 or condition_line > len(lines):
                        logging.debug(f"Invalid line number {condition_line} for file with {len(lines)} lines")
                        return None
                    
                    # Get the line (1-indexed to 0-indexed)
                    line_text = lines[condition_line - 1].strip()

                    # Just return the full line of code
                    logging.debug(f"[CONDITION_TEXT] Extracted line {condition_line}: {line_text}")

                    # Store in cache (cache_key already defined above)
                    self.condition_cache[cache_key] = line_text

                    return line_text
                    
                except Exception as e:
                    # Log the error for debugging
                    logging.debug(f"Error extracting condition text: {e}")
                    return None
        
        return PathConstraintTraverser(function_cfg, limit_paths=limit_paths, max_depth=max_depth)


def overlaps_with_block(self, basic_block: BasicBlock) -> bool:
    """Check if this program point overlaps with the given basic block.
    
    This method is more sophisticated than simple line containment - it checks
    for actual overlap between the program point's range and the block's range.
    """
    if not hasattr(basic_block, 'block_id'):
        return False
    
    try:
        # Parse block ID to get its line range
        # Format: startLine.startCol_endLine.endCol or just startLine.startCol
        block_id = basic_block.block_id
        
        # Remove any iteration context (e.g., _L9172i2)
        if '_L' in block_id:
            block_id = block_id.split('_L')[0]
        
        parts = block_id.split('_')
        if len(parts) >= 2:
            # Multi-line block
            start_parts = parts[0].split('.')
            end_parts = parts[1].split('.')
            
            block_start_line = int(start_parts[0])
            block_start_col = int(start_parts[1]) if len(start_parts) > 1 else 0
            block_end_line = int(end_parts[0])
            block_end_col = int(end_parts[1]) if len(end_parts) > 1 else 999
            
            # Handle reversed block ranges (e.g., 654.1_652.21)
            if block_start_line > block_end_line:
                block_start_line, block_end_line = block_end_line, block_start_line
        else:
            # Single line block
            start_parts = parts[0].split('.')
            block_start_line = int(start_parts[0])
            block_start_col = int(start_parts[1]) if len(start_parts) > 1 else 0
            block_end_line = block_start_line
            block_end_col = 999
        
        # Check for line overlap
        if self.end_line < block_start_line or self.start_line > block_end_line:
            return False
        
        # Special case: if end_column is -1, it means "entire line"
        if self.end_column == -1:
            # For entire line matching, just check line overlap
            return True
        
        # Lines overlap, now check column overlap for the overlapping lines
        # For simplicity, if lines overlap, we consider it an overlap
        # More precise column checking could be added if needed
        return True
        
    except (ValueError, IndexError):
        # If we can't parse the block ID, fall back to simple line containment
        return False


# Add the overlaps_with_block method to ProgramPoint
ProgramPoint.overlaps_with_block = overlaps_with_block
