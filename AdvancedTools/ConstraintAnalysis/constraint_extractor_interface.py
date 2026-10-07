#!/usr/bin/env python3
"""
Constraint Extractor - User-friendly interface for constraint analysis

This module provides a simplified, user-friendly API for constraint extraction.
It combines the functionality of the core constraint extractor with additional
features like condition text extraction and path resolution.
"""

import os
import logging
from typing import List, Dict, Optional, Union, Tuple

# Import core functionality
try:
    from .constraint_extractor_core import (
        ConstraintExtractor as CoreExtractor,
        ProgramPoint
    )
    from .cfg_manager import FunctionCFGManager
except ImportError:
    from constraint_extractor_core import (
        ConstraintExtractor as CoreExtractor,
        ProgramPoint
    )
    from cfg_manager import FunctionCFGManager


class ConstraintExtractor:
    """
    High-level interface to the constraint analysis engine.
    
    This class provides streamlined access to constraint extraction capabilities,
    with automatic file path resolution and condition text enhancement.
    """
    
    def __init__(self, project_name: str = "default_project", cache_dir: Optional[str] = None):
        """
        Initialize the constraint extractor.
        
        Args:
            project_name: Name of the project (used for caching)
            cache_dir: Optional custom cache directory
        """
        self.project_name = project_name
        self.enhance_with_text = True  # Enable condition text extraction by default
        self.cache_dir = cache_dir
        
        # Set up cache directory if provided
        if cache_dir:
            os.environ['AI_ANALYSIS_DIR'] = cache_dir
            
        # Initialize internal components
        self.cfg_manager = FunctionCFGManager(project_name)
        self.core_extractor = CoreExtractor(cfg_manager=self.cfg_manager)
        
        # Try to initialize PrecomputedCFGDatabase for function info lookup
        self._init_cfg_database()
    
    def _init_cfg_database(self):
        """Initialize PrecomputedCFGDatabase if available."""
        self.cfg_db = None
        
        # Try to get CodeQL database path from environment
        codeql_db_path = os.environ.get('CODEQL_DB_PATH', '')
        ai_analysis_dir = os.environ.get('AI_ANALYSIS_DIR', '')
        
        logging.debug(f"[_init_cfg_database] CODEQL_DB_PATH = '{codeql_db_path}'")
        logging.debug(f"[_init_cfg_database] AI_ANALYSIS_DIR = '{ai_analysis_dir}'")
        
        # Look for precomputed database in various locations
        possible_db_paths = []
        
        # Priority 1: Check AI_ANALYSIS_DIR/cache/cfg_cache first (this is where CFG manager puts it)
        if ai_analysis_dir:
            possible_db_paths.append(os.path.join(ai_analysis_dir, 'cache', 'cfg_cache', 'cfg_precomputed.db'))
            possible_db_paths.append(os.path.join(ai_analysis_dir, 'cache', 'cfg_precomputed.db'))
            possible_db_paths.append(os.path.join(ai_analysis_dir, 'cfg_precomputed.db'))
            
        if codeql_db_path:
            possible_db_paths.extend([
                os.path.join(codeql_db_path, 'cfg_precomputed.db'),
                os.path.join(os.path.dirname(codeql_db_path), 'cfg_precomputed.db'),
                os.path.join(os.path.dirname(codeql_db_path), 'ai-analysis', 'cache', 'cfg_cache', 'cfg_precomputed.db'),
                os.path.join(os.path.dirname(codeql_db_path), 'ai-analysis', 'cache', 'cfg_precomputed.db'),
            ])
            
        # Check cache_dir if provided during initialization
        if self.cache_dir:
            possible_db_paths.extend([
                os.path.join(self.cache_dir, 'cfg_cache', 'cfg_precomputed.db'),
                os.path.join(self.cache_dir, 'cfg_precomputed.db')
            ])

        # DO NOT fallback to ConstraintAnalysis directory - it may contain stale data
        # CFG cache should only be read from AI_ANALYSIS_DIR or CodeQL DB path
        
        logging.debug(f"[_init_cfg_database] Checking {len(possible_db_paths)} possible database paths")
        
        for db_path in possible_db_paths:
            if db_path and os.path.exists(db_path):
                logging.debug(f"[_init_cfg_database] Found database file at: {db_path} (size: {os.path.getsize(db_path)} bytes)")
                if os.path.getsize(db_path) > 0:
                    try:
                        try:
                            from .cfg_precompute import PrecomputedCFGDatabase
                        except ImportError:
                            from cfg_precompute import PrecomputedCFGDatabase
                        
                        self.cfg_db = PrecomputedCFGDatabase(db_path)
                        # Test if the database has the functions table
                        try:
                            test_result = self.cfg_db.get_function_info("test", None)
                            logging.info(f"[CFG] Database initialized from: {db_path}")
                            return
                        except Exception as e:
                            if "no such table: functions" in str(e):
                                logging.warning(f"[_init_cfg_database] Database {db_path} exists but is empty")
                                print(f"Warning: Database {db_path} exists but is empty. Run cfg_precompute.py to populate it.")
                                self.cfg_db = None
                            else:
                                raise
                    except Exception as e:
                        logging.error(f"[_init_cfg_database] Failed to initialize from {db_path}: {e}")
                        print(f"Failed to initialize PrecomputedCFGDatabase from {db_path}: {e}")
            else:
                logging.debug(f"[_init_cfg_database] Path does not exist: {db_path}")
        
        logging.warning("[_init_cfg_database] Could not find or initialize PrecomputedCFGDatabase")
        print("Warning: Could not find or initialize PrecomputedCFGDatabase")

    def is_point_in_function_body(self, function_name: str, file_path: str, line: int) -> bool:
        """
        Check if a line is within the function body (not on declaration line).
        
        Args:
            function_name: Name of the function
            file_path: Path to the source file
            line: Line number to check
            
        Returns:
            bool: True if the line is within function body, False if on declaration line
        """
        logging.debug(f"[is_point_in_function_body] Called with function_name='{function_name}', file_path='{file_path}', line={line}")
        
        if not self.cfg_db:
            logging.warning("[is_point_in_function_body] cfg_db is None - cannot verify function body")
            # No database, can't verify - assume it's in body
            return True
        
        logging.debug(f"[is_point_in_function_body] Using database: {self.cfg_db.db_path}")
            
        try:
            # Query function info from database
            # Try with both the given file path and just the basename
            logging.debug(f"[is_point_in_function_body] First query: get_function_info('{function_name}', '{file_path}')")
            functions = self.cfg_db.get_function_info(function_name, file_path)
            logging.debug(f"[is_point_in_function_body] First query result: {len(functions) if functions else 0} matches")
            
            if not functions and not os.path.isabs(file_path):
                # If no match and path is relative, try with just the filename
                basename = os.path.basename(file_path)
                logging.debug(f"[is_point_in_function_body] Second query: get_function_info('{function_name}', '{basename}')")
                functions = self.cfg_db.get_function_info(function_name, basename)
                logging.debug(f"[is_point_in_function_body] Second query result: {len(functions) if functions else 0} matches")
            
            logging.debug(f"[is_point_in_function_body] Checking {function_name}:{line} in {file_path}")
            logging.debug(f"[is_point_in_function_body] Found {len(functions) if functions else 0} function matches")
            if functions:
                for f in functions[:3]:
                    logging.debug(f"[is_point_in_function_body]   Match: {f}")
            
            for func in functions:
                # func is tuple: (qualified_name, file_path, start_line, end_line, function_id)
                if len(func) >= 5:
                    declaration_line = int(func[2])
                    function_id = func[4]
                    
                    # Parse function body range from function_id
                    try:
                        parts = function_id.split('_')
                        if len(parts) == 2:
                            body_start = int(parts[0].split('.')[0])
                            body_end = int(parts[1].split('.')[0])
                            
                            # Handle reversed ranges
                            actual_start = min(body_start, body_end)
                            actual_end = max(body_start, body_end)
                            
                            # Line is in function body if it's between body_start and body_end
                            # but NOT on the declaration line
                            logging.debug(f"[is_point_in_function_body] Function {func[0]}: decl={declaration_line}, body={actual_start}-{actual_end}, checking line={line}")
                            if actual_start <= line <= actual_end and line != declaration_line:
                                logging.debug(f"[is_point_in_function_body] Line {line} is in function body - returning True")
                                return True
                            elif line == declaration_line:
                                logging.debug(f"[is_point_in_function_body] Line {line} is declaration line - returning False")
                                return False
                            else:
                                logging.debug(f"[is_point_in_function_body] Line {line} is outside function range {actual_start}-{actual_end}")
                    except:
                        pass
                        
            # If we get here, no matching function found in database
            logging.debug(f"[is_point_in_function_body] No matching function body found for {function_name}:{line}")
            logging.debug(f"[is_point_in_function_body] WARNING: No database entry - defaulting to True to avoid filtering valid code")
            # When we can't find the function in the database, default to True
            # to avoid incorrectly filtering out valid code points
            return True
            
        except Exception as e:
            logging.debug(f"[is_point_in_function_body] Error checking if line is in function body: {e}")
            # On error, assume it's in body to avoid filtering valid code
            return True
            return True


    def extract_constraints_for_points(
        self,
        target_points: List[ProgramPoint],
        function_name: str,
        file_path: str,
        function_start_line: int,
        verbose: bool = False
    ) -> Dict:
        """
        Analyze constraints for multiple points in a function.

        This method finds all paths that pass through ALL given points,
        then computes cross-path dominator constraints - constraints that
        must be satisfied in ALL paths vs constraints that vary across paths.

        The key insight is:
        - A constraint is "must-satisfy" if it appears with the SAME branch value
          in ALL paths (no conflicting branch in any path)
        - A constraint is "optional" if different paths take different branches

        Args:
            target_points: List of ProgramPoint objects to analyze
            function_name: Name of the function containing the points
            file_path: Path to the source file
            function_start_line: Starting line of the function
            verbose: Whether to log detailed information

        Returns:
            Dict with keys:
            - success: bool
            - paths_found: int (number of paths through all points)
            - dominator_constraints: List[Dict] (must-satisfy in ALL paths)
            - optional_constraints: List[Dict] (varies across paths)
            - error: str (if success is False)
        """
        if not target_points:
            return {
                'success': False,
                'paths_found': 0,
                'dominator_constraints': [],
                'optional_constraints': [],
                'error': 'No target points provided'
            }

        try:
            # Get function CFG
            function_cfg = self.cfg_manager.get_cached_function(
                function_name, file_path, function_start_line
            )

            if not function_cfg:
                return {
                    'success': False,
                    'paths_found': 0,
                    'dominator_constraints': [],
                    'optional_constraints': [],
                    'error': f'Function CFG not found for {function_name}'
                }

            # For single point, use the core extractor which handles multiple smallest blocks
            # This is more thorough than the multi-point logic which selects only one block per point
            if len(target_points) == 1:
                paths, constraint_results = self.core_extractor.extract_path_constraints_from_cached_cfg(
                    function_name=function_name,
                    file_path=file_path,
                    start_line=function_start_line,
                    target_program_points=target_points,
                    required_program_points=[],
                    verbose=verbose
                )

                if not paths:
                    return {
                        'success': False,
                        'paths_found': 0,
                        'dominator_constraints': [],
                        'optional_constraints': [],
                        'error': 'No paths found to target point'
                    }

                # Extract constraints from the result structure
                dominator_constraints = []
                optional_constraints = []
                if constraint_results and len(constraint_results) > 0:
                    dominator_constraints = constraint_results[0].get('dominator_constraints', [])
                    optional_constraints = constraint_results[0].get('optional_constraints', [])

                result = {
                    'success': True,
                    'paths_found': len(paths),
                    'dominator_constraints': dominator_constraints,
                    'optional_constraints': optional_constraints
                }
                return result

            # Multi-point analysis: find paths through ALL points
            paths_with_constraints = self._find_paths_through_all_points(
                function_cfg, target_points, verbose
            )

            if not paths_with_constraints:
                return {
                    'success': False,
                    'paths_found': 0,
                    'dominator_constraints': [],
                    'optional_constraints': [],
                    'error': 'No paths found through all points'
                }

            # Compute cross-path dominator analysis
            dominator_constraints, optional_constraints = self._compute_cross_path_dominators(
                paths_with_constraints, verbose
            )

            result = {
                'success': True,
                'paths_found': len(paths_with_constraints),
                'dominator_constraints': dominator_constraints,
                'optional_constraints': optional_constraints
            }
            return result

        except Exception as e:
            logging.error(f"Error in multi-point constraint analysis: {e}")
            import traceback
            traceback.print_exc()
            return {
                'success': False,
                'paths_found': 0,
                'dominator_constraints': [],
                'optional_constraints': [],
                'error': str(e)
            }

    def _find_paths_through_all_points(
        self,
        function_cfg,
        target_points: List[ProgramPoint],
        verbose: bool = False
    ) -> List[Tuple]:
        """Find paths through every requested point with the core depth budget."""
        import time

        blocks_per_point = []
        for point in target_points:
            matching_blocks = [
                bb for bb in function_cfg.basic_blocks
                if self.core_extractor._program_point_overlaps_with_block(point, bb)
                and not self.core_extractor._is_reversed_block(bb)
            ]
            matching_blocks.sort(key=self.core_extractor._estimate_block_size)
            blocks_per_point.append(matching_blocks)

        target_blocks = self._select_blocks_for_points(target_points, blocks_per_point, verbose)
        if any(point not in target_blocks for point in target_points):
            logging.warning("Cannot find blocks for all requested program points")
            return []

        target_block = target_blocks[target_points[-1]]
        required_ids = {target_blocks[point].block_id for point in target_points[:-1]}
        started = time.monotonic()
        timed_out = False

        def collect(traverser, ignore_unrolled=False):
            nonlocal timed_out
            found = []
            for path, constraints in traverser.traverse_backward_with_constraints(
                target_block, verbose=verbose, ignore_unrolled=ignore_unrolled
            ):
                if time.monotonic() - started > 10.0:
                    timed_out = True
                    break
                if required_ids.issubset({bb.block_id for bb in path}):
                    found.append((path, constraints))
            return found

        paths_with_constraints = []
        cfg_builder = None
        for max_depth in (20, 40, 80, 160):
            if time.monotonic() - started > 10.0:
                timed_out = True
                break
            cfg_builder = self.core_extractor._create_cfg_builder_from_function(
                function_cfg, max_depth=max_depth
            )
            paths_with_constraints = collect(cfg_builder)
            if (paths_with_constraints or timed_out or cfg_builder.recursion_limit_reached
                    or not cfg_builder.depth_exceeded_count):
                break

        if (not timed_out and cfg_builder is not None and cfg_builder.path_limit_reached
                and any('_L' in bb.block_id for bb in function_cfg.basic_blocks)):
            retry_builder = self.core_extractor._create_cfg_builder_from_function(
                function_cfg, max_depth=cfg_builder.max_depth
            )
            retry_paths = collect(retry_builder, ignore_unrolled=True)
            if retry_paths:
                paths_with_constraints = retry_paths

        return paths_with_constraints

    def _select_blocks_for_points(
        self,
        target_points: List[ProgramPoint],
        blocks_per_point: List[List],
        verbose: bool = False
    ) -> Dict:
        """
        Select the best block for each target point, considering loop unrolling.

        Prefers blocks with lower unrolling levels (original code over unrolled iterations).

        Args:
            target_points: List of ProgramPoint objects
            blocks_per_point: List of lists of blocks for each point
            verbose: Whether to log detailed information

        Returns:
            Dict mapping ProgramPoint -> selected block
        """
        # Check if any point has multiple blocks (loop unrolling)
        has_unrolling = any(len(blocks) > 1 for blocks in blocks_per_point)

        if not has_unrolling:
            # Simple case: just use first (smallest) block for each point
            result = {}
            for i, point in enumerate(target_points):
                if blocks_per_point[i]:
                    result[point] = blocks_per_point[i][0]
            return result

        # Group blocks by unrolling level
        level_groups = {}  # level -> list of (point_idx, block)

        for point_idx, blocks in enumerate(blocks_per_point):
            for block in blocks:
                level = block.block_id.count('_L')
                if level not in level_groups:
                    level_groups[level] = []
                level_groups[level].append((point_idx, block))

        if verbose:
            logging.debug(f"Unrolling levels found: {sorted(level_groups.keys())}")

        # Try each level in order (prefer lower levels)
        for level in sorted(level_groups.keys()):
            level_blocks = level_groups[level]
            points_covered = {pb[0] for pb in level_blocks}

            if len(points_covered) == len(target_points):
                # This level covers all points
                if verbose:
                    logging.debug(f"Using unrolling level {level}")

                result = {}
                for point_idx in range(len(target_points)):
                    point = target_points[point_idx]
                    candidates = [block for pidx, block in level_blocks if pidx == point_idx]
                    if candidates:
                        # Choose smallest block
                        result[point] = min(
                            candidates,
                            key=lambda b: self.core_extractor._estimate_block_size(b)
                        )
                return result

        # No single level covers all points - use lowest level available for each
        result = {}
        for i, point in enumerate(target_points):
            if blocks_per_point[i]:
                # Sort by level then by size
                sorted_blocks = sorted(
                    blocks_per_point[i],
                    key=lambda b: (b.block_id.count('_L'), self.core_extractor._estimate_block_size(b))
                )
                result[point] = sorted_blocks[0]

        return result

    def _compute_cross_path_dominators(
        self,
        paths_with_constraints: List[Tuple],
        verbose: bool = False
    ) -> Tuple[List[Dict], List[Dict]]:
        """
        Compute cross-path dominator analysis.

        A constraint is a "dominator" (must-satisfy) if:
        - It appears in the paths AND
        - There is NO conflicting constraint (same line/context but different branch)

        Args:
            paths_with_constraints: List of (path, constraints) tuples
            verbose: Whether to log detailed information

        Returns:
            Tuple of (dominator_constraints, optional_constraints)
        """
        if not paths_with_constraints:
            return [], []

        # Collect all unique constraints
        all_unique_constraints = {}  # (line, branch, context) -> constraint
        paths_summaries = []  # List of path summaries

        for path_idx, (path, constraints) in enumerate(paths_with_constraints):
            path_summary = {}  # (line, branch, context) -> True

            for constraint in constraints:
                line = constraint.get('line')
                branch = constraint.get('branch')
                context = constraint.get('iteration_context', 'default')

                key = (line, branch, context)
                path_summary[key] = True

                if key not in all_unique_constraints:
                    all_unique_constraints[key] = constraint

            paths_summaries.append(path_summary)

        if verbose:
            logging.debug(f"Total unique constraints: {len(all_unique_constraints)}")

        # Track which branches appear for each (line, context)
        line_context_tracking = {}  # (line, context) -> {branch -> set of path indices}

        for path_idx, path_summary in enumerate(paths_summaries):
            for (line, branch, context) in path_summary:
                key = (line, context)
                if key not in line_context_tracking:
                    line_context_tracking[key] = {}
                if branch not in line_context_tracking[key]:
                    line_context_tracking[key][branch] = set()
                line_context_tracking[key][branch].add(path_idx)

        # Find must-satisfy constraints (no pairing branch)
        dominator_constraints = []
        optional_constraints = []
        paired_conditions = set()

        for (line, context), branch_paths in line_context_tracking.items():
            if len(branch_paths) > 1:
                # This condition has multiple branch values - it's paired/optional
                paired_conditions.add((line, context))

                # Add to optional constraints
                for branch, path_indices in branch_paths.items():
                    key = (line, branch, context)
                    if key in all_unique_constraints:
                        constraint = all_unique_constraints[key].copy()
                        constraint['path_count'] = len(path_indices)
                        constraint['total_paths'] = len(paths_with_constraints)
                        optional_constraints.append(constraint)
            else:
                # Only one branch value - must-satisfy
                branch = list(branch_paths.keys())[0]
                key = (line, branch, context)
                if key in all_unique_constraints:
                    dominator_constraints.append(all_unique_constraints[key])

        if verbose:
            logging.debug(
                f"Cross-path analysis: {len(all_unique_constraints)} unique, "
                f"{len(paired_conditions)} paired, {len(dominator_constraints)} must-satisfy"
            )

        return dominator_constraints, optional_constraints
