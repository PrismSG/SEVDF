import subprocess
import os
from json import JSONDecodeError
from typing import *
import shutil
from functools import lru_cache
import hashlib
try:
    # Try relative imports first (when used as a package)
    from .cfg_defs import Function, BasicBlock, FunctionCall
    from ..constraint_query import ConstraintQuery
except ImportError:
    # Fall back to absolute imports - but maintain the module structure
    import sys
    import os
    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if parent_dir not in sys.path:
        sys.path.insert(0, parent_dir)
    from cfg.cfg_defs import Function, BasicBlock, FunctionCall
    from constraint_query import ConstraintQuery

import logging
logger = logging.getLogger(__name__)
import json
import csv
import sqlite3
import os

# Check for quiet mode
QUIET_MODE = os.environ.get('CFG_QUIET_MODE', '0') == '1'

def cfg_print(*args, **kwargs):
    """Log at debug level (replaces print)"""
    # Join all arguments into a single string for logging
    message = ' '.join(str(arg) for arg in args)
    logging.debug(message)
        
def cfg_print_always(*args, **kwargs):
    """Log at info level (for important messages)"""
    # Join all arguments into a single string for logging
    message = ' '.join(str(arg) for arg in args)
    logging.info(message)
try:
    from .precomputed_adapter import PrecomputedAdapter
except ImportError:
    from precomputed_adapter import PrecomputedAdapter

from typing import Set

class DBHelper:
    def __init__(self, codeql_path, codeql_db_path, cache_dir=None):
        self.codeql_path = codeql_path
        self.codeql_db_path = codeql_db_path
        self.query_cache = {}
        self.unique_queries = {}
        self.use_csv_cache = False
        self.cache_dir = cache_dir
        
        # Check if pre-computed database exists
        if cache_dir:
            precomputed_db_path = os.path.join(cache_dir, "cfg_precomputed.db")
            if os.path.exists(precomputed_db_path):
                self.precomputed_adapter = PrecomputedAdapter(precomputed_db_path)
            else:
                self.precomputed_adapter = None
        else:
            self.precomputed_adapter = None
    
    # CSV caching methods are deprecated - we only use precomputed database
    def enable_csv_cache(self):
        """DEPRECATED: CSV caching is no longer used - only precomputed database."""
        pass  # No-op for backward compatibility
    
    def _get_query_hash(self, query_name, params):
        """DEPRECATED: Only used for cache key generation now."""
        key = f"{query_name}:{json.dumps(params, sort_keys=True)}"
        return hashlib.md5(key.encode()).hexdigest()
    
    def _get_csv_cache_path(self, query_hash):
        """DEPRECATED: CSV caching is no longer used."""
        return None
    
    def _cache_csv(self, query_hash, csv_path):
        """DEPRECATED: CSV caching is no longer used."""
        pass
    
    def _get_cached_csv(self, query_hash):
        """DEPRECATED: CSV caching is no longer used.""" 
        return None
    
    def run_codeql_query(self, query_file, params=None):
        """Run CodeQL query with parameters - ONLY uses precomputed database."""
        # Only use pre-computed adapter
        if self.precomputed_adapter:
            result = self.precomputed_adapter.get_query_result(query_file, params)
            if result is not None:
                return result
        
        # If precomputed adapter doesn't have the data, fail
        raise RuntimeError(f"Query '{query_file}' not found in precomputed database. All queries must use precomputed data.")
    
    def get_query_result(self, query_name, params):
        """Get query results with caching."""
        cache_key = f"{query_name}:{json.dumps(params, sort_keys=True)}"
        
        if cache_key in self.query_cache:
            # logger.debug(f"Using cached result for {query_name}")
            return self.query_cache[cache_key]
        
        # logger.debug(f"Running query: {query_name} with params: {params}")
        result = self.run_codeql_query(f"{query_name}.ql", params)
        self.query_cache[cache_key] = result
        return result
    
    def get_unique_query_count(self):
        """Get the number of unique queries executed."""
        return len(self.unique_queries)
    
    def get_query_stats(self):
        """Get statistics about query execution."""
        stats = []
        for query_key, count in self.unique_queries.items():
            query_name = query_key.split(':')[0]
            stats.append(f"{query_name}: {count} times")
        return stats


class CFGBuilder:
    def __init__(self, constraint_query: ConstraintQuery):
        self.codeql_path = constraint_query.codeql_path
        self.codeql_db_path = constraint_query.codeql_db_path
        self.cache_dir = constraint_query.cache_dir
        self.db_helper = DBHelper(self.codeql_path, self.codeql_db_path, self.cache_dir)
        # CSV caching no longer needed - using precomputed database only
        self.functions: List[Function] = []
        self.query_helper = constraint_query.query_helper
        
        # Initialize max depth based on config if available
        config_path = os.path.join(os.path.dirname(__file__), "..", "constraint_config.json")
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config = json.load(f)
                self.max_depth = config.get("analysis", {}).get("max_depth", 3)
        else:
            self.max_depth = 3
    
    def get_basic_blocks_batch(self, function_names: List[str]) -> Dict[str, List[Tuple]]:
        """DEPRECATED: Use precomputed database instead."""
        raise NotImplementedError("This method is deprecated. All CFG building must use precomputed database through get_query_result()")
    
    def get_bb_edges_batch(self, function_infos: List[Dict[str, str]]) -> Dict[str, List[Tuple]]:
        """DEPRECATED: Use precomputed database instead."""
        raise NotImplementedError("This method is deprecated. All CFG building must use precomputed database through get_query_result()")

    def build_function_cfg(self, func_info: Tuple[str, str, str, str]) -> Function:
        """Build CFG for a single function using precomputed database."""
        qualified_name, file_path, start_line, end_line = func_info
        
        block_id = f"{start_line}.0_{end_line}.0"
        f = Function(file_path, block_id, qualified_name)
        f.id = block_id
        f.cache_key = f"{qualified_name}_{os.path.basename(file_path)}_{start_line}"
        
        # Build basic blocks using precomputed data
        current_func_info = {"qualified_name": qualified_name}
        bb_query_result = self.db_helper.get_query_result("func_bb", current_func_info)
        
        # Build basic blocks
        skipped_invalid_blocks = 0
        for bb_info in bb_query_result:
            bb_file_path = bb_info[0]
            bb_id = bb_info[1]
            is_entry = bool(bb_info[2])
            is_exit = bool(bb_info[3])
            
            # Skip invalid blocks that start with 0.0
            if bb_id.startswith('0.0_'):
                skipped_invalid_blocks += 1
                continue
            
            bb = BasicBlock(bb_file_path, bb_id, qualified_name)
            bb.is_entry = is_entry
            bb.is_exit = is_exit
            
            f.basic_blocks.add(bb)
            
            # Log details for specific functions
            if qualified_name in ["test_one_file", "make_size_images"] and (is_entry or is_exit):
                cfg_print(f"      Block {bb_id}: entry={is_entry}, exit={is_exit}")
        
        # Log skipped blocks if any
        if skipped_invalid_blocks > 0:
            cfg_print(f"    Skipped {skipped_invalid_blocks} invalid blocks (starting with 0.0) during CFG construction for {qualified_name}")
        
        # Get edges
        edge_query_result = self.db_helper.get_query_result("func_bb_edge", {
            "qualified_name": qualified_name,
            "function_id": f.id
        })
        
        # Build edges
        for edge_info in edge_query_result:
            from_bb_id = edge_info[1]
            to_bb_id = edge_info[2]
            edge_type = edge_info[3] if len(edge_info) > 3 else "NONE"
            
            from_bb = f.get_basic_block(file_path, from_bb_id)
            to_bb = f.get_basic_block(file_path, to_bb_id)
            
            if from_bb and to_bb:
                from_bb.add_successor(to_bb, edge_type)
        
        # Get conditions
        cond_query_result = self.db_helper.get_query_result("func_bb_condition", {
            "qualified_name": qualified_name,
            "function_id": f.id
        })
        
        # Process conditions
        for cond_info in cond_query_result:
            bb_id = cond_info[1]
            true_bb_id = cond_info[2]
            false_bb_id = cond_info[3]
            
            bb = f.get_basic_block(file_path, bb_id)
            if bb:
                bb.has_condition = True
        
        # Unroll loops
        self.unroll_loops(f)
        
        # Log CFG structure for debugging - commented out to reduce verbosity
        # self.log_cfg_structure(f)
        
        return f

    def build_functions_cfg_batch(self, function_infos: List[Tuple[str, str, str, str]]) -> List[Function]:
        """Build CFGs for multiple functions in batch."""
        functions = []
        
        for func_info in function_infos:
            f = self.build_function_cfg(func_info)
            functions.append(f)
            self.functions.append(f)
        
        return functions

    def build_functions_cfg(self, entries: List[Tuple[str, str, str, str]], max_depth: int = None):
        """Build CFGs starting from entry functions with a maximum depth."""
        if max_depth is not None:
            self.max_depth = max_depth
            
        self.current_depth = 0
        self.processed_functions: Set[str] = set()
        self.pending_functions: List[Tuple[str, str, str, str]] = entries.copy()
        
        while self.pending_functions and self.current_depth <= self.max_depth:
            current_batch = self.pending_functions.copy()
            self.pending_functions = []
            
            for func_info in current_batch:
                qualified_name = func_info[0]
                if qualified_name not in self.processed_functions:
                    self.processed_functions.add(qualified_name)
                    self._build_single_function_cfg(func_info)
            
            self.current_depth += 1
            logger.error(
                f"Now Depth {self.current_depth}: {len(self.functions)}"
            )

    def _build_single_function_cfg(self, func_info: Tuple[str, str, str, str]):
        """Build CFG for a single function and discover new functions to process."""
        qualified_name, file_path, start_line, end_line = func_info
        
        block_id = f"{start_line}.0_{end_line}.0"
        f = Function(file_path, block_id, qualified_name)
        f.id = block_id
        f.cache_key = f"{qualified_name}_{os.path.basename(file_path)}_{start_line}"
        
        # Build basic blocks
        current_func_info = {"qualified_name": qualified_name}
        bb_query_result = self.db_helper.get_query_result("func_bb", current_func_info)
        
        skipped_invalid_blocks = 0
        for bb_info in bb_query_result:
            if len(bb_info) == 2:
                # Old format without entry/exit info
                bb_file_path = bb_info[0]
                bb_id = bb_info[1]
                is_entry = False
                is_exit = False
            else:
                # New format with entry/exit info
                bb_file_path = bb_info[0]
                bb_id = bb_info[1]
                is_entry = bool(bb_info[2])
                is_exit = bool(bb_info[3])
            
            # Skip invalid blocks that start with 0.0
            if bb_id.startswith('0.0_'):
                skipped_invalid_blocks += 1
                continue
            
            bb = BasicBlock(bb_file_path, bb_id, qualified_name)
            bb.is_entry = is_entry
            bb.is_exit = is_exit
            
            f.basic_blocks.add(bb)
        
        # Log skipped blocks if any
        if skipped_invalid_blocks > 0:
            cfg_print(f"    Skipped {skipped_invalid_blocks} invalid blocks (starting with 0.0) during CFG construction for {qualified_name}")
        
        # Build edges
        current_func_info["function_id"] = f.id
        edge_query_result = self.db_helper.get_query_result("func_bb_edge", current_func_info)
        
        for edge_info in edge_query_result:
            from_bb_id = edge_info[1]
            to_bb_id = edge_info[2]
            edge_type = edge_info[3] if len(edge_info) > 3 else "NONE"
            
            from_bb = f.get_basic_block(file_path, from_bb_id)
            to_bb = f.get_basic_block(file_path, to_bb_id)
            
            if from_bb and to_bb:
                from_bb.add_successor(to_bb, edge_type)
        
        # Get conditions
        cond_query_result = self.db_helper.get_query_result("func_bb_condition", current_func_info)
        
        for cond_info in cond_query_result:
            bb_id = cond_info[1]
            bb = f.get_basic_block(file_path, bb_id)
            if bb:
                bb.has_condition = True
        
        # Unroll loops
        self.unroll_loops(f)
        
        # Get function calls and add to pending if within depth
        if self.current_depth < self.max_depth:
            fc_query_result = self.db_helper.get_query_result("func_fc", current_func_info)
            
            for fc_info in fc_query_result:
                if len(fc_info) >= 6:
                    called_name = fc_info[1]
                    called_file = fc_info[2]
                    called_start = fc_info[3]
                    called_end = fc_info[4]
                    
                    if called_name not in self.processed_functions:
                        self.pending_functions.append((called_name, called_file, called_start, called_end))
        
        self.functions.append(f)

    def _identify_loop_body_general(self, loop_header: BasicBlock, back_edge_source: BasicBlock, all_blocks: set) -> set:
        """
        Identify loop body using reachability analysis.
        
        A block is in the loop if:
        1. It's reachable from the loop header
        2. It can reach the back edge source
        3. The path doesn't require going through an exit
        """
        # Simple approach: use standard reachability without worrying about other loops
        # The key insight: when we process loops from innermost to outermost,
        # the inner loops are already unrolled, so their back edges are already gone
        
        # Find all blocks reachable from header
        reachable_from_header = set()
        worklist = [loop_header]
        
        while worklist:
            current = worklist.pop()
            if current in reachable_from_header:
                continue
            reachable_from_header.add(current)
            
            for successor in current.successor_blocks:
                if successor not in reachable_from_header:
                    worklist.append(successor)
        
        # Find all blocks that can reach back edge source
        can_reach_back_edge = set()
        
        # Build reverse graph for efficiency
        reverse_edges = {}
        for block in all_blocks:
            for successor in block.successor_blocks:
                if successor not in reverse_edges:
                    reverse_edges[successor] = []
                reverse_edges[successor].append(block)
        
        # Backward reachability from back_edge_source
        worklist = [back_edge_source]
        
        while worklist:
            current = worklist.pop()
            if current in can_reach_back_edge:
                continue
            can_reach_back_edge.add(current)
            
            if current in reverse_edges:
                for predecessor in reverse_edges[current]:
                    if predecessor not in can_reach_back_edge:
                        worklist.append(predecessor)
        
        # Loop body = intersection
        loop_body = reachable_from_header & can_reach_back_edge
        
        # CRITICAL: For do-while loops, the back edge source (condition block) must be included
        # Otherwise it becomes orphaned after unrolling
        loop_body.add(back_edge_source)
        
        # For nested loops, we need to be more careful
        # If this is an outer loop and there are inner loops already unrolled,
        # we should include their unrolled versions too
        # This is handled by the code that adds unrolled_inner_blocks in unroll_loops
        
        return loop_body
    

    def _clone_blocks_for_iteration(self, f: Function, loop_blocks: set, iteration: int, loop_id: str = None) -> dict:
        """
        Create clones of all loop body blocks for the specified iteration.
        Returns a mapping from original block_id to cloned block.
        
        Args:
            f: Function containing the blocks
            loop_blocks: Set of blocks to clone
            iteration: Iteration number (1, 2, ...)
            loop_id: Unique identifier for this loop (e.g., "L9172")
        """
        cloned_mapping = {}  # original_block_id -> cloned_block
        
        for block in loop_blocks:
            # Create unique ID for cloned block
            if loop_id:
                # Use loop-specific naming
                clone_id = f"{block.block_id}_{loop_id}i{iteration}"
            else:
                # Fallback to old naming
                clone_id = f"{block.block_id}_iter{iteration}"
            
            # Create new block
            cloned_block = BasicBlock(
                file_path=block.file_path,
                block_id=clone_id,
                function_name=block.function_name
            )
            
            # Copy attributes
            cloned_block.condition_statement = block.condition_statement
            cloned_block.has_condition = block.has_condition
            cloned_block.is_entry = False  # Cloned blocks are never entry
            cloned_block.is_exit = block.is_exit
            cloned_block.called_functions = block.called_functions.copy()
            
            # Add to function
            f.basic_blocks.add(cloned_block)
            cloned_mapping[block.block_id] = cloned_block
            
        return cloned_mapping

    def _identify_blocks_to_clone(self, loop_body_blocks: set, all_blocks: set) -> set:
        """
        Identify all blocks that need to be cloned for proper loop unrolling.
        This includes:
        1. Loop body blocks
        2. Immediate conditional exit targets (e.g., break blocks)
        3. ALL blocks within the loop's line range (to handle precise blocks)
        """
        blocks_to_clone = loop_body_blocks.copy()
        
        # Extract loop line range
        loop_start_line = None
        loop_end_line = None
        
        for block in loop_body_blocks:
            # Consider ALL blocks, including already unrolled ones
            try:
                # Extract base block ID (before any _L suffixes)
                base_block_id = block.block_id.split('_L')[0] if '_L' in block.block_id else block.block_id
                
                # Extract start line
                start_line = int(base_block_id.split('.')[0])
                if loop_start_line is None or start_line < loop_start_line:
                    loop_start_line = start_line
                
                # Extract end line from block ID
                parts = base_block_id.split('_')
                if len(parts) > 1 and '.' in parts[1]:
                    end_line = int(parts[1].split('.')[0])
                    if loop_end_line is None or end_line > loop_end_line:
                        loop_end_line = end_line
            except:
                pass
        
        # CRITICAL FIX: Include ALL blocks within the loop's line range
        # This ensures precise blocks and already-unrolled blocks are included
        if loop_start_line is not None and loop_end_line is not None:
            added_count = 0
            for block in all_blocks:
                # Include ALL blocks, even already unrolled ones
                try:
                    # Extract base block ID (before any _L suffixes)
                    base_block_id = block.block_id.split('_L')[0] if '_L' in block.block_id else block.block_id
                    
                    # Extract block line range
                    block_start = int(base_block_id.split('.')[0])
                    block_end = block_start  # Default
                    
                    parts = base_block_id.split('_')
                    if len(parts) > 1 and '.' in parts[1]:
                        block_end = int(parts[1].split('.')[0])
                    
                    # Check if block is within loop range
                    if (loop_start_line <= block_start <= loop_end_line or
                        loop_start_line <= block_end <= loop_end_line or
                        (block_start <= loop_start_line and block_end >= loop_end_line)):
                        if block not in blocks_to_clone:
                            blocks_to_clone.add(block)
                            added_count += 1
                except:
                    pass
            
            if added_count > 0:
                cfg_print(f"        Added {added_count} additional blocks within loop range [{loop_start_line}, {loop_end_line}]")
        
        # Find immediate exit targets from conditional branches
        for block in loop_body_blocks:
            if len(block.successor_blocks) == 2:  # Conditional block
                for successor, edge_type in block.successor_blocks.items():
                    if successor not in loop_body_blocks and edge_type in ["TRUE", "FALSE"]:
                        # This is a conditional exit - clone it too
                        blocks_to_clone.add(successor)
                        cfg_print(f"        Including conditional exit target for cloning: {successor.block_id}")
        
        return blocks_to_clone
    
    def _fix_orphaned_nested_blocks(self, f: Function, loop_id: str):
        """
        Fix orphaned nested unrolled blocks after outer loop unrolling.
        
        When outer loop is unrolled, nested unrolled blocks like _L9182i2_L9172i2
        may become orphaned. This fixes those connections.
        """
        cfg_print(f"        Checking for orphaned nested blocks after unrolling {loop_id}...")
        
        fixed_connections = 0
        
        # Find blocks that are part of this outer loop's iter2
        outer_iter2_blocks = []
        for bb in f.basic_blocks:
            if bb.block_id.endswith(f"_{loop_id}i2"):
                outer_iter2_blocks.append(bb)
        
        # For each outer iter2 block, check if it should connect to nested unrolled blocks
        for outer_block in outer_iter2_blocks:
            # Get the successors of this block
            successors_copy = list(outer_block.successor_blocks.items())
            
            for succ, edge_type in successors_copy:
                # Get base ID of successor
                succ_base = succ.block_id.split('_L')[0] if '_L' in succ.block_id else succ.block_id
                
                # Look for nested unrolled versions that should also be connected
                for bb in f.basic_blocks:
                    # Check if this is a nested unrolled version of the successor
                    if (bb.block_id.startswith(succ_base) and
                        bb.block_id.endswith(f"_{loop_id}i2") and
                        bb != succ and
                        '_L' in bb.block_id and
                        bb.block_id.count('_L') > succ.block_id.count('_L')):
                        
                        # This is a nested unrolled version that should be connected
                        if bb not in outer_block.successor_blocks:
                            outer_block.add_successor(bb, edge_type)
                            cfg_print(f"          Fixed nested connection: {outer_block.block_id} -> {bb.block_id} ({edge_type})")
                            fixed_connections += 1
        
        if fixed_connections > 0:
            cfg_print(f"        ✓ Fixed {fixed_connections} orphaned nested block connections")
        else:
            cfg_print(f"        ✓ No orphaned nested blocks found")
    
    def _wire_cloned_blocks_general(self, original_blocks: set, cloned_mapping: dict):
        """
        Wire up the cloned blocks to mirror the original loop structure.
        
        General approach:
        - Internal edges (within cloned blocks) -> connect to cloned version
        - External edges -> preserve as is
        - Back edges -> DO NOT copy (to avoid creating cycles)
        - CRITICAL: Also copy edges from already-unrolled versions of blocks
        """
        # Create a set of original block IDs for quick lookup
        original_block_ids = {b.block_id for b in original_blocks}
        
        # Identify the loop header (has incoming back edge)
        loop_headers = set()
        for block in original_blocks:
            for successor in block.successor_blocks:
                if successor in original_blocks:
                    # Check if this is a back edge (successor has lower line number)
                    try:
                        block_line = int(block.block_id.split('.')[0])
                        succ_line = int(successor.block_id.split('.')[0])
                        if succ_line < block_line:
                            loop_headers.add(successor)
                    except:
                        pass
        
        # Process each cloned block
        for original_block_id, cloned_block in cloned_mapping.items():
            # Get the original block
            original_block = None
            for block in original_blocks:
                if block.block_id == original_block_id:
                    original_block = block
                    break
            
            if not original_block:
                continue
            
            # Copy edges from original to cloned
            for successor, edge_type in original_block.successor_blocks.items():
                # Check if this is a back edge
                is_back_edge = successor in loop_headers and original_block in original_blocks
                if is_back_edge:
                    # Skip back edges - they should not exist in iter2
                    cfg_print(f"        Skipping back edge in iter2: {cloned_block.block_id} -> {successor.block_id}")
                    continue
                    
                if successor.block_id in cloned_mapping:
                    # Edge to another cloned block - connect to cloned version
                    cloned_successor = cloned_mapping[successor.block_id]
                    cloned_block.add_successor(cloned_successor, edge_type)
                    cfg_print(f"          Cloned edge: {cloned_block.block_id} -> {cloned_successor.block_id} ({edge_type})")
                else:
                    # Edge to non-cloned block - preserve as is
                    cloned_block.add_successor(successor, edge_type)
                    cfg_print(f"          External edge: {cloned_block.block_id} -> {successor.block_id} ({edge_type})")
            

    def _detect_do_while_loops(self, f: Function) -> List[Tuple[str, str, str]]:
        """
        Detect do-while loops by analyzing back edges.
        Returns list of (loop_header_id, loop_exit_id, back_edge_source_id)
        """
        do_while_loops = []
        
        # Find all back edges
        for bb in f.basic_blocks:
            for succ in bb.successor_blocks:
                try:
                    # Check if it's a back edge
                    bb_line = int(bb.block_id.split('.')[0])
                    succ_line = int(succ.block_id.split('.')[0])
                    
                    if bb_line > succ_line:  # Back edge found
                        # The target of the back edge is the loop header
                        loop_header = succ
                        back_edge_source = bb
                        
                        # Find the exit block (FALSE branch from condition)
                        loop_exit = None
                        for exit_block, edge_type in back_edge_source.successor_blocks.items():
                            if edge_type == 'FALSE' or (edge_type == 'UNCONDITIONAL' and exit_block != loop_header):
                                loop_exit = exit_block
                                break
                        
                        if loop_exit:
                            do_while_loops.append((
                                loop_header.block_id,
                                loop_exit.block_id,
                                back_edge_source.block_id
                            ))
                except:
                    pass
        
        return do_while_loops
    
    def _detect_loops_by_scc(self, f: Function) -> list:
        """
        Detect loops using Tarjan's strongly connected components algorithm.
        This can find loops that database queries might miss.
        
        Returns:
            List of (header, exit, back_edge_source) tuples
        """
        # Tarjan's algorithm for SCC
        index_counter = [0]
        stack = []
        lowlinks = {}
        index = {}
        on_stack = {}
        sccs = []
        
        def strongconnect(v):
            index[v] = index_counter[0]
            lowlinks[v] = index_counter[0]
            index_counter[0] += 1
            stack.append(v)
            on_stack[v] = True
            
            for succ in v.successor_blocks:
                if succ not in index:
                    strongconnect(succ)
                    lowlinks[v] = min(lowlinks[v], lowlinks[succ])
                elif on_stack.get(succ, False):
                    lowlinks[v] = min(lowlinks[v], index[succ])
            
            if lowlinks[v] == index[v]:
                scc = []
                while True:
                    w = stack.pop()
                    on_stack[w] = False
                    scc.append(w)
                    if w == v:
                        break
                if len(scc) > 1:  # Non-trivial SCC is a loop
                    sccs.append(scc)
        
        # Find all SCCs
        for bb in f.basic_blocks:
            if bb not in index:
                strongconnect(bb)
        
        # Convert SCCs to loop format
        loops = []
        for scc in sccs:
            # Find the loop header (entry from outside SCC)
            header = None
            for block in scc:
                for pred_bb in f.basic_blocks:
                    if pred_bb not in scc and block in pred_bb.successor_blocks:
                        header = block
                        break
                if header:
                    break
            
            if not header:
                # If no external entry, pick the block with smallest line number
                header = min(scc, key=lambda b: int(b.block_id.split('.')[0]))
            
            # Find back edges
            for block in scc:
                if header in block.successor_blocks:
                    # This is a back edge
                    loops.append((header.block_id, None, block.block_id))
        
        return loops
    
    def _handle_self_loops(self, f: Function) -> int:
        """
        Handle self-loops by removing the self-edge.
        Self-loops can't be unrolled normally and need special treatment.
        
        Returns:
            Number of self-loops handled
        """
        self_loops_handled = 0
        
        for block in f.basic_blocks:
            # Check if block has a self-edge
            if block in block.successor_blocks:
                self_edge_type = block.successor_blocks[block]
                other_successors = [s for s in block.successor_blocks if s != block]
                
                # Remove the self-edge
                block.del_successor_by_id(block.block_id)
                self_loops_handled += 1
                
                # Log based on type
                if self_edge_type in ["TRUE", "FALSE"] and other_successors:
                    cfg_print(f"      Removed conditional self-loop at {block.block_id} (kept {len(other_successors)} exit edges)")
                elif not other_successors:
                    cfg_print(f"      Removed unconditional self-loop at {block.block_id} (infinite loop)")
                else:
                    cfg_print(f"      Removed self-loop at {block.block_id} (type: {self_edge_type})")
        
        return self_loops_handled

    def unroll_loops(self, f: Function):
        current_func_info = {"qualified_name": f.qualified_name,
                             "function_id": f.get_id()}

        # First, handle self-loops separately
        self_loops_handled = self._handle_self_loops(f)
        if self_loops_handled > 0:
            cfg_print(f"\n[CFG] Handled {self_loops_handled} self-loops in {f.qualified_name}")

        # Get loop results - the precomputed adapter handles func_loop correctly
        query_result = self.db_helper.get_query_result("func_loop", current_func_info)

        loops_unrolled = 0
        loop_details = []
        
        # Detect additional do-while loops
        do_while_loops = self._detect_do_while_loops(f)
        
        # Detect loops using SCC algorithm
        scc_loops = self._detect_loops_by_scc(f)
        
        # Merge all detected loops with query results
        additional_loops = []
        
        # Add do-while loops
        if do_while_loops:
            cfg_print(f"\n[CFG] Detected {len(do_while_loops)} additional do-while loops")
            for loop in do_while_loops:
                additional_loops.append(loop)
        
        # Add SCC-detected loops
        if scc_loops:
            cfg_print(f"\n[CFG] Detected {len(scc_loops)} loops via SCC algorithm")
            for loop in scc_loops:
                additional_loops.append(loop)
        
        # Merge with query results, avoiding duplicates
        for loop_header, loop_exit, back_edge_source in additional_loops:
            is_duplicate = False
            for existing in query_result:
                if (existing[0] == loop_header and 
                    existing[2] == back_edge_source):
                    is_duplicate = True
                    break
            
            if not is_duplicate:
                query_result.append([loop_header, loop_exit, back_edge_source])
                cfg_print(f"      Additional loop: header={loop_header}, back_edge={back_edge_source}")
        
        # Log raw loop detection results
        if query_result and len(query_result) > 0:
            cfg_print(f"\n[CFG] Loop detection for {f.qualified_name}:")
            cfg_print(f"      Found {len(query_result)} total loops")
            for i, result in enumerate(query_result):
                cfg_print(f"      Raw loop {i+1}: start={result[0]}, exit={result[1]}, back_edge_source={result[2]}")
        
        # Sort loops by their start position to handle nested loops properly
        # Nested loops should be unrolled from innermost to outermost
        sorted_loops = sorted(query_result, key=lambda x: x[0], reverse=True)
        
        for result in sorted_loops:
            loop_start_id = result[0]
            loop_successor_id = result[1]
            loop_predecessor_id = result[2]

            # Try to get blocks - handle file path mismatch
            loop_start_block = f.get_basic_block(f.get_file_path(), loop_start_id)
            if not loop_start_block:
                # Try without full path
                for bb in f.basic_blocks:
                    if bb.block_id == loop_start_id:
                        loop_start_block = bb
                        break
            
            loop_successor_block = f.get_basic_block(f.get_file_path(), loop_successor_id)
            if not loop_successor_block:
                for bb in f.basic_blocks:
                    if bb.block_id == loop_successor_id:
                        loop_successor_block = bb
                        break
            
            loop_predecessor_block = f.get_basic_block(f.get_file_path(), loop_predecessor_id)
            if not loop_predecessor_block:
                for bb in f.basic_blocks:
                    if bb.block_id == loop_predecessor_id:
                        loop_predecessor_block = bb
                        break

            # Log block information
            cfg_print(f"      Processing loop {loops_unrolled + 1}:")
            cfg_print(f"        Start block: {loop_start_id} -> {'found' if loop_start_block else 'NOT FOUND'}")
            cfg_print(f"        Exit block: {loop_successor_id} -> {'found' if loop_successor_block else 'NOT FOUND'}")  
            cfg_print(f"        Back edge source block: {loop_predecessor_id} -> {'found' if loop_predecessor_block else 'NOT FOUND'}")
            if loop_predecessor_block and loop_start_block:
                cfg_print(f"        Back edge: {loop_predecessor_id} -> {loop_start_id}")
            
            if loop_predecessor_block is not None and loop_start_block is not None:
                # Check if back edge exists
                if loop_start_block not in loop_predecessor_block.successor_blocks:
                    cfg_print(f"        Skipping loop {loops_unrolled + 1}: no back edge found")
                    continue
                
                # Validate that this is actually a back edge (source line > target line)
                try:
                    pred_line = int(loop_predecessor_id.split('.')[0])
                    start_line = int(loop_start_id.split('.')[0])
                    if pred_line < start_line:
                        cfg_print(f"        Skipping loop {loops_unrolled + 1}: not a back edge (line {pred_line} < {start_line})")
                        continue
                except:
                    pass  # If parsing fails, continue with loop processing
                    
                # === Two-iteration unrolling (General approach) ===
                # Step 1: Identify all blocks in the loop using general method
                loop_body_blocks = self._identify_loop_body_general(
                    loop_start_block, loop_predecessor_block, f.basic_blocks
                )
                cfg_print(f"        Loop body contains {len(loop_body_blocks)} blocks")
                
                # Check if loop is too large to unroll
                from .cfg_constants import MAX_LOOP_BODY_SIZE, MAX_LOOP_NESTING_DEPTH
                if len(loop_body_blocks) > MAX_LOOP_BODY_SIZE:
                    cfg_print(f"        Skipping loop {loops_unrolled + 1}: too large ({len(loop_body_blocks)} > {MAX_LOOP_BODY_SIZE} blocks)")
                    continue
                
                # Check nesting depth
                max_nesting = 0
                for block in loop_body_blocks:
                    nesting = block.block_id.count('_L')
                    max_nesting = max(max_nesting, nesting)
                
                if max_nesting >= MAX_LOOP_NESTING_DEPTH:
                    cfg_print(f"        Skipping loop {loops_unrolled + 1}: too deeply nested (depth {max_nesting} >= {MAX_LOOP_NESTING_DEPTH})")
                    continue
                
                # For proper nested unrolling: if this is an outer loop, 
                # also include unrolled versions from inner loops
                unrolled_inner_blocks = set()
                for block in loop_body_blocks:
                    # Find any unrolled versions of this block
                    block_base = block.block_id.split('_L')[0] if '_L' in block.block_id else block.block_id
                    for bb in f.basic_blocks:
                        if bb.block_id.startswith(block_base) and bb != block and ('_L' in bb.block_id or '_iter' in bb.block_id):
                            unrolled_inner_blocks.add(bb)
                
                if unrolled_inner_blocks:
                    cfg_print(f"        Found {len(unrolled_inner_blocks)} unrolled inner blocks to include")
                    loop_body_blocks.update(unrolled_inner_blocks)
                
                # Validate that the back edge source is actually in the loop
                if loop_predecessor_block not in loop_body_blocks:
                    cfg_print(f"        Skipping: back edge source not in computed loop body")
                    continue
                
                # Step 1.5: Identify all blocks that need cloning (including conditional exits)
                blocks_to_clone = self._identify_blocks_to_clone(loop_body_blocks, f.basic_blocks)
                cfg_print(f"        Total blocks to clone: {len(blocks_to_clone)} (including conditional exits)")
                
                # Step 2: Clone blocks for second iteration
                loop_id = f"L{loop_start_id.split('.')[0]}"  # Extract line number as loop ID
                cloned_blocks = self._clone_blocks_for_iteration(f, blocks_to_clone, iteration=2, loop_id=loop_id)
                cfg_print(f"        Created {len(cloned_blocks)} cloned blocks for iteration 2 (loop {loop_id})")
                
                # Step 3: Wire up cloned blocks using general approach
                self._wire_cloned_blocks_general(blocks_to_clone, cloned_blocks)
                
                # Step 3.5: Fix orphaned nested blocks (if this is an outer loop with nested unrolled blocks)
                if any('_L' in block.block_id for block in loop_body_blocks):
                    self._fix_orphaned_nested_blocks(f, loop_id)
                
                # Step 4: Redirect the back edge to second iteration
                if loop_start_block in loop_predecessor_block.successor_blocks:
                    # Remove back edge
                    loop_predecessor_block.del_successor_by_id(loop_start_id)
                    
                    # Connect to second iteration
                    if loop_start_id in cloned_blocks:
                        cloned_start = cloned_blocks[loop_start_id]
                        loop_predecessor_block.add_successor(cloned_start, "ITER2_START")
                        cfg_print(f"        Connected iteration 1 to iteration 2")
                
                
                # Step 5: Handle second iteration completion
                if loop_predecessor_id in cloned_blocks:
                    cloned_predecessor = cloned_blocks[loop_predecessor_id]
                    
                    # Remove any back edge from iter2 to iter2 header
                    if loop_start_id in cloned_blocks:
                        cloned_header = cloned_blocks[loop_start_id]
                        if cloned_header in cloned_predecessor.successor_blocks:
                            cloned_predecessor.del_successor_by_id(cloned_header.block_id)
                            cfg_print(f"        Removed back edge in iter2: {cloned_predecessor.block_id} -> {cloned_header.block_id}")
                    
                    # Connect to loop exits (where condition would be false)
                    # Only add exits that aren't already connected
                    for succ, edge_type in loop_start_block.successor_blocks.items():
                        if succ not in loop_body_blocks:
                            # This is a loop exit
                            if succ not in cloned_predecessor.successor_blocks:
                                cloned_predecessor.add_successor(succ, "ITER2_EXIT")
                                cfg_print(f"        Connected iteration 2 completion to exit {succ.block_id}")
                
                # Step 6: Verify no cycles in iter2
                cfg_print(f"        Verifying no cycles in iteration 2...")
                has_cycle = False
                for cloned_block_id, cloned_block in cloned_blocks.items():
                    for successor in cloned_block.successor_blocks:
                        if successor.block_id.endswith("_iter2"):
                            # Check if this creates a back edge
                            try:
                                cloned_line = int(cloned_block.block_id.split('_')[0].split('.')[0])
                                succ_line = int(successor.block_id.split('_')[0].split('.')[0])
                                if succ_line <= cloned_line:
                                    cfg_print(f"          WARNING: Potential cycle: {cloned_block.block_id} -> {successor.block_id}")
                                    has_cycle = True
                            except:
                                pass
                
                if not has_cycle:
                    cfg_print(f"        ✓ No cycles detected in iteration 2")
                
                loops_unrolled += 1
                
                # Extract line ranges from block IDs (format: startline.startcol_endline.endcol)
                def get_line_range(block_id):
                    parts = block_id.split('_')
                    if len(parts) == 2:
                        start = parts[0].split('.')[0]
                        end = parts[1].split('.')[0]
                        return f"L{start}-{end}"
                    return block_id
                
                # Improved loop info formatting
                start_range = get_line_range(loop_start_id)
                
                # Extract just the line numbers for cleaner display
                def extract_line(line_range):
                    if line_range.startswith('L'):
                        parts = line_range[1:].split('-')
                        return parts[0] if parts else line_range
                    return line_range
                
                loop_info = f"Loop {loops_unrolled}: 2 iterations, {len(cloned_blocks)} blocks cloned, header at line {extract_line(start_range)}"
                loop_details.append(loop_info)
        
        # Set the count on the function object
        f.unrolled_loops = loops_unrolled
        
        if loops_unrolled > 0:
            # Log unrolling summary
            logging.info(f"[CFG] Unrolled {loops_unrolled} loops in function {f.qualified_name}")
            for detail in loop_details:
                cfg_print(f"      {detail}")

    def log_cfg_structure(self, f: Function):
        """Log the CFG structure for debugging."""
        # Always log all functions - no filtering
        # Remove the filtering logic to log every single function
            
        logging.debug(f"\n[CFG Structure] Function: {f.qualified_name}")
        logging.debug(f"  File: {f.file_path}")
        logging.debug(f"  Total basic blocks: {len(f.basic_blocks)}")
        
        # Group blocks by entry/exit status
        entry_blocks = []
        exit_blocks = []
        normal_blocks = []
        
        for bb in f.basic_blocks:
            if bb.is_entry:
                entry_blocks.append(bb)
            elif bb.is_exit:
                exit_blocks.append(bb)
            else:
                normal_blocks.append(bb)
        
        logging.debug(f"  Entry blocks: {len(entry_blocks)}")
        for bb in entry_blocks:
            logging.debug(f"    - {bb.block_id}")
            
        logging.debug(f"  Exit blocks: {len(exit_blocks)}")
        for bb in exit_blocks:
            logging.debug(f"    - {bb.block_id}")
        
        # Log detailed block information
        logging.debug(f"\n  Basic Block Graph:")
        
        # Sort blocks by line number for better readability
        sorted_blocks = sorted(f.basic_blocks, key=lambda b: int(b.block_id.split('.')[0]))
        
        for bb in sorted_blocks:
            # Extract line numbers for display
            try:
                start_line = bb.block_id.split('_')[0].split('.')[0]
                end_line = bb.block_id.split('_')[1].split('.')[0]
                line_info = f"L{start_line}-{end_line}"
            except:
                line_info = bb.block_id
                
            # Build successor info
            successors = []
            for succ in bb.successor_blocks:
                try:
                    succ_start = succ.block_id.split('_')[0].split('.')[0]
                    successors.append(f"L{succ_start}")
                except:
                    successors.append(succ.block_id)
            
            # Build predecessor info
            predecessors = []
            for pred in bb.predecessor_blocks:
                try:
                    pred_start = pred.block_id.split('_')[0].split('.')[0]
                    predecessors.append(f"L{pred_start}")
                except:
                    predecessors.append(pred.block_id)
            
            # Format block info
            block_type = []
            if bb.is_entry:
                block_type.append("ENTRY")
            if bb.is_exit:
                block_type.append("EXIT")
            if bb.has_condition:
                block_type.append("COND")
                
            type_str = f" [{', '.join(block_type)}]" if block_type else ""
            
            logging.debug(f"    {line_info}{type_str}:")
            if predecessors:
                logging.debug(f"      <- from: {', '.join(predecessors)}")
            if successors:
                logging.debug(f"      -> to: {', '.join(successors)}")
            else:
                logging.debug(f"      -> (no successors)")
                
        # Print loop information if any
        if hasattr(f, 'unrolled_loops') and f.unrolled_loops > 0:
            logging.debug(f"\n  Loops unrolled: {f.unrolled_loops}")

    def get_entire_function(self, functioncall: FunctionCall) -> Function:
        next_function = next(
            (f for f in self.functions if f == functioncall.function),
             None  # default value
            )
        return next_function

    def build_cfg_from_csv(self, csv_files, called_file, max_depth=3):
        """
        Build control flow graph from CSV files for functions found in results.
        
        Args:
            csv_files: List of CSV file paths containing analysis results
            called_file: File path for filtering functions
            max_depth: Maximum depth for function call analysis
        """
        # Extract unique functions from CSV files
        unique_functions = set()
        
        for csv_file in csv_files:
            if not os.path.exists(csv_file):
                logger.error(f"CSV file not found: {csv_file}")
                continue
                
            with open(csv_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    func_name = row.get('function_name', '')
                    if func_name:
                        unique_functions.add(func_name)
        
        if not unique_functions:
            logger.error("No functions found in CSV files")
            return
        
        logger.error(f"Building CFG for {len(unique_functions)} unique functions")
        
        # Get function details for each unique function
        entry_functions = []
        for func_name in unique_functions:
            func_details = self._get_function_details(func_name, called_file)
            if func_details:
                entry_functions.append(func_details)
        
        if entry_functions:
            self.build_functions_cfg(entry_functions, max_depth)
            logger.error(f"Built CFG with {len(self.functions)} total functions")
    
    def _get_function_details(self, func_name: str, file_path: str = None) -> Optional[Tuple[str, str, str, str]]:
        """
        Get function details (qualified_name, file_path, start_line, end_line).
        
        Args:
            func_name: Function name
            file_path: Optional file path filter
            
        Returns:
            Tuple of (qualified_name, file_path, start_line, end_line) or None
        """
        params = {"function_name": func_name}
        if file_path:
            params["file_path"] = file_path
            
        result = self.db_helper.get_query_result("func_details", params)
        
        if result and len(result) > 0:
            # Return first match
            row = result[0]
            if len(row) >= 4:
                return (row[0], row[1], row[2], row[3])
        
        return None

    def get_call_graph(self):
        def build_call_subgraph(func: Function):
            graph = {func.qualified_name: {}}
            for fc in func.function_calls:
                called_func = self.get_entire_function(fc)
                if called_func:
                    graph[func.qualified_name][called_func.qualified_name] = build_call_subgraph(called_func)
            return graph

        return build_call_subgraph(self.entry_function)

    def print_query_stats(self):
        """Print statistics about CodeQL queries executed."""
        logging.debug(f"\n[Query Statistics]")
        logging.debug(f"Total unique queries: {self.db_helper.get_unique_query_count()}")
        logging.debug("Query breakdown:")
        for stat in self.db_helper.get_query_stats():
            logging.debug(f"  - {stat}")