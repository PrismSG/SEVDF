#!/usr/bin/env python3
"""
CFG Manager - Function-level CFG building and caching API

This module provides a clean API for building and managing Control Flow Graphs (CFGs)
for individual functions. It's designed to be used by StaticAnalysisBackend during
the analysis phase to build and cache CFGs for later constraint analysis.
"""

import os
import sys
import json
import hashlib
import tempfile
import logging
import time
import pickle
from typing import List, Dict, Set, Optional, Tuple, TYPE_CHECKING

# Ensure current directory is in path for submodule imports
_current_dir = os.path.dirname(__file__)
if _current_dir not in sys.path:
    sys.path.insert(0, _current_dir)

if TYPE_CHECKING:
    from AdvancedTools.CodeSearch.symbol_lookup import SymbolLookup

# Import CFG components
from cfg.cfg_builder import CFGBuilder
from cfg.cfg_defs import Function, BasicBlock, CFGCache

# Import cache configuration from project standards
from AdvancedTools.KnowledgeStorage.cache_config import log_cache_activity

# Import ConstraintQuery from separate module
from constraint_query import ConstraintQuery


class FunctionCFGManager:
    """
    Manages CFG building and caching for individual functions.
    
    This class provides a clean separation between CFG building and constraint analysis,
    allowing StaticAnalysisBackend to build CFGs during analysis and ConstraintAnalysis
    to reuse them later.
    """
    
    def __init__(self, project_name: str = "default_project"):
        self.project_name = project_name
        logging.debug(f"[CFG_MANAGER] Initializing FunctionCFGManager for project: {project_name}")
        
        # IMPORTANT: Set up module aliases for pickle compatibility
        # This ensures that both cfg_defs and cfg.cfg_defs point to the same module
        import sys
        current_dir = os.path.dirname(os.path.abspath(__file__))
        cfg_dir = os.path.join(current_dir, 'cfg')
        
        # Make sure cfg_defs and cfg.cfg_defs are the same module
        if 'cfg.cfg_defs' not in sys.modules and 'cfg_defs' not in sys.modules:
            # First time loading - set up the imports correctly
            if current_dir not in sys.path:
                sys.path.insert(0, current_dir)
            from cfg import cfg_defs
            sys.modules['cfg_defs'] = cfg_defs  # Alias for backward compatibility
        elif 'cfg.cfg_defs' in sys.modules and 'cfg_defs' not in sys.modules:
            sys.modules['cfg_defs'] = sys.modules['cfg.cfg_defs']
        elif 'cfg_defs' in sys.modules and 'cfg.cfg_defs' not in sys.modules:
            sys.modules['cfg.cfg_defs'] = sys.modules['cfg_defs']
        
        self.cache_dir = self._get_cache_directory()
        self.cfg_cache = CFGCache(self.cache_dir)
        # Create subfolder for our custom function cache
        self.function_cache_dir = os.path.join(self.cache_dir, "function_cfgs")
        os.makedirs(self.function_cache_dir, exist_ok=True)
        logging.debug(f"[CFG_MANAGER] Cache directory: {self.cache_dir}")
        logging.debug(f"[CFG_MANAGER] Function cache directory: {self.function_cache_dir}")
        
    def _get_cache_directory(self) -> str:
        """Get cache directory following project patterns."""
        # Check if AI_ANALYSIS_DIR environment variable is set (project standard)
        ai_analysis_dir = os.getenv('AI_ANALYSIS_DIR')

        if not ai_analysis_dir:
            error_msg = "AI_ANALYSIS_DIR environment variable is not set. CFG cache requires proper project isolation."
            log_cache_activity(f"CFG MANAGER ERROR: {error_msg}")
            raise RuntimeError(error_msg)

        # Use AI Analysis Dir cache folder with separate CFG subdirectory
        cache_dir = os.path.join(ai_analysis_dir, 'cache', 'cfg_cache')
        log_cache_activity(f"CFG MANAGER: Using AI_ANALYSIS_DIR cache: {cache_dir}")

        # Ensure cache directory exists
        os.makedirs(cache_dir, exist_ok=True)
        return cache_dir
    
    def _generate_function_key(self, function_name: str, file_path: str, start_line: int) -> str:
        """Generate a unique cache key for a function.

        Must match the format used in cfg_builder.py:
            f.cache_key = f"{qualified_name}_{os.path.basename(file_path)}_{start_line}"
        """
        # Use basename directly - must match cfg_builder.py format exactly
        file_name = os.path.basename(file_path)
        key = f"{function_name}_{file_name}_{start_line}"
        logging.debug(f"[CFG_MANAGER] Generated cache key: {key} for {function_name} in {file_path}:{start_line}")
        return key
    
    def _get_codeql_path(self) -> str:
        """Get CodeQL path from environment or default."""
        codeql_path = os.getenv("CODEQL_PATH", "codeql")
        
        # If it's a directory, append the binary name
        if os.path.isdir(codeql_path):
            codeql_path = os.path.join(codeql_path, "codeql")
        return codeql_path
    
    def _get_cache_file_path(self, function_key: str) -> str:
        """Get the cache file path for a function."""
        return os.path.join(self.function_cache_dir, f"{function_key}.pkl")

    def _find_cached_function_key(self, function_name: str, file_path: str, start_line: int) -> Optional[str]:
        """Prefer the builder's key, with a fallback for older Public caches."""
        function_key = self._generate_function_key(function_name, file_path, start_line)
        if os.path.exists(self._get_cache_file_path(function_key)):
            return function_key
        file_name = os.path.basename(file_path)
        legacy_file_name = file_name.replace('.', '_').replace('/', '_').replace('\\', '_')
        legacy_key = f"{function_name}_{legacy_file_name}_{start_line}"
        if os.path.exists(self._get_cache_file_path(legacy_key)):
            return legacy_key
        return None
    
    def _save_function_to_cache(self, function_key: str, function: Function) -> None:
        """Save function to our custom cache."""
        # Verify function and all basic blocks have required attributes before saving
        if not hasattr(function, 'file_path') or not function.file_path:
            log_cache_activity(f"WARNING: Function {function.qualified_name} missing file_path!")
            logging.warning(f"[CFG_MANAGER] Cannot save function {function_key}: missing file_path")
            return
            
        if not hasattr(function, 'basic_blocks') or not function.basic_blocks:
            log_cache_activity(f"WARNING: Function {function.qualified_name} has no basic blocks!")
            logging.warning(f"[CFG_MANAGER] Cannot save function {function_key}: no basic blocks")
            return
        
        # Verify and fix all basic blocks
        for bb in function.basic_blocks:
            if not hasattr(bb, 'file_path'):
                log_cache_activity(f"WARNING: BasicBlock {bb.block_id} missing file_path attribute! Fixing...")
                # Fix by setting from function
                bb.file_path = function.file_path
            
            if not hasattr(bb, 'block_id'):
                log_cache_activity(f"ERROR: BasicBlock missing block_id attribute!")
                return
            
            # Ensure function reference is set
            if not hasattr(bb, 'function') or bb.function is None:
                bb.function = function
        
        cache_file = self._get_cache_file_path(function_key)
        try:
            # Increase recursion limit for complex CFGs
            old_limit = sys.getrecursionlimit()
            # For very complex functions, we may need a higher limit
            new_limit = 50000 if 'compare_two_images' in function_key else 10000
            sys.setrecursionlimit(new_limit)
            logging.debug(f"[CFG_MANAGER] Set recursion limit to {new_limit} for {function_key} (was {old_limit})")
            
            try:
                with open(cache_file, 'wb') as f:
                    pickle.dump(function, f)
            finally:
                # Restore original recursion limit
                sys.setrecursionlimit(old_limit)
            
            # Verify the file was written correctly
            file_size = os.path.getsize(cache_file)
            if file_size == 0:
                logging.error(f"[CFG_MANAGER] ERROR: Saved empty cache file: {cache_file}")
                log_cache_activity(f"WARNING: Empty cache file created: {cache_file}")
                # DO NOT remove the file - leave it for debugging
            else:
                log_cache_activity(f"Saved function to cache: {cache_file} (size: {file_size} bytes)")
                logging.debug(f"[CFG_MANAGER] Successfully cached {function_key} ({file_size} bytes)")
        except RecursionError as e:
            log_cache_activity(f"RecursionError saving function to cache: {e}")
            logging.error(f"[CFG_MANAGER] RecursionError for {function_key}: CFG too complex/circular")
            logging.debug(f"[CFG_MANAGER] Try increasing recursion limit further if needed")
            # DO NOT remove any files - leave them for debugging
            if os.path.exists(cache_file):
                file_size = os.path.getsize(cache_file)
                logging.warning(f"[CFG_MANAGER] Cache file exists but save failed. Size: {file_size} bytes")
        except Exception as e:
            log_cache_activity(f"Error saving function to cache: {e}")
            logging.error(f"[CFG_MANAGER] Failed to save {function_key}: {e}")
            # DO NOT remove any files - leave them for debugging
            if os.path.exists(cache_file):
                file_size = os.path.getsize(cache_file)
                logging.warning(f"[CFG_MANAGER] Cache file exists but save failed. Size: {file_size} bytes")
    
    def _load_function_from_cache(self, function_key: str) -> Optional[Function]:
        """Load function from our custom cache."""
        cache_file = self._get_cache_file_path(function_key)
        logging.debug(f"[CFG_MANAGER] Looking for cache file: {cache_file}")
        
        if not os.path.exists(cache_file):
            logging.debug(f"[CFG_MANAGER] Cache file does not exist: {cache_file}")
            # Check if file exists without considering case or with slight variations
            cache_dir = os.path.dirname(cache_file)
            cache_filename = os.path.basename(cache_file)
            if os.path.exists(cache_dir):
                files_in_dir = os.listdir(cache_dir)
                similar_files = [f for f in files_in_dir if function_key in f]
                if similar_files:
                    logging.debug(f"[CFG_MANAGER] Found similar files: {similar_files[:10]}...")
            return None
            
        # Check if file is empty
        if os.path.getsize(cache_file) == 0:
            log_cache_activity(f"Cache file is empty: {cache_file}")
            logging.warning(f"[CFG_MANAGER] Empty cache file detected: {cache_file}")
            return None
            
        try:
            # Increase recursion limit for complex CFGs
            old_limit = sys.getrecursionlimit()
            sys.setrecursionlimit(10000)  # Increase from default 1000
            
            try:
                with open(cache_file, 'rb') as f:
                    function = pickle.load(f)
            finally:
                # Restore original recursion limit
                sys.setrecursionlimit(old_limit)
            
            # Verify and fix loaded function
            if function:
                # Ensure all basic blocks have required attributes
                for bb in function.basic_blocks:
                    if not hasattr(bb, 'file_path') and hasattr(function, 'file_path'):
                        bb.file_path = function.file_path
                        log_cache_activity(f"Fixed missing file_path for BasicBlock {bb.block_id}")
                    
                    if not hasattr(bb, 'function') or bb.function is None:
                        bb.function = function
            
            log_cache_activity(f"Loaded function from cache: {cache_file}")
            return function
        except Exception as e:
            log_cache_activity(f"Error loading function from cache: {e}")
            # DO NOT remove cache file - just log the error
            # if os.path.exists(cache_file):
            #     os.remove(cache_file)
            return None
    
    def has_cached_cfg(self, function_name: str, file_path: str, start_line: int) -> bool:
        """Check if a function's CFG is already cached."""
        return self._find_cached_function_key(function_name, file_path, start_line) is not None
    
    def build_function_cfg(
        self, 
        function_name: str, 
        file_path: str, 
        start_line: int,
        codeql_db_path: str,
        source_path: str,
        force_rebuild: bool = False
    ) -> Function:
        """
        Build CFG for a single function.
        
        Args:
            function_name: Name of the function
            file_path: Path to the source file containing the function
            start_line: Starting line number of the function
            codeql_db_path: Path to the CodeQL database
            source_path: Path to the source code directory
            force_rebuild: Force rebuild even if cached
            
        Returns:
            Function object with CFG
        """
        function_key = self._generate_function_key(function_name, file_path, start_line)
        
        # Check cache first (unless force rebuild)
        if not force_rebuild:
            cached_key = self._find_cached_function_key(function_name, file_path, start_line)
            if cached_key:
                cached_function = self._load_function_from_cache(cached_key)
                if cached_function:
                    log_cache_activity(f"CFG CACHE HIT: {cached_key}")
                    return cached_function
        
        log_cache_activity(f"CFG CACHE MISS: Building CFG for {function_key}")
        
        try:
            # Create a ConstraintQuery object for CFGBuilder
            # ConstraintQuery is now defined in this module
            constraint_query = ConstraintQuery(
                codeql_path=self._get_codeql_path(),
                codeql_db_path=codeql_db_path,
                cache_dir=self.cache_dir,
                query_helper=None
            )
            
            # Build CFG using CFGBuilder
            cfg_builder = CFGBuilder(constraint_query)
            
            # Build single function CFG
            function_info = (function_name, file_path, str(start_line), str(start_line + 10))  # Approximate end line
            built_function = cfg_builder.build_function_cfg(function_info)
            
            # Validate the built function before caching
            if built_function and hasattr(built_function, 'basic_blocks') and built_function.basic_blocks:
                # Cache the function using our custom cache
                self._save_function_to_cache(function_key, built_function)
                log_cache_activity(f"CFG CACHED: Saved {function_key}")
            else:
                # Log at DEBUG level - empty basic_blocks is common for functions not in precomputed database
                # The caller (build_functions_cfg_batch) will handle the validation and logging
                logging.debug(f"[CFG_MANAGER] Function {function_key} has no basic blocks (likely not in precomputed database)")

            return built_function
            
        except Exception as e:
            # Log the full exception details
            import traceback
            full_error = traceback.format_exc()
            log_cache_activity(f"CFG BUILD DETAILED ERROR for {function_key}:\n{full_error}")
            raise
            
        finally:
            pass  # No temporary files to clean up
    
    def build_functions_cfg_batch(
        self,
        functions_list: List[Tuple[str, str, int]],
        codeql_db_path: str,
        source_path: str,
        skip_cached: bool = True
    ) -> Dict[str, Function]:
        """
        Build CFGs for multiple functions efficiently.
        
        Args:
            functions_list: List of (function_name, file_path, start_line) tuples
            codeql_db_path: Path to the CodeQL database
            source_path: Path to the source code directory  
            skip_cached: Skip functions that are already cached
            
        Returns:
            Dictionary mapping function keys to Function objects
        """
        # Check if pre-computation is needed (transparent optimization)
        precomputed_db_path = os.path.join(self.cache_dir, "cfg_precomputed.db")
        if not os.path.exists(precomputed_db_path):
            print("[+] First-time CFG building detected. Pre-computing CFG data for optimal performance...", flush=True)
            print("[+] This one-time setup will make all future CFG building ~1000x faster", flush=True)
            try:
                from cfg_precompute import CFGPrecomputer
                # Try to get function CSV path from environment variable
                function_csv = os.environ.get('FUNCTION_CSV')
                if function_csv and os.path.exists(function_csv):
                    print(f"[+] Using Function CSV from environment: {function_csv}", flush=True)
                else:
                    function_csv = None
                    
                # Get path prefixes from environment or config
                path_prefixes = []
                if 'PATH_PREFIXES' in os.environ:
                    path_prefixes = os.environ['PATH_PREFIXES'].split(':')
                
                precomputer = CFGPrecomputer(self._get_codeql_path(), codeql_db_path, self.cache_dir, function_csv, path_prefixes)
                precomputer.precompute_all()
                print("[+] Pre-computation complete! CFG building will now use optimized queries", flush=True)
            except Exception as e:
                print(f"[!] Pre-computation failed (will use individual queries): {e}", flush=True)
                print("[!] CFG building will continue but may be slower", flush=True)
        
        results = {}
        functions_to_build = []
        
        # Filter out cached functions if requested
        for function_name, file_path, start_line in functions_list:
            function_key = self._generate_function_key(function_name, file_path, start_line)
            
            cached_key = self._find_cached_function_key(function_name, file_path, start_line) if skip_cached else None
            if cached_key:
                # Load from cache
                cached_function = self._load_function_from_cache(cached_key)
                if cached_function:
                    results[function_key] = cached_function
                    log_cache_activity(f"CFG CACHE HIT: {function_key}")
                    continue
            
            functions_to_build.append((function_name, file_path, start_line, function_key))
        
        # Build remaining functions
        log_cache_activity(f"CFG BATCH BUILD: {len(functions_to_build)} functions to build")
        
        if os.path.exists(precomputed_db_path):
            print(f"[+] Building {len(functions_to_build)} CFGs using pre-computed data (fast mode)", flush=True)
        else:
            print(f"[+] Building {len(functions_to_build)} CFGs using individual queries", flush=True)
        
        # Removed debug output for cleaner logs
        
        # Track build statistics
        newly_built_count = 0
        no_basic_blocks_count = 0
        error_count = 0

        for function_name, file_path, start_line, function_key in functions_to_build:
            try:
                built_function = self.build_function_cfg(
                    function_name, file_path, start_line,
                    codeql_db_path, source_path, force_rebuild=True
                )

                # Validate the built function has actual basic blocks
                if built_function and hasattr(built_function, 'basic_blocks') and built_function.basic_blocks:
                    results[function_key] = built_function
                    newly_built_count += 1
                    log_cache_activity(f"CFG BUILD SUCCESS: {function_key}")
                    print(f"[+] Successfully built CFG for: {function_key}", flush=True)
                else:
                    # Function was built but has no basic blocks - this is not a success
                    no_basic_blocks_count += 1
                    log_cache_activity(f"CFG BUILD INCOMPLETE: {function_key} - no basic blocks")
                    logging.warning(f"[CFG_MANAGER] Function {function_key} built but has no basic blocks (not in precomputed database?)")
            except Exception as e:
                error_count += 1
                error_msg = f"CFG BUILD ERROR: {function_key} - {e}"
                log_cache_activity(error_msg)
                print(f"Warning: {error_msg}", flush=True)  # Also print to console for debugging
                continue

        # Summary - count cached functions separately from newly built
        cached_count = len(results) - newly_built_count

        print(f"\n[+] CFG Building Summary:", flush=True)
        print(f"    Total attempted: {len(functions_to_build)}", flush=True)
        print(f"    Newly built: {newly_built_count}", flush=True)
        print(f"    No basic blocks (skipped): {no_basic_blocks_count}", flush=True)
        print(f"    Errors: {error_count}", flush=True)
        if cached_count > 0:
            print(f"    Loaded from cache: {cached_count}", flush=True)
        
        log_cache_activity(f"CFG BATCH COMPLETE: Built {newly_built_count}/{len(functions_to_build)} functions, {cached_count} from cache")
        return results
    
    def get_cached_function(self, function_name: str, file_path: str, start_line: int) -> Optional[Function]:
        """Get a cached function CFG if available."""
        function_key = self._generate_function_key(function_name, file_path, start_line)
        logging.debug(f"[CFG_MANAGER] Looking for cached function with key: {function_key}")

        # Log the exact file path we're looking for
        expected_path = self._get_cache_file_path(function_key)
        logging.debug(f"[CFG_MANAGER] Expected cache file path: {expected_path}")
        logging.debug(f"[CFG_MANAGER] File exists: {os.path.exists(expected_path)}")
        if os.path.exists(expected_path):
            logging.debug(f"[CFG_MANAGER] File size: {os.path.getsize(expected_path)} bytes")

        cached_key = self._find_cached_function_key(function_name, file_path, start_line)
        result = self._load_function_from_cache(cached_key or function_key)
        if result:
            logging.debug(f"[CFG_MANAGER] Found cached function {function_name}")
            return result

        # If not found and function_name is a simple name, try to get qualified name from SymbolLookup
        if '::' not in function_name:
            try:
                from AdvancedTools.CodeSearch.symbol_lookup import get_symbol_lookup
                symbol_lookup = get_symbol_lookup()
                lookup_result = symbol_lookup.lookup_by_qualified_name(function_name, file_path)
                if lookup_result:
                    qualified_name, csv_start_line = lookup_result
                    if qualified_name != function_name:
                        # Try with qualified name
                        qualified_key = self._generate_function_key(qualified_name, file_path, csv_start_line)
                        logging.debug(f"[CFG_MANAGER] Trying qualified name key: {qualified_key}")
                        qualified_cached_key = self._find_cached_function_key(qualified_name, file_path, csv_start_line)
                        result = self._load_function_from_cache(qualified_cached_key or qualified_key)
                        if result:
                            logging.debug(f"[CFG_MANAGER] Found cached function with qualified name: {qualified_name}")
                            return result
            except Exception as e:
                logging.debug(f"[CFG_MANAGER] SymbolLookup failed: {e}")

        logging.debug(f"[CFG_MANAGER] No cached function found for {function_name}")
        return None
    
    def clear_cache(self):
        """Clear all cached CFGs."""
        if os.path.exists(self.function_cache_dir):
            for file in os.listdir(self.function_cache_dir):
                if file.endswith('.pkl'):
                    os.remove(os.path.join(self.function_cache_dir, file))
        log_cache_activity("CFG CACHE: Cleared all cached functions")
    
    def get_cache_stats(self) -> Dict:
        """Get cache statistics."""
        cache_files = []
        if os.path.exists(self.function_cache_dir):
            cache_files = [f for f in os.listdir(self.function_cache_dir) if f.endswith(".pkl")]

        return {
            "cache_directory": self.function_cache_dir,
            "cached_functions": len(cache_files),
            "cache_files": cache_files
        }

    def extract_functions_from_analysis_results(
        self,
        analysis_results: List,
        symbol_lookup: "SymbolLookup"
    ) -> Set[Tuple[str, str, int]]:
        """
        Extract unique functions from analysis results for CFG building.

        Args:
            analysis_results: List of analysis result items (JSON strings or dicts)
            symbol_lookup: SymbolLookup instance for lookup

        Returns:
            Set of (qualified_name, file_path, start_line) tuples
        """
        unique_functions = set()

        def add_function(function_name, file_path, fallback_line):
            """Helper to lookup CSV and add function with correct start_line."""
            if not function_name or not file_path:
                return
            # Lookup CSV to get start_line
            csv_info = symbol_lookup.lookup_by_qualified_name(function_name, file_path)
            if csv_info:
                qualified_name, start_line = csv_info
                unique_functions.add((qualified_name, file_path, start_line))
            else:
                # Fallback: use function_name directly (CFG lookup may fail)
                unique_functions.add((function_name, file_path, fallback_line))

        for result_item in analysis_results:
            try:
                # Parse JSON result
                if isinstance(result_item, str):
                    result_data = json.loads(result_item)
                else:
                    result_data = result_item

                # Extract functions from source, sink, and propagation path
                if 'source' in result_data:
                    source = result_data['source']
                    if 'functionName' in source and source['functionName']:
                        add_function(
                            source['functionName'],
                            source['file_path'],
                            source.get('line', 0)
                        )

                if 'sink' in result_data:
                    sink = result_data['sink']
                    if 'functionName' in sink and sink['functionName']:
                        add_function(
                            sink['functionName'],
                            sink['file_path'],
                            sink.get('line', 0)
                        )

                if 'propagation path' in result_data:
                    for step in result_data['propagation path']:
                        if 'from' in step:
                            from_info = step['from']
                            if 'functionName' in from_info and from_info['functionName']:
                                add_function(
                                    from_info['functionName'],
                                    from_info['file_path'],
                                    from_info.get('line', 0)
                                )

                        if 'to' in step:
                            to_info = step['to']
                            if 'functionName' in to_info and to_info['functionName']:
                                add_function(
                                    to_info['functionName'],
                                    to_info['file_path'],
                                    to_info.get('line', 0)
                                )

            except (json.JSONDecodeError, KeyError, TypeError) as e:
                print(f"Warning: Could not extract functions from result item: {e}", flush=True)
                continue

        return unique_functions

    def build_cfgs_for_analysis(
        self,
        analysis_results: List,
        symbol_lookup: "SymbolLookup",
        codeql_db_path: str,
        source_path: str
    ) -> Dict[str, "Function"]:
        """
        Build CFGs for all functions appearing in analysis results.

        Args:
            analysis_results: List of analysis result items
            symbol_lookup: SymbolLookup instance
            codeql_db_path: Path to CodeQL database
            source_path: Source code path

        Returns:
            Dictionary of built CFGs
        """
        if not codeql_db_path:
            print("Warning: CodeQL database path not provided, skipping CFG building", flush=True)
            return {}

        # Extract unique functions from analysis results
        unique_functions = self.extract_functions_from_analysis_results(analysis_results, symbol_lookup)

        if not unique_functions:
            print("[+] No functions found in analysis results for CFG building", flush=True)
            return {}

        # Deduplicate by (qualified_name, file_basename)
        seen_functions = {}
        for qualified_name, file_path, start_line in unique_functions:
            file_basename = os.path.basename(file_path)
            key = (qualified_name, file_basename)
            if key not in seen_functions:
                seen_functions[key] = (qualified_name, file_path, start_line)

        functions_list = list(seen_functions.values())
        print(f"[+] Building CFGs for {len(functions_list)} unique functions from analysis results...", flush=True)

        # Pre-build CallGraph cache if available
        self._prebuild_callgraph_if_needed(codeql_db_path)

        # Build CFGs using batch method
        built_cfgs = self.build_functions_cfg_batch(
            functions_list, codeql_db_path, source_path, skip_cached=True
        )

        print(f"[+] Successfully built/cached CFGs for {len(built_cfgs)} functions", flush=True)
        cache_stats = self.get_cache_stats()
        print(f"[+] CFG Cache statistics: {cache_stats['cached_functions']} total cached functions", flush=True)

        return built_cfgs

    def _prebuild_callgraph_if_needed(self, codeql_db_path: str) -> None:
        """Pre-build CallGraph cache if available and needed."""
        try:
            from AdvancedTools.CallGraphSearch.prebuild_cache import prebuild_cache
        except ImportError:
            return

        ai_analysis_dir = os.getenv('AI_ANALYSIS_DIR', '/tmp/ai-codeql')
        callgraph_cache_path = os.path.join(ai_analysis_dir, 'cache', 'callgraph_cache.db')

        if not os.path.exists(callgraph_cache_path):
            print("[+] First-time CallGraph building detected. Pre-computing CallGraph data...", flush=True)
            try:
                start_time = time.time()
                prebuild_cache(codeql_db_path)
                elapsed = time.time() - start_time
                print(f"[+] Pre-computation complete! ({elapsed:.1f}s)", flush=True)
            except Exception as e:
                print(f"[!] Pre-computation failed (will use individual queries): {e}", flush=True)
        else:
            try:
                import sqlite3
                conn = sqlite3.connect(callgraph_cache_path)
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM callgraph_cache")
                count = cursor.fetchone()[0]
                conn.close()
                print(f"[+] CallGraph cache exists with {count} entries. Skipping pre-computation.", flush=True)
            except Exception:
                print(f"[+] CallGraph cache exists. Skipping pre-computation.", flush=True)


def build_cfg_for_function(
    function_name: str,
    file_path: str, 
    start_line: int,
    codeql_db_path: str,
    source_path: str,
    project_name: str = "default_project"
) -> Function:
    """
    Convenience function to build CFG for a single function.
    
    Args:
        function_name: Name of the function
        file_path: Path to the source file
        start_line: Starting line number of the function
        codeql_db_path: Path to the CodeQL database
        source_path: Path to the source code directory
        project_name: Project name for caching
        
    Returns:
        Function object with CFG
    """
    manager = FunctionCFGManager(project_name)
    return manager.build_function_cfg(function_name, file_path, start_line, codeql_db_path, source_path)


def build_cfgs_for_functions_list(
    functions_list: List[Tuple[str, str, int]],
    codeql_db_path: str,
    source_path: str,
    project_name: str = "default_project"
) -> Dict[str, Function]:
    """
    Convenience function to build CFGs for multiple functions.
    
    Args:
        functions_list: List of (function_name, file_path, start_line) tuples
        codeql_db_path: Path to the CodeQL database
        source_path: Path to the source code directory
        project_name: Project name for caching
        
    Returns:
        Dictionary mapping function keys to Function objects
    """
    manager = FunctionCFGManager(project_name)
    return manager.build_functions_cfg_batch(functions_list, codeql_db_path, source_path)
