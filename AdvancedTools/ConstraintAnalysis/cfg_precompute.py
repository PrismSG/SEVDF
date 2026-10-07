#!/usr/bin/env python3
"""
CFG Pre-computation - Run once to get all CFG data for the entire codebase
"""

import os
import json
import sqlite3
import subprocess
import tempfile
import csv
import yaml
from typing import Dict, List, Set, Optional
from cfg.utils import Logger
from AdvancedTools.CodeSearch.symbol_lookup import get_symbol_lookup

logger = Logger(log_level='log')


class CFGPrecomputer:
    """Pre-compute all CFG data for efficient access."""
    
    def __init__(self, codeql_path: str, codeql_db_path: str, cache_dir: str, function_csv: str = None, path_prefixes: List[str] = None):
        self.codeql_path = codeql_path
        self.codeql_db_path = codeql_db_path
        self.cache_dir = cache_dir
        self.path_prefixes = path_prefixes or []
        
        # Ensure cache directory exists
        os.makedirs(cache_dir, exist_ok=True)
        
        # SQLite database for storing pre-computed data
        self.db_path = os.path.join(cache_dir, "cfg_precomputed.db")
        
        # Function CSV file path
        self.function_csv = function_csv or self._find_function_csv()
        
        # Load source location prefix from CodeQL database
        self.source_location_prefix = self._get_source_location_prefix()
        
    def _find_function_csv(self) -> str:
        """Try to find the function CSV file using SymbolLookup discovery mechanism."""
        lookup = get_symbol_lookup()
        csv_path = lookup._find_csv_file('*_functionlist.csv')
        if csv_path:
            return csv_path
        return None
        
    def _get_source_location_prefix(self) -> Optional[str]:
        """Get source location prefix from CodeQL database configuration."""
        if not self.codeql_db_path:
            return None
            
        db_config_path = os.path.join(self.codeql_db_path, 'codeql-database.yml')
        if not os.path.exists(db_config_path):
            print(f"[Pre-compute] Warning: CodeQL database config not found: {db_config_path}", flush=True)
            return None
            
        try:
            with open(db_config_path, 'r') as f:
                db_config = yaml.safe_load(f)
                source_prefix = db_config.get('sourceLocationPrefix')
                if source_prefix:
                    print(f"[Pre-compute] Found source location prefix: {source_prefix}", flush=True)
                    return source_prefix
        except Exception as e:
            print(f"[Pre-compute] Warning: Failed to read database config: {e}", flush=True)
            
        return None
        
    def _normalize_file_path(self, file_path: str) -> str:
        """Clean up file path - just handle file: prefix and return as-is."""
        # Handle file: prefix
        if file_path.startswith('file:'):
            file_path = file_path[5:]
            if file_path and file_path[0] != '/':
                file_path = '/' + file_path
        
        # Just return the path as-is
        return file_path
        
    def precompute_all(self):
        """Run three separate queries and store results in SQLite."""
        print("[Pre-compute] Starting CFG data pre-computation from CodeQL database...", flush=True)
        
        queries_dir = os.path.join(os.path.dirname(__file__), "queries")
        
        # Run queries for complete data
        queries = []
        
        # Always run these queries
        queries = [
            ("all_basic_blocks.ql", self._store_basic_blocks),
            ("all_bb_edges.ql", self._store_edges),
            ("all_conditions.ql", self._store_conditions),
            ("all_loops_exact.ql", self._store_loops)  # Using exact loop detection - one per source loop
        ]
        
        # Check if we should use Function CSV instead of all_functions.ql
        use_function_csv = self.function_csv and os.path.exists(self.function_csv)
        if use_function_csv:
            print(f"[Pre-compute] Using Function CSV file: {self.function_csv}", flush=True)
            print("[Pre-compute] Skipping all_functions.ql query", flush=True)
        else:
            print("[Pre-compute] Function CSV not found, will query all_functions.ql", flush=True)
            # Add all_functions.ql query at the beginning
            queries.insert(0, ("all_functions.ql", self._store_functions))
        
        # Initialize database
        print("[Pre-compute] Initializing SQLite database...", flush=True)
        self._init_database()
        
        # If using Function CSV, load functions from it first
        if use_function_csv:
            self._store_functions_from_csv()
        
        for i, (query_name, store_func) in enumerate(queries, 1):
            query_path = os.path.join(queries_dir, query_name)
            
            with tempfile.NamedTemporaryFile(suffix='.bqrs', delete=False) as tmp_output:
                output_path = tmp_output.name
                
            try:
                # Execute CodeQL query
                cmd = [
                    self.codeql_path,
                    'query', 'run',
                    query_path,
                    '--database', self.codeql_db_path,
                    '--output', output_path,
                    '--threads', '0'
                ]
                
                print(f"[Pre-compute] ({i}/{len(queries)}) Running query: {query_name}", flush=True)
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode != 0:
                    print(f"[Pre-compute] Query failed: {result.stderr}", flush=True)
                    return False
                    
                # Store results
                store_func(output_path)
                
            finally:
                if os.path.exists(output_path):
                    os.remove(output_path)
        
        # Get database size
        db_size = os.path.getsize(self.db_path) / (1024 * 1024)  # MB
        print(f"[Pre-compute] ✓ Pre-computation complete!", flush=True)
        print(f"[Pre-compute]   Database size: {db_size:.1f}MB", flush=True)
        print(f"[Pre-compute]   Database location: {self.db_path}", flush=True)
        return True
                
    def _init_database(self):
        """Initialize SQLite database with tables."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Drop existing tables to ensure fresh data
        cursor.execute('DROP TABLE IF EXISTS functions')
        cursor.execute('DROP TABLE IF EXISTS basic_blocks')
        cursor.execute('DROP TABLE IF EXISTS bb_edges')
        cursor.execute('DROP TABLE IF EXISTS conditions')
        cursor.execute('DROP TABLE IF EXISTS loops')
        
        # Create tables
        cursor.execute('''
            CREATE TABLE functions (
                qualified_name TEXT PRIMARY KEY,
                file_path TEXT,
                start_line INTEGER,
                end_line INTEGER,
                function_id TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE basic_blocks (
                function_qualified_name TEXT,
                file_path TEXT,
                bb_id TEXT,
                is_entry BOOLEAN,
                is_exit BOOLEAN,
                PRIMARY KEY (function_qualified_name, bb_id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE bb_edges (
                function_qualified_name TEXT,
                from_bb_id TEXT,
                to_bb_id TEXT,
                edge_type TEXT,
                PRIMARY KEY (function_qualified_name, from_bb_id, to_bb_id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE conditions (
                function_qualified_name TEXT,
                file_path TEXT,
                bb_id TEXT,
                true_bb_id TEXT,
                false_bb_id TEXT,
                PRIMARY KEY (function_qualified_name, bb_id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE loops (
                function_qualified_name TEXT,
                loop_start_bb_id TEXT,
                loop_exit_bb_id TEXT,
                loop_back_bb_id TEXT,
                PRIMARY KEY (function_qualified_name, loop_start_bb_id)
            )
        ''')
        
        # Create indexes
        cursor.execute('CREATE INDEX idx_func_name ON functions(qualified_name)')
        cursor.execute('CREATE INDEX idx_bb_func ON basic_blocks(function_qualified_name)')
        cursor.execute('CREATE INDEX idx_edge_func ON bb_edges(function_qualified_name)')
        cursor.execute('CREATE INDEX idx_cond_func ON conditions(function_qualified_name)')
        cursor.execute('CREATE INDEX idx_loop_func ON loops(function_qualified_name)')
        
        conn.commit()
        conn.close()
        
    def _store_functions_from_csv(self):
        """Store function data from Function CSV file."""
        if not self.function_csv or not os.path.exists(self.function_csv):
            print("[Pre-compute] Warning: Function CSV file not found", flush=True)
            return

        print(f"[Pre-compute] Loading functions from CSV: {self.function_csv}", flush=True)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        count = 0
        with open(self.function_csv, 'r') as f:
            reader = csv.reader(f)
            # Skip header if present
            first_row = next(reader, None)
            # Try to determine if first row is header by checking if we can parse line numbers
            is_header = False
            # Detect format: 5-column (new) vs 4-column (old)
            is_new_format = first_row and len(first_row) >= 5
            line_col_idx = 3 if is_new_format else 2  # start_line column index

            if first_row and len(first_row) >= 4:
                try:
                    int(first_row[line_col_idx])
                    int(first_row[line_col_idx + 1])
                except (ValueError, IndexError):
                    is_header = True

            def process_row(row):
                """Process a row and return (qualified_name, file_path, start_line, end_line) or None."""
                # New 5-column format: name, qualifiedName, file_path, start_line, end_line
                if len(row) < 5:
                    return None
                qualified_name = row[1]  # Use qualifiedName (2nd column)
                file_path = self._normalize_file_path(row[2])
                start_line = int(row[3])
                end_line = int(row[4])
                return (qualified_name, file_path, start_line, end_line)

            if not is_header and first_row:
                try:
                    result = process_row(first_row)
                    if result:
                        qualified_name, file_path, start_line, end_line = result
                        function_id = f"{start_line}.1_{end_line}.1"
                        cursor.execute(
                            'INSERT OR REPLACE INTO functions VALUES (?, ?, ?, ?, ?)',
                            (qualified_name, file_path, start_line, end_line, function_id)
                        )
                        count += 1
                except ValueError as e:
                    print(f"[Pre-compute] Warning: Skipping invalid first row: {first_row} - {e}", flush=True)

            # Process remaining rows
            for row in reader:
                try:
                    result = process_row(row)
                    if result:
                        qualified_name, file_path, start_line, end_line = result
                        function_id = f"{start_line}.1_{end_line}.1"
                        cursor.execute(
                            'INSERT OR REPLACE INTO functions VALUES (?, ?, ?, ?, ?)',
                            (qualified_name, file_path, start_line, end_line, function_id)
                        )
                        count += 1
                except ValueError as e:
                    print(f"[Pre-compute] Warning: Skipping invalid row: {row} - {e}", flush=True)

        conn.commit()
        conn.close()
        print(f"[Pre-compute]   Stored {count} functions from CSV", flush=True)
        
    def _store_functions(self, bqrs_path: str):
        """Store function data from all_functions.ql results."""
        csv_path = bqrs_path + '.csv'
        
        cmd = [
            self.codeql_path,
            'bqrs', 'decode',
            '--format=csv',
            '--output', csv_path,
            bqrs_path
        ]
        
        subprocess.run(cmd, check=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        count = 0
        with open(csv_path, 'r') as f:
            reader = csv.reader(f)
            next(reader, None)  # Skip header
            
            for row in reader:
                if len(row) >= 5:
                    cursor.execute(
                        'INSERT OR REPLACE INTO functions VALUES (?, ?, ?, ?, ?)',
                        (row[0], row[1], int(row[2]), int(row[3]), row[4])
                    )
                    count += 1
                    
        conn.commit()
        conn.close()
        os.remove(csv_path)
        print(f"[Pre-compute]   Stored {count} functions", flush=True)
        
    def _store_basic_blocks(self, bqrs_path: str):
        """Store basic block data from all_basic_blocks.ql results."""
        csv_path = bqrs_path + '.csv'
        
        cmd = [
            self.codeql_path,
            'bqrs', 'decode',
            '--format=csv',
            '--output', csv_path,
            bqrs_path
        ]
        
        subprocess.run(cmd, check=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        count = 0
        func_blocks = {}  # Track blocks per function
        reversed_blocks = []  # Track blocks with reversed line numbers
        
        with open(csv_path, 'r') as f:
            reader = csv.reader(f)
            next(reader, None)  # Skip header
            
            for row in reader:
                if len(row) >= 5:  # Now expecting 5 fields
                    func_name = row[0]
                    file_path = row[1]
                    bb_id = row[2]
                    is_entry = row[3].lower() == 'true'
                    is_exit = row[4].lower() == 'true'
                    
                    # Track blocks per function
                    if func_name not in func_blocks:
                        func_blocks[func_name] = []
                    func_blocks[func_name].append((bb_id, is_entry, is_exit))
                    
                    # Check for reversed line numbers
                    try:
                        start_part, end_part = bb_id.split('_')
                        start_line = int(start_part.split('.')[0])
                        end_line = int(end_part.split('.')[0])
                        if start_line > end_line:
                            reversed_blocks.append((func_name, bb_id, start_line, end_line))
                    except:
                        pass
                    
                    cursor.execute(
                        'INSERT OR REPLACE INTO basic_blocks VALUES (?, ?, ?, ?, ?)',
                        (func_name, file_path, bb_id, is_entry, is_exit)
                    )
                    count += 1
        
        # Log interesting patterns
        print(f"\n[Pre-compute] Basic Block Analysis:", flush=True)
        print(f"  Total blocks: {count}", flush=True)
        print(f"  Functions: {len(func_blocks)}", flush=True)
        
        # Show functions with unusual patterns
        single_block_funcs = [f for f, blocks in func_blocks.items() if len(blocks) == 1]
        if single_block_funcs:
            print(f"\n  Functions with single block ({len(single_block_funcs)} total):", flush=True)
            for func in single_block_funcs[:5]:
                blocks = func_blocks[func]
                print(f"    - {func}: {blocks[0][0]} (entry={blocks[0][1]}, exit={blocks[0][2]})", flush=True)
            if len(single_block_funcs) > 5:
                print(f"    ... and {len(single_block_funcs) - 5} more", flush=True)
        
        # Show make_size functions specifically
        make_size_funcs = [f for f in func_blocks if 'make_size' in f]
        if make_size_funcs:
            print(f"\n  make_size functions:", flush=True)
            for func in sorted(make_size_funcs):
                blocks = func_blocks[func]
                print(f"    - {func}: {len(blocks)} blocks", flush=True)
                for i, (bb_id, is_entry, is_exit) in enumerate(blocks[:3]):
                    print(f"        Block {i+1}: {bb_id} (entry={is_entry}, exit={is_exit})", flush=True)
                if len(blocks) > 3:
                    print(f"        ... and {len(blocks) - 3} more blocks", flush=True)
        
        # Show reversed blocks
        if reversed_blocks:
            print(f"\n  Blocks with reversed line order ({len(reversed_blocks)} total):", flush=True)
            for func, bb_id, start, end in reversed_blocks[:5]:
                print(f"    - {func}: {bb_id} (start line {start} > end line {end})", flush=True)
            if len(reversed_blocks) > 5:
                print(f"    ... and {len(reversed_blocks) - 5} more", flush=True)
                    
        conn.commit()
        conn.close()
        os.remove(csv_path)
        print(f"\n[Pre-compute]   Stored {count} basic blocks total", flush=True)
        
    def _store_edges(self, bqrs_path: str):
        """Store edge data from all_bb_edges.ql results."""
        csv_path = bqrs_path + '.csv'
        
        cmd = [
            self.codeql_path,
            'bqrs', 'decode',
            '--format=csv',
            '--output', csv_path,
            bqrs_path
        ]
        
        subprocess.run(cmd, check=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        count = 0
        with open(csv_path, 'r') as f:
            reader = csv.reader(f)
            next(reader, None)  # Skip header
            
            for row in reader:
                if len(row) >= 4:
                    cursor.execute(
                        'INSERT OR REPLACE INTO bb_edges VALUES (?, ?, ?, ?)',
                        (row[0], row[1], row[2], row[3])
                    )
                    count += 1
                    
        conn.commit()
        conn.close()
        os.remove(csv_path)
        print(f"[Pre-compute]   Stored {count} edges", flush=True)
        
    def _store_conditions(self, bqrs_path: str):
        """Store condition data from all_conditions.ql results."""
        csv_path = bqrs_path + '.csv'
        
        cmd = [
            self.codeql_path,
            'bqrs', 'decode',
            '--format=csv',
            '--output', csv_path,
            bqrs_path
        ]
        
        subprocess.run(cmd, check=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        count = 0
        with open(csv_path, 'r') as f:
            reader = csv.reader(f)
            next(reader, None)  # Skip header
            
            for row in reader:
                if len(row) >= 5:
                    cursor.execute(
                        'INSERT OR REPLACE INTO conditions VALUES (?, ?, ?, ?, ?)',
                        (row[0], row[1], row[2], row[3], row[4])
                    )
                    count += 1
                    
        conn.commit()
        conn.close()
        os.remove(csv_path)
        print(f"[Pre-compute]   Stored {count} conditions", flush=True)
        
    def _store_loops(self, bqrs_path: str):
        """Store loop data from all_loops.ql results."""
        csv_path = bqrs_path + '.csv'
        
        cmd = [
            self.codeql_path,
            'bqrs', 'decode',
            '--format=csv',
            '--output', csv_path,
            bqrs_path
        ]
        
        subprocess.run(cmd, check=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        count = 0
        loop_examples = []
        
        with open(csv_path, 'r') as f:
            reader = csv.reader(f)
            next(reader, None)  # Skip header
            
            for row in reader:
                if len(row) >= 5:
                    func_name = row[0]
                    loop_id = row[1]  # Now includes loop identifier
                    loop_header = row[2]
                    loop_exit = row[3]
                    back_edge_source = row[4]
                    
                    cursor.execute(
                        'INSERT OR REPLACE INTO loops VALUES (?, ?, ?, ?)',
                        (func_name, loop_header, loop_exit, back_edge_source)
                    )
                    count += 1
                    
                    # Collect examples for logging
                    if len(loop_examples) < 5:
                        # Parse line numbers from block IDs
                        def get_lines(block_id):
                            try:
                                start_part, end_part = block_id.split('_')
                                start_line = start_part.split('.')[0]
                                end_line = end_part.split('.')[0]
                                return f"L{start_line}-{end_line}"
                            except:
                                return block_id
                        
                        # Check if this is a single-block do-while loop
                        is_single_block = (loop_header == back_edge_source and 
                                         loop_header.split('.')[0] == back_edge_source.split('_')[1].split('.')[0])
                        
                        loop_examples.append({
                            'func': func_name,
                            'loop_id': loop_id,
                            'header': get_lines(loop_header),
                            'exit': get_lines(loop_exit),
                            'back_edge': get_lines(back_edge_source),
                            'single_block': is_single_block
                        })
        
        # Log loop analysis
        print(f"\n[Pre-compute] Loop Analysis:", flush=True)
        print(f"  Total loops detected: {count}", flush=True)
        
        if loop_examples:
            print(f"\n  Example loops:", flush=True)
            for i, loop in enumerate(loop_examples, 1):
                loop_type = "single-block do-while" if loop.get('single_block', False) else "regular"
                print(f"    Loop {i} in {loop['func']} - {loop.get('loop_id', 'Unknown')} ({loop_type}):", flush=True)
                print(f"      Header: {loop['header']}", flush=True)
                print(f"      Exit: {loop['exit']}", flush=True)
                print(f"      Back edge from: {loop['back_edge']}", flush=True)
                    
        conn.commit()
        conn.close()
        os.remove(csv_path)
        print(f"\n[Pre-compute]   Stored {count} loops total", flush=True)
        
    def _old_store_results_in_db(self, bqrs_path: str):
        """Parse BQRS results and store in SQLite database."""
        # First decode BQRS to CSV for easier parsing
        csv_path = bqrs_path + '.csv'
        
        cmd = [
            self.codeql_path,
            'bqrs', 'decode',
            '--format=csv',
            '--output', csv_path,
            bqrs_path
        ]
        
        subprocess.run(cmd, check=True)
        
        # Create SQLite tables and store data
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS functions (
                qualified_name TEXT PRIMARY KEY,
                file_path TEXT,
                start_line INTEGER,
                end_line INTEGER
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS basic_blocks (
                function_qualified_name TEXT,
                bb_id TEXT,
                is_entry BOOLEAN,
                is_exit BOOLEAN,
                PRIMARY KEY (function_qualified_name, bb_id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS bb_edges (
                function_qualified_name TEXT,
                from_bb_id TEXT,
                to_bb_id TEXT,
                edge_type TEXT,
                PRIMARY KEY (function_qualified_name, from_bb_id, to_bb_id)
            )
        ''')
        
        # Create indexes for faster lookup
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_func_name ON functions(qualified_name)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_bb_func ON basic_blocks(function_qualified_name)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_edge_func ON bb_edges(function_qualified_name)')
        
        # Parse CSV results
        import csv
        functions_seen = set()
        blocks_seen = set()
        edge_count = 0
        
        with open(csv_path, 'r') as f:
            reader = csv.reader(f)
            # Skip header if present
            next(reader, None)
            
            for row in reader:
                if len(row) >= 9:
                    func_name = row[0]
                    file_path = row[1]
                    func_start = int(row[2])
                    func_end = int(row[3])
                    bb_id = row[4]
                    is_entry = row[5].lower() == 'true'
                    is_exit = row[6].lower() == 'true'
                    succ_id = row[7]
                    is_true_branch = row[8].lower() == 'true'
                    
                    # Determine edge type
                    if is_true_branch:
                        edge_type = "TRUE"
                    else:
                        edge_type = "FALSE"
                    
                    # Store function info
                    if func_name not in functions_seen:
                        cursor.execute(
                            'INSERT OR REPLACE INTO functions VALUES (?, ?, ?, ?)',
                            (func_name, file_path, func_start, func_end)
                        )
                        functions_seen.add(func_name)
                    
                    # Store basic block info
                    block_key = (func_name, bb_id)
                    if block_key not in blocks_seen:
                        cursor.execute(
                            'INSERT OR REPLACE INTO basic_blocks VALUES (?, ?, ?, ?)',
                            (func_name, bb_id, is_entry, is_exit)
                        )
                        blocks_seen.add(block_key)
                    
                    # Store edge info
                    cursor.execute(
                        'INSERT OR REPLACE INTO bb_edges VALUES (?, ?, ?, ?)',
                        (func_name, bb_id, succ_id, edge_type)
                    )
                    edge_count += 1
        
        conn.commit()
        conn.close()
        
        # Clean up CSV file
        os.remove(csv_path)
        
        print(f"Stored {len(functions_seen)} functions", flush=True)
        print(f"Stored {len(blocks_seen)} basic blocks", flush=True)
        print(f"Stored {edge_count} edges", flush=True)
        print(f"Pre-computed CFG data stored in {self.db_path}", flush=True)
        

class PrecomputedCFGDatabase:
    """Access pre-computed CFG data from SQLite."""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        if not os.path.exists(db_path):
            raise FileNotFoundError(f"Pre-computed database not found: {db_path}")
            
    def get_function_info(self, function_name: str, file_path: str = None):
        """Get function information from pre-computed data."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # First try exact match
        if file_path:
            cursor.execute(
                'SELECT * FROM functions WHERE qualified_name = ? AND file_path LIKE ?',
                (function_name, f'%{os.path.basename(file_path)}%')
            )
        else:
            cursor.execute(
                'SELECT * FROM functions WHERE qualified_name = ?',
                (function_name,)
            )
            
        results = cursor.fetchall()
        
        # If no exact match found, try with LIKE but prioritize exact matches
        if not results:
            if file_path:
                cursor.execute(
                    'SELECT * FROM functions WHERE qualified_name LIKE ? AND file_path LIKE ? ORDER BY LENGTH(qualified_name), qualified_name',
                    (f'%{function_name}%', f'%{os.path.basename(file_path)}%')
                )
            else:
                cursor.execute(
                    'SELECT * FROM functions WHERE qualified_name LIKE ? ORDER BY LENGTH(qualified_name), qualified_name',
                    (f'%{function_name}%',)
                )
            
            results = cursor.fetchall()
            
            # Filter to prefer exact matches or shortest matches
            if results:
                # If we have an exact match in the results, use only that
                exact_matches = [r for r in results if r[0] == function_name]
                if exact_matches:
                    results = exact_matches
                else:
                    # Otherwise, take the shortest match (to avoid make_transform_images when looking for make_transform_image)
                    shortest_len = min(len(r[0]) for r in results)
                    results = [r for r in results if len(r[0]) == shortest_len]
        
        conn.close()
        return results
        
    def get_function_cfg_data(self, qualified_name: str):
        """Get all CFG data for a function."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get basic blocks
        cursor.execute(
            'SELECT * FROM basic_blocks WHERE function_qualified_name = ?',
            (qualified_name,)
        )
        basic_blocks = cursor.fetchall()
        
        # Get edges
        cursor.execute(
            'SELECT * FROM bb_edges WHERE function_qualified_name = ?',
            (qualified_name,)
        )
        edges = cursor.fetchall()
        
        conn.close()
        
        return {
            'basic_blocks': basic_blocks,
            'edges': edges
        }


if __name__ == "__main__":
    # Command-line entry point
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python cfg_precompute.py <codeql_path> <codeql_db_path> [cache_dir]", flush=True)
        sys.exit(1)
        
    codeql_path = sys.argv[1]
    codeql_db_path = sys.argv[2]
    cache_dir = sys.argv[3] if len(sys.argv) > 3 else "./cfg_cache"
    
    precomputer = CFGPrecomputer(codeql_path, codeql_db_path, cache_dir)
    if precomputer.precompute_all():
        print("Pre-computation complete!", flush=True)
