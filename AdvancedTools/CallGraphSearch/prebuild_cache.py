#!/usr/bin/env python3
"""
Pre-populate the existing CallGraph SQLite cache with all function calls
"""

import os
import sys
import subprocess
import tempfile
import logging
import time

# Use the same cache implementation as Scanner-Union's call analysis.
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'LLMFrontend2'))
from Scanner_Union._01_path_decomposition.call_type_analysis.subpath_type_config import (
    init_cache_db, cache_result, get_cache_stats, CALLGRAPH_CACHE_PATH
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def query_all_calls(codeql_db_path):
    """Query all function calls in the database."""
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Create query to find all function calls
        # Aligned with call_graph_pt.ql constraints
        query_content = """
import cpp
import semmle.code.cpp.pointsto.CallGraph

from Call call, Function caller, Function callee, File callerFile, File calleeFile
where 
  call.getTarget() = callee and
  call.getEnclosingFunction() = caller and
  caller.getFile() = callerFile and
  callee.getFile() = calleeFile
select 
  caller.getName() as caller_name,
  callerFile.getAbsolutePath() as caller_file,
  callee.getName() as callee_name,
  calleeFile.getAbsolutePath() as callee_file,
  call.getLocation().getStartLine() as call_line
"""
        
        query_path = os.path.join(temp_dir, "all_calls.ql")
        with open(query_path, 'w') as f:
            f.write(query_content)
        
        logger.debug(f"Query content:\n{query_content}")
        
        # Create qlpack.yml
        qlpack_content = """name: callgraph-prebuild
version: 1.0.0
dependencies:
  codeql/cpp-all: "*"
"""
        qlpack_path = os.path.join(temp_dir, "qlpack.yml")
        with open(qlpack_path, 'w') as f:
            f.write(qlpack_content)
        
        # Run query
        bqrs_output = os.path.join(temp_dir, "results.bqrs")
        csv_output = os.path.join(temp_dir, "results.csv")
        
        logger.info(f"Querying all function calls in {codeql_db_path}...")
        logger.info(f"Using query: {query_path}")
        
        # Run with increased result limit
        result = subprocess.run([
            "codeql", "query", "run",
            "--database", codeql_db_path,
            "--output", bqrs_output,
            "--max-disk-cache", "4096",  # Increase cache for large results
            query_path
        ], capture_output=True, text=True)
        
        if result.returncode != 0:
            logger.error(f"Query failed with return code {result.returncode}")
            logger.error(f"Query stdout: {result.stdout}")
            logger.error(f"Query stderr: {result.stderr}")
            raise subprocess.CalledProcessError(result.returncode, result.args, result.stdout, result.stderr)
        
        if result.stdout:
            logger.debug(f"Query stdout: {result.stdout}")
        if result.stderr:
            logger.debug(f"Query stderr: {result.stderr}")
        
        subprocess.run([
            "codeql", "bqrs", "decode",
            "--format=csv",
            "--output", csv_output,
            bqrs_output
        ], check=True, capture_output=True)
        
        # Parse results using proper CSV parsing
        calls = []
        import csv
        with open(csv_output, 'r') as f:
            reader = csv.reader(f)
            # Skip header if present
            header = next(reader, None)
            
            for row in reader:
                if len(row) >= 5:
                    caller_name = row[0]
                    caller_file = row[1]
                    callee_name = row[2]
                    callee_file = row[3]
                    call_line = int(row[4])
                    
                    calls.append({
                        'caller_name': caller_name,
                        'caller_file': caller_file,
                        'callee_name': callee_name,
                        'callee_file': callee_file,
                        'call_line': call_line
                    })
        
        logger.info(f"Parsed {len(calls)} calls from CSV")
        return calls
        
    finally:
        import shutil
        shutil.rmtree(temp_dir)


def prebuild_cache(codeql_db_path):
    """Pre-populate the cache with all function calls."""
    # Initialize cache DB
    init_cache_db()
    
    # Get initial stats
    initial_stats = get_cache_stats()
    logger.info(f"Initial cache entries: {initial_stats['total_entries']}")
    
    # Query all calls
    calls = query_all_calls(codeql_db_path)
    logger.info(f"Found {len(calls)} function calls")
    
    # Log statistics about the calls
    system_header_calls = [c for c in calls if c['caller_file'].startswith('/') or c['callee_file'].startswith('/')]
    logger.info(f"System header related calls: {len(system_header_calls)}")
    
    if system_header_calls:
        logger.info("Sample system header calls:")
        for call in system_header_calls[:3]:
            logger.info(f"  {call['caller_name']} ({call['caller_file']}) → {call['callee_name']} ({call['callee_file']})")
    
    # Populate cache using batch insert
    start_time = time.time()
    
    # Direct database connection for batch insert
    import sqlite3
    
    # Use the cache path from Scanner-Union's config.
    cache_dir = os.path.dirname(CALLGRAPH_CACHE_PATH)
    if not os.path.exists(cache_dir):
        os.makedirs(cache_dir)
    
    conn = sqlite3.connect(CALLGRAPH_CACHE_PATH)
    cursor = conn.cursor()
    
    # Match the hashes used by Scanner-Union's cache lookups.
    from Scanner_Union._01_path_decomposition.call_type_analysis.subpath_type_config import create_query_hash
    import json
    
    # Prepare batch data
    batch_data = []
    for call in calls:
        # Generate query_hash using the same logic as the cache functions
        query_hash = create_query_hash(
            to_function_name=call['caller_name'],
            to_line=call['call_line'],
            to_file=call['caller_file'],
            from_function_name=call['callee_name'],
            from_file=call['callee_file'],
            codeql_db_path=codeql_db_path
        )
        
        # Create query_params JSON string for debugging/inspection
        # Always use basename to match cache format
        def normalize_path(path):
            if not path:
                return ''
            return os.path.basename(path)
            
        query_params = json.dumps({
            'to_function_name': call['caller_name'],
            'to_line': call['call_line'],
            'to_file': normalize_path(call['caller_file']),
            'from_function_name': call['callee_name'],
            'from_file': normalize_path(call['callee_file'])
        }, sort_keys=True)
        
        batch_data.append((
            query_hash,
            codeql_db_path,
            query_params,
            True  # result (all entries from the query are True)
        ))
    
    # Batch insert with transaction
    try:
        cursor.executemany("""
            INSERT OR REPLACE INTO callgraph_cache 
            (query_hash, codeql_db_path, query_params, result)
            VALUES (?, ?, ?, ?)
        """, batch_data)
        conn.commit()
        logger.info(f"Batch inserted {len(batch_data)} entries")
    except Exception as e:
        logger.error(f"Batch insert failed: {e}")
        conn.rollback()
    finally:
        conn.close()
    
    elapsed = time.time() - start_time
    
    # Get final stats
    final_stats = get_cache_stats()
    logger.info(f"\nCache pre-build complete!")
    logger.info(f"Time taken: {elapsed:.2f} seconds")
    logger.info(f"New entries added: {final_stats['total_entries'] - initial_stats['total_entries']}")
    logger.info(f"Total cache entries: {final_stats['total_entries']}")
    
    # Log some sample entries for debugging
    if len(batch_data) > 0:
        logger.info(f"\nSample cached entries (first 3):")
        for i, (query_hash, db_path, query_params, result) in enumerate(batch_data[:3]):
            logger.info(f"  Entry {i+1}:")
            logger.info(f"    Query hash: {query_hash}")
            logger.info(f"    Query params: {query_params}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python prebuild_callgraph_cache_simple.py <codeql_db_path>")
        sys.exit(1)
    
    codeql_db_path = sys.argv[1]
    if not os.path.exists(codeql_db_path):
        print(f"Error: CodeQL database not found: {codeql_db_path}")
        sys.exit(1)
    
    prebuild_cache(codeql_db_path)


if __name__ == "__main__":
    main()
