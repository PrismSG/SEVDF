from BaseMachine.state_machine import StateMachine
from BaseMachine.action_utils import create_chat_action, create_new_chat_action
from BaseMachine.model_config import get_model_name
import re
import os
import sqlite3
import hashlib
import json
import logging

from .subpath_type_context import Call

# Global variable to control analysis mode
ANALYSIS_MODE = "static"  # Set to "static" for CodeQL mode, "llm" for LLM mode
# Use AI_ANALYSIS_DIR if available, otherwise fall back to /tmp
AI_ANALYSIS_DIR = os.environ.get('AI_ANALYSIS_DIR', '/tmp/ai-codeql')
CALLGRAPH_CACHE_PATH = os.path.join(AI_ANALYSIS_DIR, 'cache', 'callgraph_cache.db')

# Cache statistics tracking
_cache_stats = {'hits': 0, 'misses': 0, 'last_report': 0}

def init_cache_db():
    """
    Initialize the CallGraph cache database.
    Creates the table if it doesn't exist.
    """
    # Ensure cache directory exists
    cache_dir = os.path.dirname(CALLGRAPH_CACHE_PATH)
    if not os.path.exists(cache_dir):
        os.makedirs(cache_dir, exist_ok=True)
    
    try:
        conn = sqlite3.connect(CALLGRAPH_CACHE_PATH)
        cursor = conn.cursor()
        
        # Create cache table if it doesn't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS callgraph_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                codeql_db_path TEXT NOT NULL,
                query_hash TEXT NOT NULL,
                query_params TEXT NOT NULL,
                result BOOLEAN NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(query_hash)
            )
        ''')
        
        # Create index for faster lookups
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_query_hash ON callgraph_cache(query_hash)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_codeql_db_path ON callgraph_cache(codeql_db_path)
        ''')
        
        conn.commit()
        conn.close()
        
    except Exception as e:
        logging.error(f"Error initializing cache database: {e}")

def create_query_hash(to_function_name, to_line, to_file, from_function_name, from_file, codeql_db_path):
    """
    Create a unique hash for the query parameters.
    
    Args:
        to_function_name: Function name that contains the calling line
        to_line: Line number that should contain the call
        to_file: File containing the to_function
        from_function_name: Function name being called
        from_file: File containing the from_function
        codeql_db_path: Path to CodeQL database (not used in hash)
        
    Returns:
        str: SHA256 hash of the query parameters
    """
    # Create a normalized representation of the query parameters
    # Always use basename to match prebuild cache format
    def normalize_path(path):
        if not path:
            return ''
        # Always use just the filename for consistent matching
        return os.path.basename(path)
    
    query_data = {
        'to_function_name': to_function_name,
        'to_line': to_line,
        'to_file': normalize_path(to_file),
        'from_function_name': from_function_name,
        'from_file': normalize_path(from_file),
    }
    
    # Convert to JSON string with sorted keys for consistent hashing
    query_string = json.dumps(query_data, sort_keys=True)
    
    # Create SHA256 hash
    return hashlib.sha256(query_string.encode('utf-8')).hexdigest()

def get_cached_result(to_function_name, to_line, to_file, from_function_name, from_file, codeql_db_path):
    """
    Retrieve cached result for the given query parameters.
    A missing record leaves the call relationship unknown and requires a query.
    
    Returns:
        bool or None: Cached result if found, None if not in cache
    """
    try:
        # Look up whether A calls B at the specified line.
        query_hash = create_query_hash(to_function_name, to_line, to_file, from_function_name, from_file, codeql_db_path)
        
        conn = sqlite3.connect(CALLGRAPH_CACHE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT result FROM callgraph_cache WHERE query_hash = ?
        ''', (query_hash,))
        
        result = cursor.fetchone()
        
        if result:
            conn.close()
            logging.debug(f"Cache hit (direct) for query: {to_function_name}:{to_line} -> {from_function_name}")
            _cache_stats['hits'] += 1
            _report_cache_stats()
            return bool(result[0])
        
        conn.close()
        
        # A missing record may indicate an empty or partially populated cache.
        logging.debug(f"Cache miss for query: {to_function_name}:{to_line} -> {from_function_name}")
        _cache_stats['misses'] += 1
        _report_cache_stats()
        return None
            
    except Exception as e:
        logging.error(f"Error retrieving cached result: {e}")
        return None

def cache_result(to_function_name, to_line, to_file, from_function_name, from_file, codeql_db_path, result):
    """
    Cache the result for the given query parameters.
    
    Args:
        to_function_name: Function name that contains the calling line
        to_line: Line number that should contain the call
        to_file: File containing the to_function
        from_function_name: Function name being called
        from_file: File containing the from_function
        codeql_db_path: Path to CodeQL database
        result: Boolean result to cache
    """
    try:
        query_hash = create_query_hash(to_function_name, to_line, to_file, from_function_name, from_file, codeql_db_path)
        
        # Store query parameters as JSON for debugging/inspection purposes
        # Always use basename to match prebuild cache format
        def normalize_path(path):
            if not path:
                return ''
            return os.path.basename(path)
            
        query_params = json.dumps({
            'to_function_name': to_function_name,
            'to_line': to_line,
            'to_file': normalize_path(to_file),
            'from_function_name': from_function_name,
            'from_file': normalize_path(from_file)
        }, sort_keys=True)
        
        conn = sqlite3.connect(CALLGRAPH_CACHE_PATH)
        cursor = conn.cursor()
        
        # Use INSERT OR REPLACE to handle duplicates
        cursor.execute('''
            INSERT OR REPLACE INTO callgraph_cache 
            (query_hash, codeql_db_path, query_params, result)
            VALUES (?, ?, ?, ?)
        ''', (query_hash, codeql_db_path, query_params, result))
        
        conn.commit()
        conn.close()
        
        logging.debug(f"Cached result for query: {to_function_name}:{to_line} -> {from_function_name} = {result}")
        
    except Exception as e:
        logging.error(f"Error caching result: {e}")

def clear_cache_for_database(codeql_db_path):
    """
    Clear all cached results for a specific CodeQL database.
    
    Args:
        codeql_db_path: Path to the CodeQL database to clear cache for
    """
    try:
        conn = sqlite3.connect(CALLGRAPH_CACHE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            DELETE FROM callgraph_cache WHERE codeql_db_path = ?
        ''', (codeql_db_path,))
        
        deleted_count = cursor.rowcount
        conn.commit()
        conn.close()
        
        logging.debug(f"Cleared {deleted_count} cached entries for database: {codeql_db_path}")
        
    except Exception as e:
        logging.error(f"Error clearing cache for database {codeql_db_path}: {e}")

def _report_cache_stats():
    """Report cache statistics every 100 queries"""
    global _cache_stats
    total_queries = _cache_stats['hits'] + _cache_stats['misses']
    
    if total_queries > 0 and total_queries % 100 == 0:
        hit_rate = _cache_stats['hits'] / total_queries * 100
        logging.info(f"[CallGraph Cache Stats] Total queries: {total_queries}, Hits: {_cache_stats['hits']}, Misses: {_cache_stats['misses']}, Hit rate: {hit_rate:.1f}%")

def get_cache_stats():
    """
    Get statistics about the cache.
    
    Returns:
        dict: Cache statistics including total entries, entries per project, etc.
    """
    try:
        conn = sqlite3.connect(CALLGRAPH_CACHE_PATH)
        cursor = conn.cursor()
        
        # Total entries
        cursor.execute('SELECT COUNT(*) FROM callgraph_cache')
        total_entries = cursor.fetchone()[0]
        
        # Entries per database
        cursor.execute('''
            SELECT codeql_db_path, COUNT(*) as count 
            FROM callgraph_cache 
            GROUP BY codeql_db_path 
            ORDER BY count DESC
        ''')
        database_stats = cursor.fetchall()
        
        # Count results by value
        cursor.execute('''
            SELECT result, COUNT(*) as count
            FROM callgraph_cache
            GROUP BY result
        ''')
        result_stats = cursor.fetchall()
        
        conn.close()
        
        return {
            'total_entries': total_entries,
            'database_stats': dict(database_stats),
            'result_stats': dict(result_stats)
        }
        
    except Exception as e:
        logging.error(f"Error getting cache stats: {e}")
        return {'total_entries': 0, 'database_stats': {}, 'result_stats': {}}

def initialize_system_prompt_action(machine) -> None:
    machine.messages = [
        {
            "role": "system",
            "content": f'You are an expert in function call analysis.',
        }
    ]
    return None

def check_function_call_action(machine):
    to_call_from = create_chat_action(
        prompt_template='''Please STRICTLY check if the line  {toCode} in {toLocation} contains a function call to the function of {fromCode} in {fromLocation}. The related code is below:
        {relatedCode}

        If the line  {toCode} in {toLocation} is the caller, and the {fromCode} in {fromLocation} is in the callee, set to_call_from to True; else set to_call_from to False.

        Please Note:
        The Rules should be very STRICT, {toCode} in {toLocation} MUST call a function, and the called function MUST be the function containing {fromCode} in {fromLocation}.

        ''',
        response_parser=Call,
        model_name=get_model_name(),
        save_option='both'
    )(machine, toCode=machine.context.toCode, toLocation=machine.context.toLocation, fromCode=machine.context.fromCode, fromLocation=machine.context.fromLocation, relatedCode=machine.context.relatedCode)
    machine.to_call_from = to_call_from
    return None

def check_function_call_static_action(machine):
    """
    Static mode action using CodeQL to check function call relationships with caching.
    """
    try:
        # Initialize cache database
        init_cache_db()
        
        # Parse the location information from the context
        to_location = machine.context.toLocation  # Format: "filename:line"
        from_location = machine.context.fromLocation  # Format: "filename:line"
        
        # Extract file and line information
        to_file_line = to_location.split(':')
        from_file_line = from_location.split(':')
        
        if len(to_file_line) < 2 or len(from_file_line) < 2:
            # Fallback to LLM mode if location format is incorrect
            print(f"Warning: Invalid location format, falling back to LLM mode")
            return check_function_call_action(machine)
        
        to_file = to_file_line[0]
        to_line = int(to_file_line[1])
        from_file = from_file_line[0]
        
        # Get function names directly from context
        to_function_name = machine.context.toFunctionName
        from_function_name = machine.context.fromFunctionName
        
        if not to_function_name or not from_function_name:
            # Fallback to LLM mode if function names are not provided
            print(f"Warning: Function names not provided in context, falling back to LLM mode")
            return check_function_call_action(machine)
        
        # Get CodeQL database path from machine context
        codeql_db_path = machine.context.codeql_db_path
        
        if not codeql_db_path:
            print(f"Warning: No CodeQL database path found, falling back to LLM mode")
            return check_function_call_action(machine)
        
        logging.info(f"[CallGraph] Static mode: Checking {to_function_name}:{to_line} -> {from_function_name}")
        logging.info(f"[CallGraph]   - DB: {codeql_db_path}")
        logging.info(f"[CallGraph]   - DB exists: {os.path.exists(codeql_db_path)}")
        logging.info(f"[CallGraph]   - From file: {from_file}")
        logging.info(f"[CallGraph]   - To file: {to_file}")
        # Log normalized paths for clarity
        logging.info(f"[CallGraph]   - Normalized from: {os.path.basename(from_file)}")
        logging.info(f"[CallGraph]   - Normalized to: {os.path.basename(to_file)}")
        
        # Add cache database check
        if os.path.exists(CALLGRAPH_CACHE_PATH):
            try:
                import sqlite3
                conn = sqlite3.connect(CALLGRAPH_CACHE_PATH)
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM callgraph_cache")
                count = cursor.fetchone()[0]
                conn.close()
                logging.info(f"[CallGraph] Cache database exists with {count} entries")
            except Exception as e:
                logging.info(f"[CallGraph] Cache database check failed: {e}")
        else:
            logging.info(f"[CallGraph] Cache database not found at {CALLGRAPH_CACHE_PATH}")
        
        # Check cache first
        cached_result = get_cached_result(to_function_name, to_line, to_file, from_function_name, from_file, codeql_db_path)
        
        # Log the query hash for debugging
        query_hash = create_query_hash(to_function_name, to_line, to_file, from_function_name, from_file, codeql_db_path)
        logging.info(f"[CallGraph] Query hash: {query_hash}")
        
        if cached_result is not None:
            # Use cached result
            is_call = cached_result
            logging.info(f"[CallGraph] Cache HIT: {is_call}")
        else:
            # Run CodeQL query and cache the result
            logging.info(f"[CallGraph] Cache MISS: Running CodeQL query...")
            logging.info(f"[CallGraph] Query parameters:")
            logging.info(f"[CallGraph]   - to_function_name: {to_function_name}")
            logging.info(f"[CallGraph]   - to_line: {to_line}")
            logging.info(f"[CallGraph]   - to_file: {to_file}")
            logging.info(f"[CallGraph]   - from_function_name: {from_function_name}")
            logging.info(f"[CallGraph]   - from_file: {from_file}")
            logging.info(f"[CallGraph]   - codeql_db_path: {codeql_db_path}")
            
            from AdvancedTools.CallGraphSearch.call_graph_search import check_point_to_point_call
            
            try:
                is_call = check_point_to_point_call(
                    to_function_name=to_function_name,
                    to_line=to_line,
                    to_file=to_file,
                    from_function_name=from_function_name,
                    from_file=from_file,
                    codeql_db_path=codeql_db_path
                )
                logging.info(f"[CallGraph] CodeQL query completed successfully: {is_call}")
            except Exception as query_error:
                logging.error(f"[CallGraph] CodeQL query failed: {query_error}")
                raise
            
            # Cache the result
            cache_result(to_function_name, to_line, to_file, from_function_name, from_file, codeql_db_path, is_call)
            logging.info(f"[CallGraph] Result cached for future use")
        
        # Create Call object with the result
        call_result = Call(to_call_from=is_call)
        machine.to_call_from = call_result
        
        logging.info(f"[CallGraph] Final result: {is_call} ({'RETURN' if is_call else 'CALL'})")
        
    except Exception as e:
        logging.error(f"Error in static analysis, falling back to LLM mode: {e}")
        # Fallback to LLM mode on any error
        return check_function_call_action(machine)
    
    return None

def exit_action(machine):
    return None

def get_check_function_call_action(machine):
    """
    Determine which action to use based on global ANALYSIS_MODE variable.
    """
    if ANALYSIS_MODE == 'static':
        return check_function_call_static_action(machine)
    else:
        return check_function_call_action(machine)

state_definitions = {
    'InitializeSystemPrompt': {
        'action': initialize_system_prompt_action,
        'next_state_func': lambda result, machine: 'CheckFunctionCall',
    },
    'CheckFunctionCall': {
        'action': get_check_function_call_action,
        'next_state_func': lambda result, machine: 'Exit',
    },
    'Exit': {
        'action': exit_action,
        'next_state_func': None,
    },
}

# Keep original state definitions for backward compatibility
state_definitions_llm = {
    'InitializeSystemPrompt': {
        'action': initialize_system_prompt_action,
        'next_state_func': lambda result, machine: 'CheckFunctionCall',
    },
    'CheckFunctionCall': {
        'action': check_function_call_action,
        'next_state_func': lambda result, machine: 'Exit',
    },
    'Exit': {
        'action': exit_action,
        'next_state_func': None,
    },
}

# Static mode state definitions
state_definitions_static = {
    'InitializeSystemPrompt': {
        'action': initialize_system_prompt_action,
        'next_state_func': lambda result, machine: 'CheckFunctionCall',
    },
    'CheckFunctionCall': {
        'action': check_function_call_static_action,
        'next_state_func': lambda result, machine: 'Exit',
    },
    'Exit': {
        'action': exit_action,
        'next_state_func': None,
    },
}
