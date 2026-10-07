import sqlite3
import logging
from colorama import Fore
import os
import hashlib
import json
from AdvancedTools.KnowledgeStorage.cache_config import is_cache_enabled, CACHE_DB_NAME, CACHE_DEBUG_MODE, log_cache_activity, get_intermediate_cache_mode


def connect_to_db(db_name='cwe_knowledge_base.db'):
    """
    Connect to the knowledge storage database.
    
    The database location is determined by the following priority:
    1. If AI_ANALYSIS_DIR environment variable is set: $AI_ANALYSIS_DIR/cache/
    2. Otherwise: current working directory
    
    Args:
        db_name: Name of the database file
        
    Returns:
        sqlite3.Connection: Database connection
    """
    # Check if AI_ANALYSIS_DIR environment variable is set
    ai_analysis_dir = os.getenv('AI_ANALYSIS_DIR')
    
    if ai_analysis_dir:
        # Use AI Analysis Dir cache folder
        cache_dir = os.path.join(ai_analysis_dir, 'cache')
        # Ensure cache directory exists
        os.makedirs(cache_dir, exist_ok=True)
        db_path = os.path.join(cache_dir, db_name)
        logging.info(f"Using AI Analysis Dir cache: {db_path}")
    else:
        # Fall back to current working directory
        db_path = os.path.join(os.getcwd(), db_name)
        logging.info(f"Using current directory cache: {db_path}")
    
    return sqlite3.connect(db_path)


def create_table_if_not_exists(conn):
    """Create tables for both legacy and new caching systems."""
    cursor = conn.cursor()
    
    # Legacy table for backward compatibility
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS analysis_cache (
        id INTEGER PRIMARY KEY,
        cwe_code TEXT,
        project_name TEXT,
        fromvar TEXT,
        function TEXT,
        summary TEXT
    )
    ''')
    
    # New unified table for subpath analysis caching
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS subpath_analysis_cache (
        id INTEGER PRIMARY KEY,
        analysis_type TEXT NOT NULL,  -- 'backward', 'forward', 'intermediate'
        cwe_code TEXT,
        project_name TEXT,
        variable_name TEXT NOT NULL,
        function_chain_hash TEXT NOT NULL,
        function_chain_sequence TEXT NOT NULL,  -- JSON string of unique function list
        backward_chain_hash TEXT DEFAULT '0',  -- Hash of backward chain for intermediate analysis
        forward_chain_hash TEXT DEFAULT '0',   -- Hash of forward chain for intermediate analysis
        analysis_result TEXT NOT NULL,
        created_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(analysis_type, cwe_code, project_name, variable_name, function_chain_hash, backward_chain_hash, forward_chain_hash)
    )
    ''')
    
    # Index for better performance
    cursor.execute('''
    CREATE INDEX IF NOT EXISTS idx_subpath_cache_lookup 
    ON subpath_analysis_cache (analysis_type, variable_name, function_chain_hash, backward_chain_hash, forward_chain_hash)
    ''')
    
    conn.commit()


def extract_unique_function_chain(steps, segment_type):
    """
    Extract function sequence from steps for caching key with intra-function merging.

    Strategy:
    - Merge steps within the same function where sameFunction=True (intra-function flow)
    - Preserve recursive calls where sameFunction=False but same function name/file
    - Preserve all inter-function calls

    Args:
        steps: List of step objects containing fromPoint and toPoint
        segment_type: Analysis direction ('backward', 'intermediate', 'forward').
            Encoded into the hash so that different analysis directions of the
            same function chain produce distinct keys.

    Returns:
        tuple: (function_list, function_chain_hash)
            - function_list: Function sequence with intra-function steps merged
            - function_chain_hash: Hash of the function sequence including file paths
    """
    if not steps:
        return [], ""
    
    function_sequence = []
    
    # Process steps to build function sequence
    # Include file path to distinguish same-named functions in different files
    for i, step in enumerate(steps):
        from_func_with_file = f"{step.fromPoint.functionName}@{step.fromPoint.file}"
        to_func_with_file = f"{step.toPoint.functionName}@{step.toPoint.file}"
        
        # Always add fromPoint function for the first step
        if i == 0:
            function_sequence.append(from_func_with_file)
        
        # Check if this is an intra-function transition (internal flow):
        # Same function name, same file, AND sameFunction=True
        is_intra_function = (step.fromPoint.functionName == step.toPoint.functionName and 
                           step.fromPoint.file == step.toPoint.file and
                           step.sameFunction)
        
        # Add toPoint function unless it's an intra-function transition
        # This preserves recursive calls (sameFunction=False) while merging internal flow
        if not is_intra_function:
            function_sequence.append(to_func_with_file)
    
    # Create hash of the function sequence for efficient lookup.
    # When segment_type is provided, prepend it so that backward and forward
    # analyses of the same function chain yield different hashes.
    function_chain_str = f"{segment_type}:{'->' .join(function_sequence)}"
    function_chain_hash = hashlib.md5(function_chain_str.encode()).hexdigest()
    
    return function_sequence, function_chain_hash


def extract_chain_hash_from_steps(steps, segment_type):
    """
    Extract function chain hash from analysis steps.

    Args:
        steps: List of analysis steps
        segment_type: Analysis direction ('backward', 'intermediate', 'forward')

    Returns:
        str: Hash of the function chain, or '0' if no steps.
    """
    if not steps:
        return '0'

    _, function_chain_hash = extract_unique_function_chain(steps, segment_type)
    return function_chain_hash


def extract_outer_variable_location(steps, is_backward=True):
    """
    Extract location information for outer variable from analysis steps.
    
    This is a utility function for intermediate analysis caching to get
    location information (file:line) for the outer variable.
    
    Args:
        steps: List of analysis steps (backward or forward)
        is_backward: True for backward analysis (use last step's toPoint), 
                    False for forward analysis (use first step's fromPoint)
        
    Returns:
        str: Location in format "file:line", or None if no steps
    """
    if not steps:
        return None
    
    if is_backward:
        # For backward analysis, outer variable is at the last step's toPoint (sink)
        point = steps[-1].toPoint
    else:
        # For forward analysis, outer variable is at the first step's fromPoint (source)
        point = steps[0].fromPoint
    
    if hasattr(point, 'file') and hasattr(point, 'line'):
        return f"{point.file}:{point.line}"
    
    return None


def retrieve_subpath_analysis_cache(conn, analysis_type, cwe_code, project_name, 
                                  variable_name, function_chain_hash,
                                  backward_chain_hash='0', forward_chain_hash='0'):
    """
    Retrieve cached analysis result for subpath analysis.
    
    Args:
        conn: Database connection
        analysis_type: Type of analysis ('backward', 'forward', 'intermediate')
        cwe_code: CWE code
        project_name: Project name
        variable_name: Variable name for the analysis
        function_chain_hash: Hash of the unique function chain
        backward_chain_hash: Hash of backward chain (for intermediate analysis)
        forward_chain_hash: Hash of forward chain (for intermediate analysis)
        
    Returns:
        tuple: (analysis_result, function_chain_sequence) or None if not found
    """
    cursor = conn.cursor()
    cursor.execute('''
    SELECT analysis_result, function_chain_sequence FROM subpath_analysis_cache 
    WHERE analysis_type=? AND cwe_code=? AND project_name=? 
    AND variable_name=? AND function_chain_hash=? AND backward_chain_hash=? AND forward_chain_hash=?
    ''', (analysis_type, cwe_code, project_name, variable_name, function_chain_hash, backward_chain_hash, forward_chain_hash))
    
    result = cursor.fetchone()
    if result:
        log_cache_activity(f"CACHE HIT - {analysis_type} analysis | CWE:{cwe_code} | Project:{project_name} | Variable:{variable_name} | Hash:{function_chain_hash[:8]}... | BackwardHash:{backward_chain_hash[:8] if backward_chain_hash != '0' else '0'} | ForwardHash:{forward_chain_hash[:8] if forward_chain_hash != '0' else '0'}")
        logging.info(Fore.GREEN + f'Cache hit for {analysis_type} analysis of variable {variable_name}')
        return result[0], json.loads(result[1])
    
    log_cache_activity(f"CACHE MISS - {analysis_type} analysis | CWE:{cwe_code} | Project:{project_name} | Variable:{variable_name} | Hash:{function_chain_hash[:8]}... | BackwardHash:{backward_chain_hash[:8] if backward_chain_hash != '0' else '0'} | ForwardHash:{forward_chain_hash[:8] if forward_chain_hash != '0' else '0'}")
    logging.info(Fore.YELLOW + f'Cache miss for {analysis_type} analysis of variable {variable_name}')
    return None


def store_subpath_analysis_cache(conn, analysis_type, cwe_code, project_name,
                                variable_name, function_chain_hash, function_chain_sequence,
                                analysis_result, backward_chain_hash='0', forward_chain_hash='0'):
    """
    Store analysis result in subpath analysis cache.
    
    Args:
        conn: Database connection
        analysis_type: Type of analysis ('backward', 'forward', 'intermediate')
        cwe_code: CWE code
        project_name: Project name
        variable_name: Variable name for the analysis
        function_chain_hash: Hash of the unique function chain
        function_chain_sequence: List of unique functions in order
        analysis_result: The analysis result to cache
        backward_chain_hash: Hash of backward chain (for intermediate analysis)
        forward_chain_hash: Hash of forward chain (for intermediate analysis)
    """
    cursor = conn.cursor()
    
    # Convert function sequence to JSON string
    function_chain_json = json.dumps(function_chain_sequence)
    if not isinstance(analysis_result, str):
        analysis_result = json.dumps(analysis_result)
    
    cursor.execute('''
    INSERT OR REPLACE INTO subpath_analysis_cache 
    (analysis_type, cwe_code, project_name, variable_name, function_chain_hash, 
     function_chain_sequence, analysis_result, backward_chain_hash, forward_chain_hash) 
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (analysis_type, cwe_code, project_name, variable_name, function_chain_hash,
          function_chain_json, analysis_result, backward_chain_hash, forward_chain_hash))
    
    conn.commit()
    log_cache_activity(f"CACHE STORE - {analysis_type} analysis | CWE:{cwe_code} | Project:{project_name} | Variable:{variable_name} | Hash:{function_chain_hash[:8]}... | BackwardHash:{backward_chain_hash[:8] if backward_chain_hash != '0' else '0'} | ForwardHash:{forward_chain_hash[:8] if forward_chain_hash != '0' else '0'} | Functions:{' -> '.join([f.split('@')[0] for f in function_chain_sequence])} | Full:{' -> '.join(function_chain_sequence)}")
    logging.info(Fore.GREEN + f'Cached {analysis_type} analysis result for variable {variable_name}')


def retrieve_backward_analysis_cache(conn, backward_steps, cwe_code, project_name):
    """
    Retrieve cached result for source_backward_subpath_analysis_action.
    
    Args:
        conn: Database connection
        backward_steps: List of backward analysis steps
        cwe_code: CWE code
        project_name: Project name
        
    Returns:
        Cached analysis result or None if not found
    """
    if not is_cache_enabled('backward'):
        log_cache_activity(f"CACHE DISABLED - Backward analysis caching is disabled")
        if CACHE_DEBUG_MODE:
            logging.info(Fore.YELLOW + 'Backward analysis caching is disabled')
        return None
        
    if not backward_steps:
        log_cache_activity(f"CACHE SKIP - Backward analysis: no steps provided")
        return None
    
    # Extract outer_backward_behavior_variable from the last step (sink point for backward analysis)
    # This matches the definition: machine.outer_backward_behavior_variable = machine.context.steps[-1].toPoint.variable
    outer_backward_behavior_variable = backward_steps[-1].toPoint.variable
    
    # Extract unique function chain
    function_sequence, function_chain_hash = extract_unique_function_chain(backward_steps, 'backward')

    # No config hash needed for backward analysis

    log_cache_activity(f"CACHE LOOKUP - Backward analysis starting | Steps:{len(backward_steps)} | Variable:{outer_backward_behavior_variable} | Chain:{' -> '.join([f.split('@')[0] for f in function_sequence])}")
    
    result = retrieve_subpath_analysis_cache(
        conn, 'backward', cwe_code, project_name,
        outer_backward_behavior_variable, function_chain_hash,
        '0', '0'  # backward and forward chain hashes are not relevant for backward analysis
    )
    
    if result:
        analysis_result, cached_function_sequence = result
        logging.info(Fore.CYAN + f'Using cached backward analysis for outer_backward_behavior_variable: {outer_backward_behavior_variable}')
        logging.info(Fore.CYAN + f'Function chain: {" -> ".join([f.split("@")[0] for f in cached_function_sequence])}')
        logging.info(Fore.CYAN + f'Full chain with files: {" -> ".join(cached_function_sequence)}')
        return analysis_result
    
    return None


def store_backward_analysis_cache(conn, backward_steps, cwe_code, project_name, analysis_result):
    """
    Store result for source_backward_subpath_analysis_action in cache.
    
    Args:
        conn: Database connection
        backward_steps: List of backward analysis steps
        cwe_code: CWE code
        project_name: Project name
        analysis_result: The analysis result to cache
    """
    if not is_cache_enabled('backward'):
        log_cache_activity(f"CACHE DISABLED - Backward analysis caching is disabled for storage")
        if CACHE_DEBUG_MODE:
            logging.info(Fore.YELLOW + 'Backward analysis caching is disabled')
        return
        
    if not backward_steps:
        log_cache_activity(f"CACHE SKIP - Backward analysis storage: no steps provided")
        return
    
    # Extract outer_backward_behavior_variable from the last step (sink point for backward analysis)
    # This matches the definition: machine.outer_backward_behavior_variable = machine.context.steps[-1].toPoint.variable
    outer_backward_behavior_variable = backward_steps[-1].toPoint.variable
    
    # Extract unique function chain
    function_sequence, function_chain_hash = extract_unique_function_chain(backward_steps, 'backward')

    # No config hash needed for backward analysis

    log_cache_activity(f"CACHE STORAGE - Backward analysis | Steps:{len(backward_steps)} | Variable:{outer_backward_behavior_variable} | Chain:{' -> '.join([f.split('@')[0] for f in function_sequence])}")
    
    store_subpath_analysis_cache(
        conn, 'backward', cwe_code, project_name,
        outer_backward_behavior_variable, function_chain_hash, function_sequence,
        analysis_result, '0', '0'  # backward and forward chain hashes are not relevant for backward analysis
    )
    
    logging.info(Fore.CYAN + f'Stored backward analysis cache for outer_backward_behavior_variable: {outer_backward_behavior_variable}')
    logging.info(Fore.CYAN + f'Function chain: {" -> ".join([f.split("@")[0] for f in function_sequence])}')
    logging.info(Fore.CYAN + f'Full chain with files: {" -> ".join(function_sequence)}')


def retrieve_forward_analysis_cache(conn, forward_steps, cwe_code, project_name):
    """
    Retrieve cached result for forward_to_sink_subpath_analysis_action.
    
    Args:
        conn: Database connection
        forward_steps: List of forward analysis steps
        cwe_code: CWE code
        project_name: Project name
        
    Returns:
        Cached analysis result or None if not found
    """
    if not is_cache_enabled('forward'):
        log_cache_activity(f"CACHE DISABLED - Forward analysis caching is disabled")
        if CACHE_DEBUG_MODE:
            logging.info(Fore.YELLOW + 'Forward analysis caching is disabled')
        return None
        
    if not forward_steps:
        log_cache_activity(f"CACHE SKIP - Forward analysis: no steps provided")
        return None
    
    # Extract outer_forward_behavior_variable from the first step (source point for forward analysis)
    # This matches the definition: machine.outer_forward_behavior_variable = machine.context.steps[0].fromPoint.variable
    outer_forward_behavior_variable = forward_steps[0].fromPoint.variable
    
    # Extract unique function chain
    function_sequence, function_chain_hash = extract_unique_function_chain(forward_steps, 'forward')

    # No config hash needed for forward analysis

    log_cache_activity(f"CACHE LOOKUP - Forward analysis starting | Steps:{len(forward_steps)} | Variable:{outer_forward_behavior_variable} | Chain:{' -> '.join([f.split('@')[0] for f in function_sequence])}")
    
    result = retrieve_subpath_analysis_cache(
        conn, 'forward', cwe_code, project_name,
        outer_forward_behavior_variable, function_chain_hash,
        '0', '0'  # backward and forward chain hashes are not relevant for forward analysis
    )
    
    if result:
        analysis_result, cached_function_sequence = result
        logging.info(Fore.CYAN + f'Using cached forward analysis for outer_forward_behavior_variable: {outer_forward_behavior_variable}')
        logging.info(Fore.CYAN + f'Function chain: {" -> ".join([f.split("@")[0] for f in cached_function_sequence])}')
        logging.info(Fore.CYAN + f'Full chain with files: {" -> ".join(cached_function_sequence)}')
        return analysis_result
    
    return None


def store_forward_analysis_cache(conn, forward_steps, cwe_code, project_name, analysis_result):
    """
    Store result for forward_sink_subpath_analysis_action in cache.
    
    Args:
        conn: Database connection
        forward_steps: List of forward analysis steps
        cwe_code: CWE code
        project_name: Project name
        analysis_result: The analysis result to cache
    """
    if not is_cache_enabled('forward'):
        log_cache_activity(f"CACHE DISABLED - Forward analysis caching is disabled for storage")
        if CACHE_DEBUG_MODE:
            logging.info(Fore.YELLOW + 'Forward analysis caching is disabled')
        return
        
    if not forward_steps:
        log_cache_activity(f"CACHE SKIP - Forward analysis storage: no steps provided")
        return
    
    # Extract outer_forward_behavior_variable from the first step (source point for forward analysis)
    # This matches the definition: machine.outer_forward_behavior_variable = machine.context.steps[0].fromPoint.variable
    outer_forward_behavior_variable = forward_steps[0].fromPoint.variable
    
    # Extract unique function chain
    function_sequence, function_chain_hash = extract_unique_function_chain(forward_steps, 'forward')

    # No config hash needed for forward analysis

    log_cache_activity(f"CACHE STORAGE - Forward analysis | Steps:{len(forward_steps)} | Variable:{outer_forward_behavior_variable} | Chain:{' -> '.join([f.split('@')[0] for f in function_sequence])}")
    
    store_subpath_analysis_cache(
        conn, 'forward', cwe_code, project_name,
        outer_forward_behavior_variable, function_chain_hash, function_sequence,
        analysis_result, '0', '0'  # backward and forward chain hashes are not relevant for forward analysis
    )
    
    logging.info(Fore.CYAN + f'Stored forward analysis cache for outer_forward_behavior_variable: {outer_forward_behavior_variable}')
    logging.info(Fore.CYAN + f'Function chain: {" -> ".join([f.split("@")[0] for f in function_sequence])}')
    logging.info(Fore.CYAN + f'Full chain with files: {" -> ".join(function_sequence)}')


def retrieve_intermediate_analysis_cache(conn, intermediate_steps, cwe_code, project_name, 
                                       backward_outer_variable, forward_outer_variable, 
                                       backward_outer_location=None, forward_outer_location=None,
                                       backward_chain_hash=None, forward_chain_hash=None):
    """
    Retrieve cached result for intermediate_transition_subpath_analysis_action.
    
    This function supports two mutually exclusive caching modes:
    
    Mode 1: 'variable_only'
    - Cache key: variable_pair_with_location + function_chain_hash + '0' + '0'
    - Only considers variable pairs and ignores chain hashes
    
    Mode 2: 'with_chain_hash'  
    - Cache key: variable_pair_with_location + function_chain_hash + backward_chain_hash + forward_chain_hash
    - Uses actual chain hashes for more precise caching
    
    Args:
        conn: Database connection
        intermediate_steps: List of intermediate analysis steps
        cwe_code: CWE code
        project_name: Project name
        backward_outer_variable: Outer variable from backward analysis
        forward_outer_variable: Outer variable from forward analysis
        backward_outer_location: Location of backward outer variable (file:line)
        forward_outer_location: Location of forward outer variable (file:line)
        backward_chain_hash: Hash of backward chain (None means '0')
        forward_chain_hash: Hash of forward chain (None means '0')
        
    Returns:
        Cached analysis result or None if not found
    """
    if not is_cache_enabled('intermediate'):
        log_cache_activity(f"CACHE DISABLED - Intermediate analysis caching is disabled")
        if CACHE_DEBUG_MODE:
            logging.info(Fore.YELLOW + 'Intermediate analysis caching is disabled')
        return None
        
    if not intermediate_steps:
        log_cache_activity(f"CACHE SKIP - Intermediate analysis: no steps provided")
        return None
    
    # Create variable pair with location information
    backward_var_with_location = f"{backward_outer_variable}@{backward_outer_location}" if backward_outer_location else backward_outer_variable
    forward_var_with_location = f"{forward_outer_variable}@{forward_outer_location}" if forward_outer_location else forward_outer_variable
    variable_pair_with_location = f"{backward_var_with_location}|{forward_var_with_location}"
    
    # Extract unique function chain
    function_sequence, function_chain_hash = extract_unique_function_chain(intermediate_steps, 'intermediate')
    
    # No config hash needed for intermediate analysis
    
    # Get current cache mode
    cache_mode = get_intermediate_cache_mode()
    
    # Determine cache keys based on mode
    if cache_mode == 'variable_only':
        # Mode 1: Only use variable pair, ignore chain hashes
        backward_hash = '0'
        forward_hash = '0'
        log_cache_activity(f"CACHE LOOKUP - Intermediate analysis (variable_only mode) | Steps:{len(intermediate_steps)} | Variables:{variable_pair_with_location} | Chain:{' -> '.join([f.split('@')[0] for f in function_sequence])}")
    elif cache_mode == 'with_chain_hash':
        # Mode 2: Use actual chain hashes
        backward_hash = backward_chain_hash if backward_chain_hash is not None else '0'
        forward_hash = forward_chain_hash if forward_chain_hash is not None else '0'
        log_cache_activity(f"CACHE LOOKUP - Intermediate analysis (with_chain_hash mode) | Steps:{len(intermediate_steps)} | Variables:{variable_pair_with_location} | Chain:{' -> '.join([f.split('@')[0] for f in function_sequence])} | BackwardHash:{backward_hash[:8] if backward_hash != '0' else '0'} | ForwardHash:{forward_hash[:8] if forward_hash != '0' else '0'}")
    else:
        log_cache_activity(f"CACHE ERROR - Invalid intermediate cache mode: {cache_mode}")
        return None
    
    # Retrieve cache with determined keys
    result = retrieve_subpath_analysis_cache(
        conn, 'intermediate', cwe_code, project_name,
        variable_pair_with_location, function_chain_hash,
        backward_hash, forward_hash
    )
    
    if result:
        analysis_result, cached_function_sequence = result
        if cache_mode == 'variable_only':
            logging.info(Fore.CYAN + f'Using cached intermediate analysis (variable_only mode) for variable pair: {variable_pair_with_location}')
        else:
            logging.info(Fore.CYAN + f'Using cached intermediate analysis (with_chain_hash mode) for variable pair: {variable_pair_with_location}')
            logging.info(Fore.CYAN + f'Backward chain hash: {backward_hash[:8] if backward_hash != "0" else "0"}, Forward chain hash: {forward_hash[:8] if forward_hash != "0" else "0"}')
        logging.info(Fore.CYAN + f'Function chain: {" -> ".join([f.split("@")[0] for f in cached_function_sequence])}')
        logging.info(Fore.CYAN + f'Full chain with files: {" -> ".join(cached_function_sequence)}')
        return analysis_result
    
    return None


def store_intermediate_analysis_cache(conn, intermediate_steps, cwe_code, project_name, 
                                     backward_outer_variable, forward_outer_variable, 
                                     analysis_result, backward_outer_location=None, forward_outer_location=None,
                                     backward_chain_hash=None, forward_chain_hash=None):
    """
    Store result for intermediate_transition_subpath_analysis_action in cache.
    
    This function supports two mutually exclusive caching modes:
    
    Mode 1: 'variable_only'
    - Cache key: variable_pair_with_location + function_chain_hash + '0' + '0'
    - Only considers variable pairs and ignores chain hashes
    - Provides broader cache coverage
    
    Mode 2: 'with_chain_hash'
    - Cache key: variable_pair_with_location + function_chain_hash + backward_chain_hash + forward_chain_hash
    - Uses actual chain hashes for more precise caching
    - Stores only when using chain hash mode
    
    Args:
        conn: Database connection
        intermediate_steps: List of intermediate analysis steps
        cwe_code: CWE code
        project_name: Project name
        backward_outer_variable: Outer variable from backward analysis
        forward_outer_variable: Outer variable from forward analysis
        analysis_result: The analysis result to cache
        backward_outer_location: Location of backward outer variable (file:line)
        forward_outer_location: Location of forward outer variable (file:line)
        backward_chain_hash: Hash of backward chain (None means '0')
        forward_chain_hash: Hash of forward chain (None means '0')
    """
    if not is_cache_enabled('intermediate'):
        log_cache_activity(f"CACHE DISABLED - Intermediate analysis caching is disabled for storage")
        if CACHE_DEBUG_MODE:
            logging.info(Fore.YELLOW + 'Intermediate analysis caching is disabled')
        return
        
    if not intermediate_steps:
        log_cache_activity(f"CACHE SKIP - Intermediate analysis storage: no steps provided")
        return
    
    # Create variable pair with location information
    backward_var_with_location = f"{backward_outer_variable}@{backward_outer_location}" if backward_outer_location else backward_outer_variable
    forward_var_with_location = f"{forward_outer_variable}@{forward_outer_location}" if forward_outer_location else forward_outer_variable
    variable_pair_with_location = f"{backward_var_with_location}|{forward_var_with_location}"
    
    # Extract unique function chain
    function_sequence, function_chain_hash = extract_unique_function_chain(intermediate_steps, 'intermediate')
    
    # No config hash needed for intermediate analysis
    
    # Get current cache mode
    cache_mode = get_intermediate_cache_mode()
    
    # Determine cache keys based on mode
    if cache_mode == 'variable_only':
        # Mode 1: Only use variable pair, ignore chain hashes
        backward_hash = '0'
        forward_hash = '0'
        log_cache_activity(f"CACHE STORAGE - Intermediate analysis (variable_only mode) | Steps:{len(intermediate_steps)} | Variables:{variable_pair_with_location} | Chain:{' -> '.join([f.split('@')[0] for f in function_sequence])}")
    elif cache_mode == 'with_chain_hash':
        # Mode 2: Use actual chain hashes
        backward_hash = backward_chain_hash if backward_chain_hash is not None else '0'
        forward_hash = forward_chain_hash if forward_chain_hash is not None else '0'
        log_cache_activity(f"CACHE STORAGE - Intermediate analysis (with_chain_hash mode) | Steps:{len(intermediate_steps)} | Variables:{variable_pair_with_location} | Chain:{' -> '.join([f.split('@')[0] for f in function_sequence])} | BackwardHash:{backward_hash[:8] if backward_hash != '0' else '0'} | ForwardHash:{forward_hash[:8] if forward_hash != '0' else '0'}")
    else:
        log_cache_activity(f"CACHE ERROR - Invalid intermediate cache mode: {cache_mode}")
        return
    
    # Store cache with determined keys
    store_subpath_analysis_cache(
        conn, 'intermediate', cwe_code, project_name,
        variable_pair_with_location, function_chain_hash, function_sequence,
        analysis_result, backward_hash, forward_hash
    )
    
    if cache_mode == 'variable_only':
        logging.info(Fore.CYAN + f'Stored intermediate analysis cache (variable_only mode) for variable pair: {variable_pair_with_location}')
    else:
        logging.info(Fore.CYAN + f'Stored intermediate analysis cache (with_chain_hash mode) for variable pair: {variable_pair_with_location}')
        logging.info(Fore.CYAN + f'Backward chain hash: {backward_hash[:8] if backward_hash != "0" else "0"}, Forward chain hash: {forward_hash[:8] if forward_hash != "0" else "0"}')
    
    logging.info(Fore.CYAN + f'Function chain: {" -> ".join([f.split("@")[0] for f in function_sequence])}')
    logging.info(Fore.CYAN + f'Full chain with files: {" -> ".join(function_sequence)}')


# Legacy functions for backward compatibility
def retrieve_knowledge(conn, cwe_code, project_name, fromvar, function):
    """Retrieve knowledge from the legacy cache."""
    cursor = conn.cursor()
    cursor.execute('''
    SELECT summary FROM analysis_cache 
    WHERE cwe_code=? AND project_name=? AND fromvar=? AND function=?
    ''', (cwe_code, project_name, fromvar, function))
    result = cursor.fetchone()
    return result[0] if result else None


def store_knowledge(conn, cwe_code, project_name, fromvar, function, summary):
    """Store knowledge in the legacy cache."""
    cursor = conn.cursor()
    cursor.execute('''
    INSERT OR REPLACE INTO analysis_cache 
    (cwe_code, project_name, fromvar, function, summary) 
    VALUES (?, ?, ?, ?, ?)
    ''', (cwe_code, project_name, fromvar, function, summary))
    conn.commit()
    logging.info(Fore.GREEN + 'Analysis result cached.')
