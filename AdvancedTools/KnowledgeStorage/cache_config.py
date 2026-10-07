# Global cache configuration settings
# Enable/disable caching for different analysis types

# Cache configuration settings

# Database configuration
CACHE_DB_NAME = 'cwe_knowledge_base.db'

# Cache logging configuration
# Note: Cache files will be stored in AI_ANALYSIS_DIR/cache/ if AI_ANALYSIS_DIR is set,
# otherwise they will be stored in the current working directory
CACHE_LOG_FILE = 'cache_activity.log'  # Log file for cache operations
ENABLE_CACHE_LOGGING = True  # Enable separate cache logging

# Master switch for all caching functionality
ENABLE_CACHE = True

# Evolution mode - when True, disable intermediate cache to force fresh analysis
# This is controlled by VK_EVOLUTION_MODE environment variable
import os
EVOLUTION_MODE = os.environ.get('VK_EVOLUTION_MODE', '').lower() in ('true', '1', 'yes')

# Individual switches for different analysis types
ENABLE_BACKWARD_CACHE = True
ENABLE_FORWARD_CACHE = True
ENABLE_INTERMEDIATE_CACHE = True  # Enable intermediate analysis caching

# Intermediate cache mode configuration (mutually exclusive modes)
# Mode 1: 'variable_only' - Cache by variable pair (with location) only
# Mode 2: 'with_chain_hash' - Cache by variable pair + backward/forward chain hashes
INTERMEDIATE_CACHE_MODE = 'with_chain_hash'  # Options: 'variable_only', 'with_chain_hash'

# Skip storing results for intermediate cached results
# When enabled, analysis results that were retrieved from intermediate cache
# will not be saved to result files or uploaded to Google Sheets
SKIP_CACHED_INTERMEDIATE_RESULTS = True  # Disable only when fresh intermediate analysis is required.

# Debug settings
CACHE_DEBUG_MODE = False  # Set to True for verbose cache logging

def is_cache_enabled(analysis_type='all'):
    """
    Check if caching is enabled for a specific analysis type.

    Args:
        analysis_type: Type of analysis ('backward', 'forward', 'intermediate', 'all')

    Returns:
        bool: True if caching is enabled for the specified type

    Note:
        In Evolution mode (VK_EVOLUTION_MODE=true), all caches (backward, forward,
        intermediate) are disabled to force fresh analysis for validating pattern
        effectiveness.
    """
    if not ENABLE_CACHE:
        return False

    # In Evolution mode, disable all caches to force fresh analysis
    if EVOLUTION_MODE and analysis_type in ('backward', 'forward', 'intermediate'):
        return False

    if analysis_type == 'all':
        return True
    elif analysis_type == 'backward':
        return ENABLE_BACKWARD_CACHE
    elif analysis_type == 'forward':
        return ENABLE_FORWARD_CACHE
    elif analysis_type == 'intermediate':
        return ENABLE_INTERMEDIATE_CACHE
    else:
        return False

def get_intermediate_cache_mode():
    """
    Get the current intermediate cache mode.
    
    Returns:
        str: 'variable_only' or 'with_chain_hash'
    """
    return INTERMEDIATE_CACHE_MODE

def log_cache_activity(message):
    """
    Log cache activity to a separate file for monitoring.
    
    The log file location is determined by the following priority:
    1. If AI_ANALYSIS_DIR environment variable is set: $AI_ANALYSIS_DIR/cache/
    2. Otherwise: same directory as this config file
    
    Args:
        message: The message to log
    """
    if not ENABLE_CACHE_LOGGING:
        return
        
    import os
    import datetime
    
    # Create timestamp
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Prepare log message
    log_message = f"[{timestamp}] {message}\n"
    
    # Check if AI_ANALYSIS_DIR environment variable is set
    ai_analysis_dir = os.getenv('AI_ANALYSIS_DIR')
    
    if ai_analysis_dir:
        # Use AI Analysis Dir cache folder
        cache_dir = os.path.join(ai_analysis_dir, 'cache')
        # Ensure cache directory exists
        os.makedirs(cache_dir, exist_ok=True)
        log_path = os.path.join(cache_dir, CACHE_LOG_FILE)
    else:
        # Fall back to the directory of this config file
        config_dir = os.path.dirname(os.path.abspath(__file__))
        log_path = os.path.join(config_dir, CACHE_LOG_FILE)
    
    # Write to log file
    try:
        with open(log_path, 'a', encoding='utf-8') as f:
            f.write(log_message)
    except Exception as e:
        # If logging fails, don't break the main functionality
        pass
