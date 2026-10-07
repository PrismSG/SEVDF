"""
ConstraintQuery - Configuration container for constraint analysis queries.

This module was separated from cfg_manager to avoid circular import issues.
"""

from typing import Optional


class ConstraintQuery:
    """Configuration container for constraint analysis queries."""
    
    def __init__(self, codeql_path: str, codeql_db_path: str, cache_dir: str = None, query_helper=None):
        self.codeql_path = codeql_path
        self.codeql_db_path = codeql_db_path
        self.cache_dir = cache_dir
        self.query_helper = query_helper