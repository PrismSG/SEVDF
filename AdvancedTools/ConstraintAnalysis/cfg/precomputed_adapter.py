"""
Adapter to make pre-computed data match the exact format expected by CFG builder
"""
import sqlite3
import os
from typing import List, Tuple, Optional


class PrecomputedAdapter:
    """Adapts pre-computed database to match exact query result formats."""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        if not os.path.exists(db_path):
            raise FileNotFoundError(f"Pre-computed database not found: {db_path}")
    
    def get_query_result(self, query_file: str, params: dict) -> Optional[List[Tuple]]:
        """
        Generic method to route queries to specific methods based on query name.
        Returns None if the query is not supported by pre-computation.
        """
        # Extract query name from file path
        query_name = query_file.replace('.ql', '').split('/')[-1]
        
        # Get parameters
        qualified_name = params.get('qualified_name', '')
        function_id = params.get('function_id', '')
        
        # Route to appropriate method
        if query_name == 'func_bb_edge':
            return self.get_func_bb_edge_results(qualified_name, function_id)
        elif query_name == 'func_entrybb':
            return self.get_func_entrybb_results(qualified_name, function_id)
        elif query_name == 'func_exitbb':
            return self.get_func_exitbb_results(qualified_name, function_id)
        elif query_name == 'func_bb_condition' or query_name == 'func_condition':
            return self.get_func_condition_results(qualified_name, function_id)
        elif query_name == 'func_loop':
            return self.get_func_loop_results(qualified_name, function_id)
        elif query_name == 'func_bb':
            return self.get_func_bb_results(qualified_name, function_id)
        else:
            # Query not supported by pre-computation
            return None
    
    def get_func_bb_edge_results(self, qualified_name: str, function_id: str) -> List[Tuple]:
        """
        Get edge results in exact format expected by cfg_builder.
        Original query returns: (file_path, block_id, successor_id, edge_type)
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get all edges for this function with file path from basic_blocks
        cursor.execute('''
            SELECT DISTINCT b.file_path, e.from_bb_id, e.to_bb_id, e.edge_type
            FROM bb_edges e
            JOIN basic_blocks b ON b.function_qualified_name = e.function_qualified_name 
                AND b.bb_id = e.from_bb_id
            WHERE e.function_qualified_name = ?
            ORDER BY e.from_bb_id, e.to_bb_id
        ''', (qualified_name,))
        
        results = cursor.fetchall()
        conn.close()
        return results
    
    def get_func_entrybb_results(self, qualified_name: str, function_id: str) -> List[Tuple]:
        """
        Get entry basic block in exact format.
        Original query returns: (file_path, bb_id)
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT b.file_path, b.bb_id
            FROM basic_blocks b
            WHERE b.function_qualified_name = ? AND b.is_entry = 1
        ''', (qualified_name,))
        
        results = cursor.fetchall()
        conn.close()
        return results
    
    def get_func_exitbb_results(self, qualified_name: str, function_id: str) -> List[Tuple]:
        """
        Get exit basic blocks.
        Original query returns: (bb_id,)
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT bb_id
            FROM basic_blocks
            WHERE function_qualified_name = ? AND is_exit = 1
        ''', (qualified_name,))
        
        results = cursor.fetchall()
        conn.close()
        return results
    
    def get_func_condition_results(self, qualified_name: str, function_id: str) -> List[Tuple]:
        """
        Get condition blocks in exact format.
        Original query returns: (file_path, bb_id, true_bb_id, false_bb_id)
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT file_path, bb_id, true_bb_id, false_bb_id
            FROM conditions
            WHERE function_qualified_name = ?
        ''', (qualified_name,))
        
        results = cursor.fetchall()
        conn.close()
        return results
    
    def get_func_loop_results(self, qualified_name: str, function_id: str) -> List[Tuple]:
        """
        Get loop information.
        Original query returns: (loop_start_bb_id, loop_exit_bb_id, loop_back_bb_id)
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT loop_start_bb_id, loop_exit_bb_id, loop_back_bb_id
            FROM loops
            WHERE function_qualified_name = ?
        ''', (qualified_name,))
        
        results = cursor.fetchall()
        conn.close()
        return results
    def get_func_bb_results(self, qualified_name: str, function_id: str) -> List[Tuple]:
        """
        Get basic blocks for a function.
        Original query returns: (file_path, block_id, is_entry, is_exit)
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT DISTINCT b.file_path, b.bb_id, b.is_entry, b.is_exit
            FROM basic_blocks b
            WHERE b.function_qualified_name = ?
        ''', (qualified_name,))
        
        results = cursor.fetchall()
        conn.close()
        return results
