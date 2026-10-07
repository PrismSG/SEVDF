"""
Debug Storage for Scanner-Union
Stores segments, units, and connections information for debugging
"""
import sqlite3
import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)


class DebugStorage:
    def __init__(self, db_path: str = None, max_records: Optional[int] = 1000):
        """Initialize debug storage
        
        Args:
            db_path: Path to database file
            max_records: Maximum number of records to store per type (default: 1000, None for no limit)
        """
        if db_path is None:
            # Use AI_ANALYSIS_DIR for debug database
            ai_analysis_dir = os.environ.get('AI_ANALYSIS_DIR', '/tmp/ai-codeql')
            debug_dir = os.path.join(ai_analysis_dir, 'debug')
            os.makedirs(debug_dir, exist_ok=True)
            self.db_path = os.path.join(debug_dir, 'scanner_union_debug.db')
        else:
            self.db_path = db_path
            
        self.conn = sqlite3.connect(self.db_path)
        self._create_tables()
        self.max_records = max_records
        
        # Track record counts per run
        self._record_counts = {}
        
        if max_records is None:
            logger.info(f"Debug storage initialized at: {self.db_path} (no record limit)")
        else:
            logger.info(f"Debug storage initialized at: {self.db_path} (max {max_records} records per type)")
        
    def _create_tables(self):
        """Create debug tables"""
        cursor = self.conn.cursor()
        
        # Table for analysis runs
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS analysis_runs (
                run_id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                cwe_code TEXT,
                project_name TEXT,
                total_paths INTEGER,
                total_units INTEGER,
                metadata TEXT
            )
        ''')
        
        # Table for path segments
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS path_segments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
                path_id TEXT NOT NULL,
                segment_type TEXT NOT NULL,
                cache_key TEXT,
                unit_cache_key TEXT,  -- Reference to the actual logic unit
                steps_count INTEGER,
                first_function TEXT,
                last_function TEXT,
                variable_name TEXT,
                has_virtual_step BOOLEAN DEFAULT 0,
                step_details TEXT,
                FOREIGN KEY (run_id) REFERENCES analysis_runs(run_id)
            )
        ''')
        
        # Table for logic units
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logic_units (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
                cache_key TEXT NOT NULL,
                segment_type TEXT NOT NULL,
                steps_count INTEGER,
                function_chain TEXT,
                variable_name TEXT,
                paths_using_count INTEGER,
                paths_using TEXT,
                is_context_specific BOOLEAN DEFAULT 0,
                context_info TEXT,
                FOREIGN KEY (run_id) REFERENCES analysis_runs(run_id),
                UNIQUE(run_id, cache_key)
            )
        ''')
        
        # Table for connections
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
                path_id TEXT NOT NULL,
                backward_key TEXT,
                intermediate_key TEXT,
                forward_key TEXT,
                has_all_segments BOOLEAN,
                connection_pattern TEXT,
                FOREIGN KEY (run_id) REFERENCES analysis_runs(run_id)
            )
        ''')
        
        # Table for intermediate contexts
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS intermediate_contexts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
                intermediate_key TEXT NOT NULL,
                backward_key TEXT,
                forward_key TEXT,
                context_count INTEGER DEFAULT 1,
                FOREIGN KEY (run_id) REFERENCES analysis_runs(run_id)
            )
        ''')
        
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_segments_run_path ON path_segments(run_id, path_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_units_run_key ON logic_units(run_id, cache_key)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_connections_run ON connections(run_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_contexts_run_key ON intermediate_contexts(run_id, intermediate_key)')
        
        self.conn.commit()
    
    def start_analysis_run(self, cwe_code: str, project_name: str, total_paths: int, 
                          total_units: int, metadata: Dict = None) -> int:
        """Start a new analysis run and return run_id"""
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO analysis_runs (timestamp, cwe_code, project_name, total_paths, total_units, metadata)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            datetime.now().isoformat(),
            cwe_code,
            project_name,
            total_paths,
            total_units,
            json.dumps(metadata or {})
        ))
        self.conn.commit()
        run_id = cursor.lastrowid
        
        # Initialize record counts for this run
        self._record_counts[run_id] = {
            'path_segments': 0,
            'logic_units': 0,
            'connections': 0,
            'intermediate_contexts': 0
        }
        
        return run_id
    
    def store_path_segment(self, run_id: int, path_id: str, segment_type: str,
                          cache_key: Optional[str], steps: List[Any], 
                          variable_name: Optional[str] = None,
                          steps_relationships: Dict[Any, str] = None,
                          unit_cache_key: Optional[str] = None):
        """Store information about a path segment"""
        # Check if we've reached the limit
        if self.max_records is not None and run_id in self._record_counts and self._record_counts[run_id]['path_segments'] >= self.max_records:
            if self._record_counts[run_id]['path_segments'] == self.max_records:
                logger.info(f"Debug storage: Reached limit of {self.max_records} path_segments")
            return  # Skip storing this record
        if not steps:
            steps_count = 0
            first_function = None
            last_function = None
            step_details = []
        else:
            steps_count = len(steps)
            first_function = steps[0].fromPoint.functionName if hasattr(steps[0], 'fromPoint') else None
            last_function = steps[-1].toPoint.functionName if hasattr(steps[-1], 'toPoint') else None
            
            # Extract step details
            step_details = []
            for i, step in enumerate(steps):
                # Get relation from steps_relationships dictionary if available
                relation = None
                if steps_relationships and hasattr(step, 'fromPoint') and hasattr(step, 'toPoint'):
                    # Normalize file paths to match the keys in steps_relationships
                    from_file = step.fromPoint.file.split('/')[-1] if '/' in step.fromPoint.file else step.fromPoint.file
                    to_file = step.toPoint.file.split('/')[-1] if '/' in step.toPoint.file else step.toPoint.file
                    
                    key = (from_file, step.fromPoint.line, 
                           to_file, step.toPoint.line, step.flowstep)
                    relation = steps_relationships.get(key, None)
                    if relation is None:
                        logger.debug(f"No relation found for key: {key}")
                        logger.debug(f"Available keys in steps_relationships: {list(steps_relationships.keys())[:5]}...")
                
                # Check if relation is missing
                if not relation:
                    logger.warning(f"[{segment_type}] Missing relation for step {i}: {key} - this step was likely created during path splitting")
                    # Still try to get from attributes for debugging
                    relation = getattr(step, 'relation_type', getattr(step, 'relation', None))
                    if not relation:
                        # This shouldn't happen anymore with our fixes
                        relation = "ERROR_MISSING"
                
                detail = {
                    'index': i,
                    'from_func': step.fromPoint.functionName if hasattr(step, 'fromPoint') else None,
                    'to_func': step.toPoint.functionName if hasattr(step, 'toPoint') else None,
                    'from_line': step.fromPoint.line if hasattr(step, 'fromPoint') else None,
                    'to_line': step.toPoint.line if hasattr(step, 'toPoint') else None,
                    'relation': relation
                }
                step_details.append(detail)
        
        # Check for virtual steps
        has_virtual = False
        if steps and steps_relationships:
            for step in steps:
                if hasattr(step, 'fromPoint') and hasattr(step, 'toPoint'):
                    key = (step.fromPoint.file, step.fromPoint.line, 
                           step.toPoint.file, step.toPoint.line, step.flowstep)
                    if steps_relationships.get(key) == 'VIRTUAL':
                        has_virtual = True
                        break
        
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO path_segments 
            (run_id, path_id, segment_type, cache_key, unit_cache_key, steps_count, first_function, 
             last_function, variable_name, has_virtual_step, step_details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            run_id,
            path_id,
            segment_type,
            cache_key,
            unit_cache_key,
            steps_count,
            first_function,
            last_function,
            variable_name,
            has_virtual,
            json.dumps(step_details)
        ))
        self.conn.commit()
        
        # Update count
        if run_id in self._record_counts:
            self._record_counts[run_id]['path_segments'] += 1
    
    def store_logic_unit(self, run_id: int, unit: Any):
        """Store information about a logic unit"""
        # Check if it's a context-specific unit (always store these)
        is_context_specific = '__ctx_' in unit.cache_key
        
        # Check if we've reached the limit (but always store context-specific units)
        if self.max_records is not None and not is_context_specific and run_id in self._record_counts and self._record_counts[run_id]['logic_units'] >= self.max_records:
            if self._record_counts[run_id]['logic_units'] == self.max_records:
                logger.info(f"Debug storage: Reached limit of {self.max_records} logic_units (but will continue storing context-specific units)")
            return  # Skip storing this record
        
        # Log when storing context-specific units beyond limit
        if self.max_records is not None and is_context_specific and run_id in self._record_counts and self._record_counts[run_id]['logic_units'] >= self.max_records:
            logger.debug(f"Storing context-specific unit {unit.cache_key[:32]}... despite reaching limit")
        
        context_info = {}
        
        if is_context_specific:
            # Extract context information
            parts = unit.cache_key.split('__ctx_')
            if len(parts) == 2:
                base_key = parts[0]
                ctx_part = parts[1]
                ctx_parts = ctx_part.split('_')
                if len(ctx_parts) >= 2:
                    context_info = {
                        'base_key': base_key,
                        'backward_ctx': ctx_parts[0],
                        'forward_ctx': ctx_parts[1] if len(ctx_parts) > 1 else None
                    }
        
        # Get function chain - should match the logic in extract_unique_function_chain
        function_chain = []
        if hasattr(unit, 'function_chain'):
            # Use the pre-computed function chain from path decomposition
            function_chain = unit.function_chain
        elif hasattr(unit, 'steps') and unit.steps:
            # Fallback: compute it using the same logic as extract_unique_function_chain
            from AdvancedTools.KnowledgeStorage.knowledge_storage import extract_unique_function_chain
            function_list, _ = extract_unique_function_chain(unit.steps, unit.segment_type)
            function_chain = function_list
        
        cursor = self.conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO logic_units 
                (run_id, cache_key, segment_type, steps_count, function_chain, 
                 variable_name, paths_using_count, paths_using, is_context_specific, context_info)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                run_id,
                unit.cache_key,
                unit.segment_type,
                len(unit.steps) if hasattr(unit, 'steps') else 0,
                '->'.join(function_chain) if isinstance(function_chain, list) else str(function_chain),
                getattr(unit, 'variable_name', None),
                len(unit.paths_using) if hasattr(unit, 'paths_using') else 0,
                json.dumps(unit.paths_using if hasattr(unit, 'paths_using') else []),
                is_context_specific,
                json.dumps(context_info)
            ))
            self.conn.commit()
            
            # Update count
            if run_id in self._record_counts:
                self._record_counts[run_id]['logic_units'] += 1
                
        except sqlite3.IntegrityError:
            # Unit already exists for this run
            logger.debug(f"Logic unit {unit.cache_key} already stored for run {run_id}")
    
    def store_connection(self, run_id: int, path_id: str, backward_key: Optional[str],
                        intermediate_key: Optional[str], forward_key: Optional[str]):
        """Store connection information"""
        # Check if we've reached the limit
        if self.max_records is not None and run_id in self._record_counts and self._record_counts[run_id]['connections'] >= self.max_records:
            if self._record_counts[run_id]['connections'] == self.max_records:
                logger.info(f"Debug storage: Reached limit of {self.max_records} connections")
            return  # Skip storing this record
        # Determine connection pattern
        pattern_parts = []
        if backward_key:
            pattern_parts.append('B')
        if intermediate_key:
            pattern_parts.append('I')
        if forward_key:
            pattern_parts.append('F')
        pattern = '-'.join(pattern_parts) if pattern_parts else 'EMPTY'
        
        has_all = bool(backward_key and intermediate_key and forward_key)
        
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO connections 
            (run_id, path_id, backward_key, intermediate_key, forward_key, 
             has_all_segments, connection_pattern)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            run_id,
            path_id,
            backward_key,
            intermediate_key,
            forward_key,
            has_all,
            pattern
        ))
        self.conn.commit()
        
        # Update count
        if run_id in self._record_counts:
            self._record_counts[run_id]['connections'] += 1
    
    def store_intermediate_context(self, run_id: int, intermediate_key: str,
                                  backward_key: str, forward_key: str):
        """Store intermediate context information"""
        # Check if we've reached the limit
        if self.max_records is not None and run_id in self._record_counts and self._record_counts[run_id]['intermediate_contexts'] >= self.max_records:
            if self._record_counts[run_id]['intermediate_contexts'] == self.max_records:
                logger.info(f"Debug storage: Reached limit of {self.max_records} intermediate_contexts")
            return  # Skip storing this record
        cursor = self.conn.cursor()
        
        # Check if this context already exists
        cursor.execute('''
            SELECT id, context_count FROM intermediate_contexts
            WHERE run_id = ? AND intermediate_key = ? AND backward_key = ? AND forward_key = ?
        ''', (run_id, intermediate_key, backward_key, forward_key))
        
        result = cursor.fetchone()
        if result:
            # Update count
            cursor.execute('''
                UPDATE intermediate_contexts SET context_count = context_count + 1
                WHERE id = ?
            ''', (result[0],))
        else:
            # Insert new context
            cursor.execute('''
                INSERT INTO intermediate_contexts 
                (run_id, intermediate_key, backward_key, forward_key)
                VALUES (?, ?, ?, ?)
            ''', (run_id, intermediate_key, backward_key, forward_key))
        
        self.conn.commit()
        
        # Update count
        if run_id in self._record_counts:
            self._record_counts[run_id]['intermediate_contexts'] += 1
    
    def get_record_counts(self, run_id: int) -> Dict[str, int]:
        """Get current record counts for a run"""
        return self._record_counts.get(run_id, {})
    
    def get_analysis_summary(self, run_id: int) -> Dict[str, Any]:
        """Get summary of an analysis run"""
        cursor = self.conn.cursor()
        
        # Basic run info
        cursor.execute('SELECT * FROM analysis_runs WHERE run_id = ?', (run_id,))
        run_info = cursor.fetchone()
        
        if not run_info:
            return {}
        
        # Segment statistics
        cursor.execute('''
            SELECT segment_type, COUNT(*) as count, 
                   SUM(CASE WHEN cache_key IS NOT NULL THEN 1 ELSE 0 END) as with_key,
                   SUM(CASE WHEN cache_key IS NULL THEN 1 ELSE 0 END) as without_key,
                   SUM(CASE WHEN has_virtual_step THEN 1 ELSE 0 END) as virtual_count
            FROM path_segments 
            WHERE run_id = ?
            GROUP BY segment_type
        ''', (run_id,))
        segment_stats = {row[0]: {
            'total': row[1], 
            'with_key': row[2], 
            'without_key': row[3],
            'virtual': row[4]
        } for row in cursor.fetchall()}
        
        # Unit statistics
        cursor.execute('''
            SELECT segment_type, COUNT(*) as count,
                   AVG(paths_using_count) as avg_reuse,
                   MAX(paths_using_count) as max_reuse,
                   SUM(CASE WHEN is_context_specific THEN 1 ELSE 0 END) as context_specific
            FROM logic_units
            WHERE run_id = ?
            GROUP BY segment_type
        ''', (run_id,))
        unit_stats = {row[0]: {
            'count': row[1],
            'avg_reuse': row[2],
            'max_reuse': row[3],
            'context_specific': row[4]
        } for row in cursor.fetchall()}
        
        # Connection statistics
        cursor.execute('''
            SELECT connection_pattern, COUNT(*) as count
            FROM connections
            WHERE run_id = ?
            GROUP BY connection_pattern
        ''', (run_id,))
        connection_patterns = {row[0]: row[1] for row in cursor.fetchall()}
        
        # Intermediate context statistics
        cursor.execute('''
            SELECT COUNT(DISTINCT intermediate_key) as unique_intermediates,
                   COUNT(*) as total_contexts,
                   AVG(context_count) as avg_context_count
            FROM intermediate_contexts
            WHERE run_id = ?
        ''', (run_id,))
        context_stats = cursor.fetchone()
        
        # Get record counts to show if limits were reached
        record_counts = self.get_record_counts(run_id)
        limits_reached = {}
        context_units_beyond_limit = 0
        
        if record_counts and self.max_records is not None:
            for record_type, count in record_counts.items():
                if count >= self.max_records:
                    limits_reached[record_type] = True
        
        # Count context-specific units stored beyond limit
        cursor.execute('''
            SELECT COUNT(*) FROM logic_units 
            WHERE run_id = ? AND is_context_specific = 1
        ''', (run_id,))
        total_context_units = cursor.fetchone()[0]
        
        # If we have more than max_records total units, some context units were stored beyond limit
        cursor.execute('SELECT COUNT(*) FROM logic_units WHERE run_id = ?', (run_id,))
        total_units = cursor.fetchone()[0]
        if self.max_records is not None and total_units > self.max_records:
            context_units_beyond_limit = total_units - self.max_records
        
        return {
            'run_info': {
                'run_id': run_info[0],
                'timestamp': run_info[1],
                'cwe_code': run_info[2],
                'project_name': run_info[3],
                'total_paths': run_info[4],
                'total_units': run_info[5],
                'max_records_per_type': self.max_records,
                'limits_reached': limits_reached,
                'context_units_beyond_limit': context_units_beyond_limit,
                'total_context_specific_units': total_context_units
            },
            'segment_statistics': segment_stats,
            'unit_statistics': unit_stats,
            'connection_patterns': connection_patterns,
            'context_statistics': {
                'unique_intermediates': context_stats[0] if context_stats else 0,
                'total_contexts': context_stats[1] if context_stats else 0,
                'avg_context_count': context_stats[2] if context_stats else 0
            }
        }
    
    def get_debug_info(self, run_id: int, path_id: str = None) -> Dict[str, Any]:
        """Get detailed debug information"""
        cursor = self.conn.cursor()
        
        if path_id:
            # Get specific path info
            cursor.execute('''
                SELECT * FROM path_segments 
                WHERE run_id = ? AND path_id = ?
                ORDER BY 
                    CASE segment_type 
                        WHEN 'backward' THEN 1 
                        WHEN 'intermediate' THEN 2 
                        WHEN 'forward' THEN 3 
                    END
            ''', (run_id, path_id))
            segments = cursor.fetchall()
            
            cursor.execute('''
                SELECT * FROM connections
                WHERE run_id = ? AND path_id = ?
            ''', (run_id, path_id))
            connection = cursor.fetchone()
            
            return {
                'path_id': path_id,
                'segments': segments,
                'connection': connection
            }
        else:
            # Get all paths with issues
            cursor.execute('''
                SELECT DISTINCT path_id 
                FROM path_segments
                WHERE run_id = ? AND cache_key IS NULL
            ''', (run_id,))
            paths_without_keys = [row[0] for row in cursor.fetchall()]
            
            cursor.execute('''
                SELECT path_id, connection_pattern
                FROM connections
                WHERE run_id = ? AND has_all_segments = 0
            ''', (run_id,))
            incomplete_connections = cursor.fetchall()
            
            return {
                'paths_without_cache_keys': paths_without_keys,
                'incomplete_connections': incomplete_connections
            }
    
    def close(self):
        """Close database connection"""
        self.conn.close()
