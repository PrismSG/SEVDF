"""
Unified Coordinator - Orchestrates all steps of Scanner-Union
"""
import os
import time
import json
import logging
from typing import List, Dict, Any
from colorama import Fore

# Import contexts and tools from each step
from .._01_path_decomposition.path_decomposition_tools import batch_decompose_paths
from .._01_path_decomposition.path_decomposition_context import PathDecomposition

from .._02_logic_unit_management.logic_unit_tools import (
    aggregate_logic_units, get_analysis_order
)
from .._02_logic_unit_management.logic_unit_manager import LogicUnitManager

from .._03_connection_analysis.logic_unit_connections import LogicUnitConnections, get_unit_intermediate_contexts

from .._04_logic_unit_reasoning_scheduler.reasoning_scheduler_config import execute_batch_analysis
from .._04_logic_unit_reasoning_scheduler.reasoning_scheduler_tools import create_analysis_queue
from .._04_logic_unit_reasoning_scheduler.reasoning_scheduler_context import AnalysisExecutor

from .._05_vulnerability_assessment.vulnerability_assessment_tools import assemble_batch_results

from .._01_path_decomposition.path_decomposition_context import FlowStepDivide
from AdvancedTools.KnowledgeStorage.knowledge_storage import (
    connect_to_db, create_table_if_not_exists,
    retrieve_backward_analysis_cache, store_backward_analysis_cache,
    retrieve_forward_analysis_cache, store_forward_analysis_cache,
    retrieve_intermediate_analysis_cache, store_intermediate_analysis_cache
)

# Import debug storage
try:
    from .._00_debug.debug_storage import DebugStorage
    DEBUG_ENABLED = True
except ImportError:
    DEBUG_ENABLED = False

# Import reasoning dump storage
try:
    from .._00_debug.reasoning_dump import ReasoningDumpStorage
    REASONING_DUMP_AVAILABLE = True
except ImportError:
    REASONING_DUMP_AVAILABLE = False

logger = logging.getLogger(__name__)


class UnifiedCoordinator:
    """
    Coordinates all steps of Scanner-Union batch processing
    """
    
    def __init__(self, cwe_code: str, project_name: str, cwe_cot_config: Dict, model_name: str = "gpt-4", cwe_data=None):
        self.cwe_code = cwe_code
        self.project_name = project_name
        self.cwe_cot_config = cwe_cot_config  # Configuration for per-unit reasoning.
        self.model_name = model_name
        self.cwe_data = cwe_data  # Store the cwe_data object
        
        # Knowledge storage for caching
        self.db_conn = connect_to_db()
        create_table_if_not_exists(self.db_conn)
        
        # Debug storage - TEMPORARILY ENABLED BY DEFAULT FOR DEBUGGING
        self.debug_storage = None
        self.debug_run_id = None
        # if DEBUG_ENABLED and os.environ.get('SCANNER_UNION_DEBUG', '0') == '1':
        if DEBUG_ENABLED:  # Always enable for debugging
            try:
                self.debug_storage = DebugStorage(max_records=None)  # No limit
                logger.info("Debug storage enabled for Scanner-Union (DEFAULT ON FOR DEBUGGING)")
            except Exception as e:
                logger.warning(f"Failed to initialize debug storage: {e}")
        
        # Reasoning dump storage
        self.reasoning_dump = None
        if REASONING_DUMP_AVAILABLE:
            try:
                ai_dir = os.environ.get('AI_ANALYSIS_DIR', '/tmp/ai-codeql')
                self.reasoning_dump = ReasoningDumpStorage(
                    base_dir=os.path.join(ai_dir, 'reasoning_dumps')
                )
                logger.info("Reasoning dump storage enabled")
            except Exception as e:
                logger.warning(f"Failed to initialize reasoning dump storage: {e}")

        # Components from each step
        self.logic_unit_manager = LogicUnitManager()
        self.connections = LogicUnitConnections()
        
        # Statistics
        self.stats = {}
        self.decompositions = {}  # Store for statistics generation
    
    def process_paths(self, flow_steps: List[FlowStepDivide], total_paths: int = None) -> Dict[str, Any]:
        """
        Main entry point - process multiple paths

        Args:
            flow_steps: List of paths to process
            total_paths: Total number of paths (for statistics, defaults to len(flow_steps))
        """
        start_time = time.time()

        if total_paths is None:
            total_paths = len(flow_steps)

        logger.info(f"Starting processing of {len(flow_steps)} paths")

        # Initialize debug run
        if self.debug_storage and not self.debug_run_id:
            self.debug_run_id = self.debug_storage.start_analysis_run(
                cwe_code=self.cwe_code,
                project_name=self.project_name,
                total_paths=total_paths or len(flow_steps),
                total_units=0,  # Will be updated later
                metadata={'model': self.model_name}
            )
            logger.info(f"Debug run started with ID: {self.debug_run_id}")
        
        # Step 1: Path Decomposition
        logger.info("Step 1: Path Decomposition")
        decompositions, preprocessing_report = self._step1_decompose_paths(flow_steps)
        self.decompositions = decompositions  # Store for statistics
        
        # Dump decomposition log
        if self.reasoning_dump:
            try:
                self.reasoning_dump.dump_decomposition_log(decompositions)
            except Exception as e:
                logger.warning(f"Failed to dump decomposition log: {e}")

        # Step 2: Logic Unit Management
        logger.info("Step 2: Logic Unit Management")
        units, path_mappings = self._step2_manage_logic_units(decompositions, preprocessing_report)
        
        # Step 3: Connection Analysis
        logger.info("Step 3: Connection Analysis")
        self._step3_analyze_connections(decompositions, units)

        # Log unit counts by type for this batch
        backward_count = sum(1 for u in units.values() if u.segment_type == 'backward')
        forward_count = sum(1 for u in units.values() if u.segment_type == 'forward')
        intermediate_count = sum(1 for u in units.values() if u.segment_type == 'intermediate')
        logger.info(f"Logic Unit counts in this batch: backward={backward_count}, forward={forward_count}, intermediate={intermediate_count}")

        # Generate preprocessing statistics
        logger.info("Generating preprocessing statistics and visualizations...")
        from .._00_statistics.statistics_generator import StatisticsGenerator
        import os

        # Determine output directory
        output_dir = None
        if hasattr(self, 'output_dir'):
            output_dir = os.path.join(self.output_dir, 'statistics')

        stats_gen = StatisticsGenerator(output_dir=output_dir)
        preprocessing_statistics = stats_gen.generate_statistics(
            self.logic_unit_manager,
            self.connections,
            self.decompositions
        )

        # Log total unit counts
        all_units = self.logic_unit_manager.units
        total_backward = sum(1 for u in all_units.values() if u.segment_type == 'backward')
        total_forward = sum(1 for u in all_units.values() if u.segment_type == 'forward')
        total_intermediate = sum(1 for u in all_units.values() if u.segment_type == 'intermediate')
        logger.info(f"Total Logic Unit counts: backward={total_backward}, forward={total_forward}, intermediate={total_intermediate}")
        
        # Step 4: Cache Check
        logger.info("Step 4: Cache Check")
        cache_stats = self._step4_check_cache(units)

        # Step 5: Batch Analysis Execution
        logger.info("Step 5: Batch Analysis Execution")
        analysis_stats = self._step5_execute_analysis(units)

        # Step 6: Cache Storage
        logger.info("Step 6: Cache Storage")
        self._step6_store_cache(units)

        # Step 7: Result Assembly
        logger.info("Step 7: Result Assembly")
        execution_time = time.time() - start_time

        statistics = {
            **cache_stats,
            **analysis_stats,
            'total_units': len(units),
            'connection_stats': self.connections.get_connection_statistics()
        }

        batch_result_dict = assemble_batch_results(
            decompositions, units, execution_time, statistics, preprocessing_report
        ).to_dict()
        batch_result_dict['total_units_processed'] = len(units)
        batch_result_dict['cache_hit_rate'] = cache_stats.get('cache_hit_rate', 0)

        logger.info(f"Batch processing complete in {execution_time:.2f} seconds")

        # Step 7b: Assemble path-level reasoning dumps
        if self.reasoning_dump:
            logger.info("Step 7b: Assembling path-level reasoning dumps")
            try:
                for path_id, decomposition in self.decompositions.items():
                    self.reasoning_dump.store_path_reasoning(
                        path_id=path_id,
                        backward_key=decomposition.backward_cache_key,
                        intermediate_key=decomposition.intermediate_cache_key,
                        forward_key=decomposition.forward_cache_key,
                        units=units
                    )
                self.reasoning_dump.write_index(units, self.connections)
            except Exception as e:
                logger.error(f"Failed to assemble reasoning dumps: {e}")

        # Print debug summary if enabled
        if self.debug_storage and self.debug_run_id:
            try:
                debug_summary = self.debug_storage.get_analysis_summary(self.debug_run_id)
                logger.info("\n=== DEBUG SUMMARY ===")
                logger.info(f"Debug run ID: {self.debug_run_id}")
                logger.info(f"Segment statistics: {debug_summary.get('segment_statistics', {})}")
                logger.info(f"Unit statistics: {debug_summary.get('unit_statistics', {})}")
                logger.info(f"Connection patterns: {debug_summary.get('connection_patterns', {})}")
                logger.info(f"Context statistics: {debug_summary.get('context_statistics', {})}")

                # Get paths with issues
                debug_info = self.debug_storage.get_debug_info(self.debug_run_id)
                if debug_info.get('paths_without_cache_keys'):
                    logger.warning(f"Paths without cache keys: {debug_info['paths_without_cache_keys']}")
                if debug_info.get('incomplete_connections'):
                    logger.warning(f"Incomplete connections: {len(debug_info['incomplete_connections'])}")

                logger.info(f"Debug database location: {self.debug_storage.db_path}")
                logger.info("===================\n")

                # Close debug storage
                self.debug_storage.close()
            except Exception as e:
                logger.error(f"Error generating debug summary: {e}")

        # Add preprocessing statistics to result
        batch_result_dict['preprocessing_statistics'] = preprocessing_statistics
        batch_result_dict['statistics'].update({
            'preprocessing': preprocessing_statistics,
            'analysis_completed': True
        })

        return batch_result_dict
    
    def _step1_decompose_paths(self, flow_steps: List[FlowStepDivide]):
        """Step 1: Decompose paths into segments"""
        # Convert to format expected by decomposition tools
        path_info_list = []
        for i, flow_step in enumerate(flow_steps):
            # Just pass the flow_step, Logic Units will extract variable names
            path_info_list.append(flow_step)
        
        # Batch decompose with CodeQL database path from cwe_data
        codeql_db_path = ''
        if self.cwe_data and hasattr(self.cwe_data, 'codeql_db_path'):
            codeql_db_path = self.cwe_data.codeql_db_path
        path_decompositions = batch_decompose_paths(
            path_info_list, codeql_db_path
        )
        
        # Debug: Check for duplicate cache keys
        cache_key_count = {'backward': {}, 'intermediate': {}, 'forward': {}}
        
        # First pass: count cache keys
        for path_id, decomp_data in path_decompositions.items():
            for segment_type, cache_key in decomp_data.get('segments', {}).items():
                if cache_key:
                    if cache_key not in cache_key_count[segment_type]:
                        cache_key_count[segment_type][cache_key] = []
                    cache_key_count[segment_type][cache_key].append(path_id)
        
        # Log duplicate cache keys
        logger.info("\n=== CACHE KEY DUPLICATION ANALYSIS ===")
        total_segment_count = 0
        total_reused_segments = 0
        
        for segment_type, keys in cache_key_count.items():
            duplicates = [(k, v) for k, v in keys.items() if len(v) > 1]
            segment_count_for_type = sum(len(paths) for paths in keys.values())
            reused_segments_for_type = sum(len(paths) - 1 for paths in keys.values() if len(paths) > 1)
            
            total_segment_count += segment_count_for_type
            total_reused_segments += reused_segments_for_type
            
            logger.info(f"{segment_type} segments:")
            logger.info(f"  Total segments: {segment_count_for_type}")
            logger.info(f"  Unique cache keys: {len(keys)}")
            logger.info(f"  Reused segments: {reused_segments_for_type}")
            logger.info(f"  Cache keys used by multiple paths: {len(duplicates)}")
            
            if duplicates:
                # Show distribution of reuse counts
                reuse_distribution = {}
                for _, paths in duplicates:
                    count = len(paths)
                    reuse_distribution[count] = reuse_distribution.get(count, 0) + 1
                logger.info(f"  Reuse distribution: {dict(sorted(reuse_distribution.items()))}")
                
                # Show top reused keys
                for cache_key, paths in sorted(duplicates, key=lambda x: len(x[1]), reverse=True)[:3]:
                    logger.info(f"    {cache_key[:32]}... used by {len(paths)} paths")
        
        logger.info(f"\nTOTAL SEGMENTS VERIFICATION:")
        logger.info(f"  Counted from cache keys: {total_segment_count}")
        logger.info(f"  Reported in preprocessing: {sum(d['segment_count'] for d in path_decompositions.values())}")
        logger.info(f"  Total reused segments: {total_reused_segments}")
        
        # Convert to PathDecomposition objects
        decompositions = {}
        for path_id, decomp_data in path_decompositions.items():
            # Get concrete steps from decomp_data (path-specific)
            decomposition = PathDecomposition(
                path_id=path_id,
                original_flow_step=decomp_data.get('_flow_step'),
                backward_steps=decomp_data.get('backward_steps', []),
                intermediate_steps=decomp_data.get('intermediate_steps', []),
                forward_steps=decomp_data.get('forward_steps', []),
                steps_relationships=decomp_data.get('steps_relationships', {}),
                backward_is_virtual=decomp_data.get('backward_is_virtual', False),
                forward_is_virtual=decomp_data.get('forward_is_virtual', False),
            )
            
            # Set cache keys for each segment from decomposition data
            for segment_type, cache_key in decomp_data.get('segments', {}).items():
                if cache_key:
                    # Set cache key for connection tracking
                    if segment_type == 'backward':
                        decomposition.backward_cache_key = cache_key
                    elif segment_type == 'intermediate':
                        decomposition.intermediate_cache_key = cache_key
                    elif segment_type == 'forward':
                        decomposition.forward_cache_key = cache_key
            
            # Log missing segments for debugging
            if not decomposition.backward_cache_key:
                logger.debug(f"Path {path_id}: No backward segment")
            if not decomposition.intermediate_cache_key:
                logger.debug(f"Path {path_id}: No intermediate segment")
            if not decomposition.forward_cache_key:
                logger.debug(f"Path {path_id}: No forward segment")
            
            # Store segment info in debug storage
            if self.debug_storage and self.debug_run_id:
                
                # Store backward segment
                if decomposition.backward_steps or decomposition.backward_cache_key:
                    # Get the actual unit cache key (might be the same as cache_key for non-intermediate)
                    unit_cache_key = decomposition.backward_cache_key
                    
                    self.debug_storage.store_path_segment(
                        run_id=self.debug_run_id,
                        path_id=path_id,
                        segment_type='backward',
                        cache_key=decomposition.backward_cache_key,
                        steps=decomposition.backward_steps or [],
                        variable_name=decomposition.backward_steps[-1].toPoint.variable if decomposition.backward_steps else None,
                        steps_relationships=decomposition.steps_relationships,  # Use path's own relationships
                        unit_cache_key=unit_cache_key
                    )
                
                # Store intermediate segment
                if decomposition.intermediate_steps or decomposition.intermediate_cache_key:
                    # For intermediate, the unit_cache_key might be different due to context
                    unit_cache_key = decomposition.intermediate_cache_key
                    
                    # Note: unit_cache_key will contain __ctx_ suffix for context-specific units
                    self.debug_storage.store_path_segment(
                        run_id=self.debug_run_id,
                        path_id=path_id,
                        segment_type='intermediate',
                        cache_key=decomposition.intermediate_cache_key,
                        steps=decomposition.intermediate_steps or [],
                        variable_name=decomposition.intermediate_steps[0].fromPoint.variable if decomposition.intermediate_steps else None,
                        steps_relationships=decomposition.steps_relationships,  # Use path's own relationships
                        unit_cache_key=unit_cache_key
                    )
                
                # Store forward segment
                if decomposition.forward_steps or decomposition.forward_cache_key:
                    # Get the actual unit cache key (might be the same as cache_key for non-intermediate)
                    unit_cache_key = decomposition.forward_cache_key
                    
                    self.debug_storage.store_path_segment(
                        run_id=self.debug_run_id,
                        path_id=path_id,
                        segment_type='forward',
                        cache_key=decomposition.forward_cache_key,
                        steps=decomposition.forward_steps or [],
                        variable_name=decomposition.forward_steps[0].fromPoint.variable if decomposition.forward_steps else None,
                        steps_relationships=decomposition.steps_relationships,  # Use path's own relationships
                        unit_cache_key=unit_cache_key
                    )
            
            decompositions[path_id] = decomposition
        
        # Debug: Check segment_count values
        segment_count_values = [d['segment_count'] for d in path_decompositions.values()]
        segment_count_distribution = {}
        for count in segment_count_values:
            segment_count_distribution[count] = segment_count_distribution.get(count, 0) + 1
        
        logger.info(f"\n=== SEGMENT COUNT DEBUG ===")
        logger.info(f"  segment_count distribution: {segment_count_distribution}")
        logger.info(f"  Sum of segment_counts: {sum(segment_count_values)}")
        logger.info(f"  Actual segments counted: {total_segment_count}")
        
        # Use the actual count instead of the potentially incorrect sum
        preprocessing_report = {
            'total_paths': len(decompositions),
            'total_segments': total_segment_count,  # Use the verified count
            'unique_segments': 0  # Will be calculated in step 2
        }
        
        return decompositions, preprocessing_report
    
    def _step2_manage_logic_units(self, decompositions, preprocessing_report):
        """Step 2: Aggregate and manage Logic Units"""
        units, path_mappings = aggregate_logic_units(
            list(decompositions.values()),
            project_name=self.project_name,
            cache_dir=os.environ.get('AI_ANALYSIS_DIR')
        )
        
        # Update preprocessing report with unique segments count
        preprocessing_report['unique_segments'] = len(units)
        
        # Register in manager
        for cache_key, unit in units.items():
            self.logic_unit_manager.units[cache_key] = unit
            self.logic_unit_manager.units_by_type[unit.segment_type].append(cache_key)
            
            # Store unit info in debug storage
            if self.debug_storage and self.debug_run_id:
                self.debug_storage.store_logic_unit(self.debug_run_id, unit)
        
        return units, path_mappings
    
    def _step3_analyze_connections(self, decompositions, units):
        """Step 3: Build connection relationships"""
        logger.info(f"Building connections for {len(decompositions)} paths")
        
        for path_id, decomposition in decompositions.items():
            # For intermediate keys, extract the original key without context
            intermediate_key = decomposition.intermediate_cache_key
            if intermediate_key and "__ctx_" in intermediate_key:
                intermediate_key = intermediate_key.split("__ctx_")[0]
            
            # Debug logging
            logger.debug(f"Path {path_id} connections:")
            logger.debug(f"  Backward: {decomposition.backward_cache_key[:16] if decomposition.backward_cache_key else 'None'}...")
            logger.debug(f"  Intermediate: {intermediate_key[:16] if intermediate_key else 'None'}...")
            logger.debug(f"  Forward: {decomposition.forward_cache_key[:16] if decomposition.forward_cache_key else 'None'}...")
            
            self.connections.add_path_connection(
                path_id=path_id,
                backward_key=decomposition.backward_cache_key,
                intermediate_key=intermediate_key,
                forward_key=decomposition.forward_cache_key
            )
            
            # Store connection info in debug storage
            if self.debug_storage and self.debug_run_id:
                self.debug_storage.store_connection(
                    run_id=self.debug_run_id,
                    path_id=path_id,
                    backward_key=decomposition.backward_cache_key,
                    intermediate_key=intermediate_key,
                    forward_key=decomposition.forward_cache_key
                )
                
                # Store intermediate contexts if applicable
                # Store for B-I-F, B-I, or I-F patterns
                if intermediate_key and (decomposition.backward_cache_key or decomposition.forward_cache_key):
                    self.debug_storage.store_intermediate_context(
                        run_id=self.debug_run_id,
                        intermediate_key=intermediate_key,
                        backward_key=decomposition.backward_cache_key,
                        forward_key=decomposition.forward_cache_key
                    )
        
        logger.info("Connection analysis complete")
        logger.info(self.connections.visualize_connections())
    
    def _step4_check_cache(self, units):
        """Step 4: Check cache status for all Logic Units"""
        cache_hits = 0
        cache_misses = 0
        
        for unit in units.values():
            cached_result = self._check_cache_for_unit(unit)
            if isinstance(cached_result, str):
                try:
                    cached_result = json.loads(cached_result)
                except (TypeError, ValueError):
                    logger.debug(f"Ignoring invalid cached JSON for {unit.cache_key}")
                    cached_result = None
            if isinstance(cached_result, dict) and cached_result:
                unit.cached_result = cached_result
                unit.is_cached = True
                cache_hits += 1
            else:
                unit.is_cached = False
                unit.cached_result = None
                cache_misses += 1
        
        return {
            'cache_hits': cache_hits,
            'cache_misses': cache_misses,
            'cache_hit_rate': cache_hits / max(1, cache_hits + cache_misses)
        }
    
    def _step5_execute_analysis(self, units):
        """Step 5: Execute batch analysis"""
        # Create analysis queue
        queue = create_analysis_queue(units, self.connections)
        
        # Create executor with Scanner-Union's own analysis implementation
        executor = AnalysisExecutor(
            cwe_code=self.cwe_code,
            project_name=self.project_name,
            model_name=self.model_name,
            cwe_cot_config=self.cwe_cot_config
        )
        
        # Execute analysis
        stats = execute_batch_analysis(
            queue, units, self.connections, executor,
            reasoning_dump=self.reasoning_dump
        )

        return stats
    
    def _step6_store_cache(self, units):
        """Step 6: Store analysis results to cache"""
        stored_count = 0
        
        for unit in units.values():
            if unit.analysis_result and not unit.is_cached:
                try:
                    self._store_to_cache(unit)
                    stored_count += 1
                except Exception as e:
                    logger.error(f"Failed to store cache for {unit.cache_key}: {e}")
        
        logger.info(f"Stored {stored_count} new results to cache")
    
    def _check_cache_for_unit(self, unit):
        """Check cache for a specific Logic Unit"""
        try:
            if unit.segment_type == 'backward':
                return retrieve_backward_analysis_cache(
                    self.db_conn,
                    unit.steps,
                    self.cwe_code,
                    self.project_name
                )
            elif unit.segment_type == 'forward':
                return retrieve_forward_analysis_cache(
                    self.db_conn,
                    unit.steps,
                    self.cwe_code,
                    self.project_name
                )
            elif unit.segment_type == 'intermediate':
                # Get context from connections
                contexts = get_unit_intermediate_contexts(unit, self.connections)
                if contexts:
                    backward_key, forward_key = contexts[0]
                    # Get backward and forward units
                    backward_unit = self.logic_unit_manager.units.get(backward_key)
                    forward_unit = self.logic_unit_manager.units.get(forward_key)
                    if backward_unit and forward_unit:
                        # Extract variable names and locations
                        backward_outer_variable = backward_unit.steps[-1].toPoint.variable if backward_unit.steps else ""
                        forward_outer_variable = forward_unit.steps[0].fromPoint.variable if forward_unit.steps else ""
                        
                        # Extract locations (optional)
                        backward_outer_location = None
                        if backward_unit.steps and hasattr(backward_unit.steps[-1].toPoint, 'file'):
                            backward_outer_location = f"{backward_unit.steps[-1].toPoint.file}:{backward_unit.steps[-1].toPoint.line}"
                        
                        forward_outer_location = None
                        if forward_unit.steps and hasattr(forward_unit.steps[0].fromPoint, 'file'):
                            forward_outer_location = f"{forward_unit.steps[0].fromPoint.file}:{forward_unit.steps[0].fromPoint.line}"
                        
                        return retrieve_intermediate_analysis_cache(
                            self.db_conn,
                            unit.steps,  # intermediate steps
                            self.cwe_code,
                            self.project_name,
                            backward_outer_variable,
                            forward_outer_variable,
                            backward_outer_location,
                            forward_outer_location,
                            backward_unit.cache_key,  # backward_chain_hash
                            forward_unit.cache_key    # forward_chain_hash
                        )
        except Exception as e:
            logger.debug(f"Cache check failed for {unit.cache_key}: {e}")
        return None
    
    def _store_to_cache(self, unit):
        """Store Logic Unit result to cache"""
        result = unit.analysis_result
        if not result:
            return
            
        if unit.segment_type == 'backward':
            store_backward_analysis_cache(
                self.db_conn,
                unit.steps,
                self.cwe_code,
                self.project_name,
                result
            )
        elif unit.segment_type == 'forward':
            store_forward_analysis_cache(
                self.db_conn,
                unit.steps,
                self.cwe_code,
                self.project_name,
                result
            )
        elif unit.segment_type == 'intermediate':
            contexts = get_unit_intermediate_contexts(unit, self.connections)
            if contexts:
                backward_key, forward_key = contexts[0]
                # Get backward and forward units
                backward_unit = self.logic_unit_manager.units.get(backward_key)
                forward_unit = self.logic_unit_manager.units.get(forward_key)
                if backward_unit and forward_unit:
                    # Extract variable names and locations
                    backward_outer_variable = backward_unit.steps[-1].toPoint.variable if backward_unit.steps else ""
                    forward_outer_variable = forward_unit.steps[0].fromPoint.variable if forward_unit.steps else ""
                    
                    # Extract locations (optional)
                    backward_outer_location = None
                    if backward_unit.steps and hasattr(backward_unit.steps[-1].toPoint, 'file'):
                        backward_outer_location = f"{backward_unit.steps[-1].toPoint.file}:{backward_unit.steps[-1].toPoint.line}"
                    
                    forward_outer_location = None
                    if forward_unit.steps and hasattr(forward_unit.steps[0].fromPoint, 'file'):
                        forward_outer_location = f"{forward_unit.steps[0].fromPoint.file}:{forward_unit.steps[0].fromPoint.line}"
                    
                    store_intermediate_analysis_cache(
                        self.db_conn,
                        unit.steps,  # intermediate steps
                        self.cwe_code,
                        self.project_name,
                        backward_outer_variable,
                        forward_outer_variable,
                        result,
                        backward_outer_location,
                        forward_outer_location,
                        backward_unit.cache_key,  # backward_chain_hash
                        forward_unit.cache_key    # forward_chain_hash
                    )
