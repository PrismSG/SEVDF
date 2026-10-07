"""
Logic Unit Reasoning Scheduler Config

Main scheduling logic: dispatches per-unit LLM reasoning in phase order
(backward → forward → intermediate). Each LogicUnit is analyzed independently
via its own StateMachine instance.
"""
import json
import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any, Optional

from .reasoning_scheduler_context import AnalysisTask, AnalysisQueue, AnalysisExecutor
from .reasoning_scheduler_tools import create_analysis_queue
from .._02_logic_unit_management.logic_unit_context import LogicUnit
from .._03_connection_analysis.logic_unit_connections import LogicUnitConnections, get_unit_intermediate_contexts

# Import Scanner-Union's own state machine and contexts
from .._04_3_source_backward_unit_analysis.source_backward_context import SourceBackwardFlowContext
from .._04_4_intermediate_transition_unit_analysis.intermediate_transition_context import IntermediateTransitionFlowContext
from .._04_5_forward_to_sink_unit_analysis.forward_to_sink_context import ForwardToSinkFlowContext
from .._04_3_source_backward_unit_analysis.source_backward_config import state_definitions as source_backward_state_definitions
from .._04_4_intermediate_transition_unit_analysis.intermediate_transition_config import state_definitions as intermediate_transition_state_definitions
from .._04_5_forward_to_sink_unit_analysis.forward_to_sink_config import state_definitions as forward_sink_state_definitions

# Import base machine
from BaseMachine.state_machine import StateMachine

logger = logging.getLogger(__name__)

_SKIP_VIRTUAL_UNITS = os.environ.get('SKIP_VIRTUAL_UNITS', '0') == '1'
_PARALLEL_UNITS = int(os.environ.get('VK_PARALLEL_UNITS', '4'))


# ---------------------------------------------------------------------------
# Per-unit state machine creation and execution
# ---------------------------------------------------------------------------

def _analyze_backward_unit(
    unit: LogicUnit,
    cwe_code: str,
    project_name: str,
    cwe_cot_config: Dict[str, Any],
    model_name: str
) -> Dict[str, Any]:
    """Analyze a backward Logic Unit using Scanner-Union's state machine"""
    logger.debug(f"Analyzing backward unit with {len(unit.steps)} steps")

    # Create context for backward analysis
    context = SourceBackwardFlowContext(
        steps=unit.steps,
        model_name=model_name,
        start_function_name=unit.steps[0].fromPoint.functionName if unit.steps else "",
        variable_name=unit.variable_name,
        outer_backward_behavior_variable=unit.shared_variables.get('outer_backward_behavior_variable', ''),
        outer_backward_behavior_function_name=unit.shared_variables.get('outer_backward_behavior_function_name', ''),
        outer_backward_behavior_line_code=unit.shared_variables.get('outer_backward_behavior_line_code', ''),
        outer_backward_behavior_line_number=unit.shared_variables.get('outer_backward_behavior_line_number', 0),
        steps_relationships=unit.steps_relationships
    )

    config_path = cwe_cot_config.get('config_path', '') if cwe_cot_config else ''

    machine = StateMachine(
        context=context,
        state_definitions=source_backward_state_definitions,
        initial_state='InitContext',
        config_path=config_path,
        cwe_cot_config=cwe_cot_config
    )

    # Pass variant information to the state machine
    machine.has_propagation_variants = unit.has_propagation_variants
    machine.merged_constraints = unit.merged_constraints
    machine.variant_details = unit.variant_details

    try:
        machine.process()
        result = getattr(machine, 'one_step_analysis', {})
        conversation = list(getattr(machine, 'complete_conversation_history', []))
        return result, conversation
    except Exception as e:
        logger.error(f"Backward analysis failed: {e}")
        return {
            'reachability': 'ERROR',
            'reachability_explanation': str(e),
            'required_conditions': [],
            'reachability_confidence': 'low',
            'rule_checks': [],
            'error': str(e)
        }, []


def _analyze_forward_unit(
    unit: LogicUnit,
    cwe_code: str,
    project_name: str,
    cwe_cot_config: Dict[str, Any],
    model_name: str
) -> Dict[str, Any]:
    """Analyze a forward Logic Unit using Scanner-Union's state machine"""
    logger.debug(f"Analyzing forward unit with {len(unit.steps)} steps")

    context = ForwardToSinkFlowContext(
        steps=unit.steps,
        steps_relationships=unit.steps_relationships,
        model_name=model_name,
        variable_name=unit.variable_name,
        user_input_variable=unit.shared_variables.get('user_input_variable', unit.variable_name),
        user_input_function_name=unit.shared_variables.get('user_input_function_name', ''),
        user_input_line_code=unit.shared_variables.get('user_input_line_code', ''),
        user_input_line_number=unit.shared_variables.get('user_input_line_number', 0)
    )

    config_path = cwe_cot_config.get('config_path', '') if cwe_cot_config else ''

    machine = StateMachine(
        context=context,
        state_definitions=forward_sink_state_definitions,
        initial_state='InitContext',
        config_path=config_path,
        cwe_cot_config=cwe_cot_config
    )

    machine.has_propagation_variants = unit.has_propagation_variants
    machine.merged_constraints = unit.merged_constraints
    machine.variant_details = unit.variant_details

    try:
        machine.process()
        result = getattr(machine, 'one_step_analysis', {})
        conversation = list(getattr(machine, 'complete_conversation_history', []))
        return result, conversation
    except Exception as e:
        logger.error(f"Forward analysis failed: {e}")
        return {
            'reachability': 'ERROR',
            'reachability_explanation': str(e),
            'required_conditions': [],
            'reachability_confidence': 'low',
            'rule_checks': [],
            'error': str(e)
        }, []


def _analyze_intermediate_unit(
    unit: LogicUnit,
    backward_results: Dict[str, Dict],
    forward_results: Dict[str, Dict],
    connections: LogicUnitConnections,
    cwe_code: str,
    project_name: str,
    cwe_cot_config: Dict[str, Any],
    model_name: str
) -> Dict[str, Any]:
    """Analyze an intermediate Logic Unit using Scanner-Union's state machine"""
    contexts = get_unit_intermediate_contexts(unit, connections)

    if not contexts:
        # Intermediate-only path (no backward/forward segments) — analyze with empty context
        logger.info(f"No B/F contexts for intermediate unit {unit.cache_key}, analyzing as standalone")
        contexts = [(None, None)]

    context_results = []
    for backward_key, forward_key in contexts:
        backward_result = backward_results.get(backward_key, {}) if backward_key else {}
        forward_result = forward_results.get(forward_key, {}) if forward_key else {}

        logger.debug(f"Analyzing intermediate unit with {len(unit.steps)} steps")

        backward_empty = not backward_result or backward_result.get('reachability') == 'ERROR'
        forward_empty = not forward_result or forward_result.get('reachability') == 'ERROR'

        source_backward_result_str = json.dumps(backward_result) if backward_result else ''
        forward_sink_result_str = json.dumps(forward_result) if forward_result else ''

        logger.info(f"Intermediate unit context: backward_empty={backward_empty}, forward_empty={forward_empty}, "
                     f"backward_result_keys={list(backward_result.keys()) if backward_result else 'N/A'}, "
                     f"forward_result_keys={list(forward_result.keys()) if forward_result else 'N/A'}")

        context = IntermediateTransitionFlowContext(
            steps=unit.steps,
            steps_relationships=unit.steps_relationships,
            source_backward_result=source_backward_result_str,
            forward_sink_result=forward_sink_result_str,
            forward_empty=forward_empty,
            backward_empty=backward_empty
        )

        context.model_name = model_name
        context.user_input_variable = unit.shared_variables.get('user_input_variable', unit.variable_name)
        context.user_input_function_name = unit.shared_variables.get('user_input_function_name', '')
        context.user_input_line_code = unit.shared_variables.get('user_input_line_code', '')
        context.user_input_line_number = unit.shared_variables.get('user_input_line_number', 0)
        context.sink_information = unit.shared_variables.get('sink_information', {})

        config_path = cwe_cot_config.get('config_path', '') if cwe_cot_config else ''

        machine = StateMachine(
            context=context,
            state_definitions=intermediate_transition_state_definitions,
            initial_state='InitContext',
            config_path=config_path,
            cwe_cot_config=cwe_cot_config
        )

        machine.has_propagation_variants = unit.has_propagation_variants
        machine.merged_constraints = unit.merged_constraints
        machine.variant_details = unit.variant_details

        try:
            machine.process()

            if not hasattr(machine, 'json_result') or machine.json_result is None:
                logger.warning(f"Intermediate analysis produced no json_result for unit {unit.cache_key}")
                result = {
                    'reachability': 'ERROR',
                    'reachability_explanation': 'Intermediate analysis produced no structured result',
                    'required_conditions': [],
                    'reachability_confidence': 'low',
                    'transition_checks': [],
                    'is_false_positive': None,
                    'false_positive_confidence': None,
                    'error': 'No json_result produced',
                    'backward_key': backward_key,
                    'forward_key': forward_key
                }
            else:
                result = getattr(machine, 'intermediate_transition_json_result', {})
                if hasattr(machine, 'json_result'):
                    result['valid_uaf'] = machine.json_result.valid_uaf
                result['backward_key'] = backward_key
                result['forward_key'] = forward_key
        except Exception as e:
            logger.error(f"Intermediate analysis failed: {e}")
            result = {
                'reachability': 'ERROR',
                'reachability_explanation': str(e),
                'required_conditions': [],
                'reachability_confidence': 'low',
                'transition_checks': [],
                'is_false_positive': None,
                'false_positive_confidence': None,
                'error': str(e),
                'backward_key': backward_key,
                'forward_key': forward_key
            }

        # Capture conversation history for this context
        result['conversation_history'] = list(getattr(machine, 'complete_conversation_history', []))

        context_results.append(result)

    return {
        'context_results': context_results,
        'contexts_analyzed': len(context_results)
    }


# ---------------------------------------------------------------------------
# Main scheduling logic
# ---------------------------------------------------------------------------

def execute_batch_analysis(
    queue: AnalysisQueue,
    units: Dict[str, LogicUnit],
    connections: LogicUnitConnections,
    executor: AnalysisExecutor,
    reasoning_dump: Optional[object] = None
) -> Dict[str, Any]:
    """
    Main scheduling entry point.
    Dispatches per-unit reasoning in three phases: backward → forward → intermediate.

    Args:
        reasoning_dump: Optional ReasoningDumpStorage instance for persisting conversations.
    """
    start_time = time.time()

    stats = {
        'backward_analyzed': 0,
        'forward_analyzed': 0,
        'intermediate_analyzed': 0,
        'analysis_errors': 0,
        'total_analysis_time': 0
    }

    # Log unit distribution
    backward_unit_count = sum(1 for u in units.values() if u.segment_type == 'backward')
    forward_unit_count = sum(1 for u in units.values() if u.segment_type == 'forward')
    intermediate_unit_count = sum(1 for u in units.values() if u.segment_type == 'intermediate')
    cached_count = sum(1 for u in units.values() if u.is_cached)

    logger.info(f"Unit distribution: backward={backward_unit_count}, forward={forward_unit_count}, intermediate={intermediate_unit_count}")
    logger.info(f"Cached units: {cached_count}")

    backward_results = {}
    forward_results = {}

    # Cached and skipped virtual units still provide context to intermediate reasoning.
    for unit in units.values():
        skipped = unit.is_cached or (_SKIP_VIRTUAL_UNITS and unit.is_virtual)
        result = unit.get_result()
        if skipped and result:
            if unit.segment_type == 'backward':
                backward_results[unit.cache_key] = result
            elif unit.segment_type == 'forward':
                forward_results[unit.cache_key] = result
    if backward_results or forward_results:
        logger.info(f"Pre-populated {len(backward_results)} backward + {len(forward_results)} forward results from skipped units")

    lock = threading.Lock()

    # --- Per-unit worker functions (closures over shared state) ---

    def _process_backward_task(task):
        unit = units.get(task.logic_unit_key)
        if not unit:
            return
        try:
            analysis_start = time.time()
            result, conversation = _analyze_backward_unit(
                unit, executor.cwe_code, executor.project_name,
                executor.cwe_cot_config, executor.model_name
            )
            unit.analysis_result = result
            unit.conversation_history = conversation
            with lock:
                backward_results[unit.cache_key] = result
                stats['backward_analyzed'] += 1
            logger.info(f"Backward unit {unit.cache_key[:8]}... analyzed in {time.time() - analysis_start:.2f}s")

            if reasoning_dump and conversation:
                reasoning_dump.store_unit_reasoning(
                    cache_key=unit.cache_key,
                    segment_type='backward',
                    conversation_history=conversation,
                    analysis_result=result,
                    metadata={
                        'variable_name': unit.variable_name,
                        'steps_count': len(unit.steps),
                        'paths_using': list(unit.paths_using),
                    }
                )
                unit.conversation_history = []
        except Exception as e:
            logger.error(f"Failed to analyze backward unit {unit.cache_key}: {e}")
            with lock:
                stats['analysis_errors'] += 1

    def _process_forward_task(task):
        unit = units.get(task.logic_unit_key)
        if not unit:
            return
        try:
            analysis_start = time.time()
            result, conversation = _analyze_forward_unit(
                unit, executor.cwe_code, executor.project_name,
                executor.cwe_cot_config, executor.model_name
            )
            unit.analysis_result = result
            unit.conversation_history = conversation
            with lock:
                forward_results[unit.cache_key] = result
                stats['forward_analyzed'] += 1
            logger.info(f"Forward unit {unit.cache_key[:8]}... analyzed in {time.time() - analysis_start:.2f}s")

            if reasoning_dump and conversation:
                reasoning_dump.store_unit_reasoning(
                    cache_key=unit.cache_key,
                    segment_type='forward',
                    conversation_history=conversation,
                    analysis_result=result,
                    metadata={
                        'variable_name': unit.variable_name,
                        'steps_count': len(unit.steps),
                        'paths_using': list(unit.paths_using),
                    }
                )
                unit.conversation_history = []
        except Exception as e:
            logger.error(f"Failed to analyze forward unit {unit.cache_key}: {e}")
            with lock:
                stats['analysis_errors'] += 1

    def _process_intermediate_task(task):
        unit = units.get(task.logic_unit_key)
        if not unit:
            return
        try:
            analysis_start = time.time()
            result = _analyze_intermediate_unit(
                unit, backward_results, forward_results, connections,
                executor.cwe_code, executor.project_name,
                executor.cwe_cot_config, executor.model_name
            )
            unit.analysis_result = result
            with lock:
                stats['intermediate_analyzed'] += 1
            logger.info(f"Intermediate unit {unit.cache_key[:8]}... analyzed in {time.time() - analysis_start:.2f}s")

            if reasoning_dump:
                all_conversations = []
                for ctx_result in result.get('context_results', []):
                    ctx_conversation = ctx_result.pop('conversation_history', [])
                    if ctx_conversation:
                        reasoning_dump.store_unit_reasoning(
                            cache_key=unit.cache_key,
                            segment_type='intermediate',
                            conversation_history=ctx_conversation,
                            analysis_result=ctx_result,
                            metadata={
                                'variable_name': unit.variable_name,
                                'steps_count': len(unit.steps),
                                'paths_using': list(unit.paths_using),
                                'backward_key': ctx_result.get('backward_key'),
                                'forward_key': ctx_result.get('forward_key'),
                            }
                        )
                        all_conversations.extend(ctx_conversation)
                unit.conversation_history = all_conversations
        except Exception as e:
            logger.error(f"Failed to analyze intermediate unit {unit.cache_key}: {e}")
            with lock:
                stats['analysis_errors'] += 1

    # --- Execution ---

    max_workers = _PARALLEL_UNITS

    # Phase 1+2: Backward and Forward units (all independent, can run concurrently)
    bf_count = len(queue.backward_tasks) + len(queue.forward_tasks)
    logger.info(f"Phase 1+2: Analyzing {len(queue.backward_tasks)} backward + "
                f"{len(queue.forward_tasks)} forward units (workers={max_workers})...")

    if max_workers > 1 and bf_count > 0:
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = []
            for task in queue.backward_tasks:
                futures.append(pool.submit(_process_backward_task, task))
            for task in queue.forward_tasks:
                futures.append(pool.submit(_process_forward_task, task))
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Unexpected error in parallel B/F analysis: {e}")
    else:
        for task in queue.backward_tasks:
            _process_backward_task(task)
        for task in queue.forward_tasks:
            _process_forward_task(task)

    # Phase 3: Intermediate units (depends on Phase 1+2, but independent of each other)
    logger.info(f"Phase 3: Analyzing {len(queue.intermediate_tasks)} intermediate units "
                f"(workers={max_workers})...")

    if max_workers > 1 and len(queue.intermediate_tasks) > 0:
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = []
            for task in queue.intermediate_tasks:
                futures.append(pool.submit(_process_intermediate_task, task))
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Unexpected error in parallel intermediate analysis: {e}")
    else:
        for task in queue.intermediate_tasks:
            _process_intermediate_task(task)

    stats['total_analysis_time'] = time.time() - start_time
    total_analyzed = stats['backward_analyzed'] + stats['forward_analyzed'] + stats['intermediate_analyzed']
    logger.info(f"Scheduling complete: {total_analyzed} units analyzed, "
                f"{stats['analysis_errors']} errors, total time: {stats['total_analysis_time']:.2f}s")

    return stats
