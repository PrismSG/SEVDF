"""
Logic Unit Reasoning Scheduler Tools

Helper utilities for the reasoning scheduler.
"""
import logging
import os
from typing import Dict

from .reasoning_scheduler_context import AnalysisTask, AnalysisQueue
from .._02_logic_unit_management.logic_unit_context import LogicUnit
from .._03_connection_analysis.logic_unit_connections import LogicUnitConnections

logger = logging.getLogger(__name__)

_SKIP_VIRTUAL_UNITS = os.environ.get('SKIP_VIRTUAL_UNITS', '0') == '1'


def create_analysis_queue(
    units: Dict[str, LogicUnit],
    connections: LogicUnitConnections
) -> AnalysisQueue:
    """
    Create prioritized analysis queue from Logic Units.
    Skips cached units and sorts by usage count (higher = higher priority).
    """
    queue = AnalysisQueue()

    for unit in units.values():
        if unit.is_cached:
            continue

        # Virtual units (single-point placeholders) — skip LLM analysis only if enabled
        if _SKIP_VIRTUAL_UNITS and unit.is_virtual:
            unit.analysis_result = {
                'reachability': 'REACHABLE',
                'reachability_explanation': 'Virtual single-point segment (no real steps to analyze)',
                'required_conditions': [],
                'reachability_confidence': 'HIGH',
                'rule_checks': [],
                'is_virtual': True,
            }
            logger.debug(f"Skipping virtual {unit.segment_type} unit {unit.cache_key[:16]}")
            continue

        priority = unit.get_usage_count()

        task = AnalysisTask(
            logic_unit_key=unit.cache_key,
            segment_type=unit.segment_type,
            priority=priority
        )

        # Add dependencies for intermediate units
        if unit.segment_type == 'intermediate':
            original_cache_key = unit.cache_key
            if "__ctx_" in unit.cache_key:
                original_cache_key = unit.cache_key.split("__ctx_")[0]

            contexts = connections.get_intermediate_contexts(original_cache_key)
            if contexts:
                backward_key, forward_key = contexts[0]
                task.dependencies = [backward_key, forward_key]

        # Add to appropriate queue
        if unit.segment_type == 'backward':
            queue.backward_tasks.append(task)
        elif unit.segment_type == 'forward':
            queue.forward_tasks.append(task)
        elif unit.segment_type == 'intermediate':
            queue.intermediate_tasks.append(task)

    # Sort by priority
    queue.backward_tasks.sort(key=lambda t: t.priority, reverse=True)
    queue.forward_tasks.sort(key=lambda t: t.priority, reverse=True)
    queue.intermediate_tasks.sort(key=lambda t: t.priority, reverse=True)

    return queue
