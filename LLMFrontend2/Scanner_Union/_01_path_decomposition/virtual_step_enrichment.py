"""
Virtual Step Enrichment

Creates virtual single-point backward/forward steps when those segments are
empty after path decomposition.  This ensures every path has a complete
B -> I -> F structure so the downstream backward and forward state machines
always receive at least one step to analyze.

Used during Scanner-Union path decomposition.
"""
import logging
from typing import List, Dict, Any, Tuple

logger = logging.getLogger(__name__)


def _create_virtual_step(point, step_class):
    """Create a virtual single-point step (fromPoint == toPoint).

    Uses the caller-provided Step class so the returned object matches
    whatever Step type the rest of the pipeline expects.
    """
    return step_class(
        flowstep=0,
        fromPoint=point,
        toPoint=point,
        relatedCode=point.relatedCode,
        sameFunction=True
    )


def _register_virtual_relationship(
    steps_relationships: Dict[Any, str],
    point,
) -> None:
    """Add a VIRTUAL entry to the steps_relationships dict.

    Uses the full file path from the point so that downstream state
    machines can find the entry with the same key format they use for
    all other relationship lookups.
    """
    virtual_key = (point.file, point.line,
                   point.file, point.line, 0)
    steps_relationships[virtual_key] = 'VIRTUAL'


def _infer_step_class(existing_steps: List) -> type:
    """Infer the Step class from existing steps so virtual steps match."""
    if existing_steps:
        return type(existing_steps[0])
    # Fallback to Scanner_Union's Step (the canonical definition)
    from .path_decomposition_context import Step
    return Step


def enrich_with_virtual_steps(
    backward_steps: List,
    intermediate_steps: List,
    forward_steps: List,
    steps_relationships: Dict[Any, str],
) -> Tuple[List, List, List, Dict[Any, str], bool, bool]:
    """
    Ensure backward and forward segments are non-empty by creating virtual
    single-point steps when necessary.

    Returns:
        (backward_steps, intermediate_steps, forward_steps,
         steps_relationships, backward_is_virtual, forward_is_virtual)
    """
    backward_is_virtual = False
    forward_is_virtual = False

    # Infer Step class from whichever segment has real steps
    step_class = _infer_step_class(intermediate_steps or forward_steps or backward_steps)

    # --- virtual backward ---------------------------------------------------
    if len(backward_steps) == 0 and (intermediate_steps or forward_steps):
        source_point = None
        if intermediate_steps:
            source_point = intermediate_steps[0].fromPoint
        elif forward_steps:
            source_point = forward_steps[0].fromPoint

        if source_point is not None:
            logger.info(f"Creating virtual backward step at "
                        f"{source_point.functionName}:{source_point.line}")
            backward_steps = [_create_virtual_step(source_point, step_class)]
            _register_virtual_relationship(steps_relationships, source_point)
            backward_is_virtual = True

    # --- virtual forward ----------------------------------------------------
    if len(forward_steps) == 0 and (intermediate_steps or backward_steps):
        sink_point = None
        if intermediate_steps:
            sink_point = intermediate_steps[-1].toPoint
        elif backward_steps:
            sink_point = backward_steps[-1].toPoint

        if sink_point is not None:
            logger.info(f"Creating virtual forward step at "
                        f"{sink_point.functionName}:{sink_point.line}")
            forward_steps = [_create_virtual_step(sink_point, step_class)]
            _register_virtual_relationship(steps_relationships, sink_point)
            forward_is_virtual = True

    return (backward_steps, intermediate_steps, forward_steps,
            steps_relationships, backward_is_virtual, forward_is_virtual)
