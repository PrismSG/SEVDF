"""
Context models for cross-subpath vulnerability determination.

When intermediate transition steps are empty, this module provides the context
for a sub-machine that combines backward (source) and forward (sink) analysis
results directly to determine vulnerability status.
"""

from pydantic import BaseModel
from typing import List, Optional


class CrossSubpathFlowContext(BaseModel):
    source_backward_result: str
    forward_sink_result: str
    backward_steps: list
    forward_steps: list

    class Config:
        arbitrary_types_allowed = True


class CrossSubpathResult(BaseModel):
    is_false_positive: bool
    overall_assessment: Optional[str] = None
    transition_checks: Optional[List] = None
    false_positive_confidence: Optional[str] = None
