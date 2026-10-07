"""
Path Decomposition Context - Data models for path decomposition
"""
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Core data types (shared across Scanner_Union)
# ---------------------------------------------------------------------------

class Point(BaseModel):
    file: str
    line: int
    lineCode: str
    variable: str
    relatedCode: str
    functionName: str
    # Optional column information
    startColumn: Optional[int] = None
    endColumn: Optional[int] = None
    # Semantic label from SARIF message.text (e.g., "*call to getenv", "recv output argument")
    semanticLabel: Optional[str] = None


class Step(BaseModel):
    flowstep: int
    fromPoint: Point
    toPoint: Point
    relatedCode: str
    sameFunction: bool


class FlowStepDivide(BaseModel):
    steps: List[Step]
    variable_name: str = "unknown"


# ---------------------------------------------------------------------------
# Path decomposition results
# ---------------------------------------------------------------------------

@dataclass
class PathDecomposition:
    """Result of decomposing a single path"""
    path_id: str
    original_flow_step: FlowStepDivide

    # Segments after decomposition
    backward_steps: List[Step]
    intermediate_steps: List[Step]
    forward_steps: List[Step]

    # Step relationships for call/return analysis
    steps_relationships: Dict[Any, str] = field(default_factory=dict)

    # Cache keys for each segment
    backward_cache_key: Optional[str] = None
    intermediate_cache_key: Optional[str] = None
    forward_cache_key: Optional[str] = None

    # Virtual segment flags (for CoT enrichment, excluded from statistics)
    backward_is_virtual: bool = False
    forward_is_virtual: bool = False

    def get_segment_mapping(self) -> Dict[str, Optional[str]]:
        return {
            'backward': self.backward_cache_key,
            'intermediate': self.intermediate_cache_key,
            'forward': self.forward_cache_key
        }


@dataclass
class DecompositionBatch:
    """Result of batch decomposition"""
    decompositions: Dict[str, PathDecomposition]  # path_id -> PathDecomposition
    total_paths: int
    total_segments: int
    unique_segments: int
