"""
Logic Unit Reasoning Scheduler Context
"""
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field


@dataclass
class AnalysisTask:
    """A single analysis task for a Logic Unit"""
    logic_unit_key: str
    segment_type: str
    priority: int  # Higher number = higher priority
    dependencies: List[str] = field(default_factory=list)  # Keys of units this depends on
    
    
@dataclass
class AnalysisQueue:
    """Queue of analysis tasks"""
    backward_tasks: List[AnalysisTask] = field(default_factory=list)
    forward_tasks: List[AnalysisTask] = field(default_factory=list)
    intermediate_tasks: List[AnalysisTask] = field(default_factory=list)
    
    
@dataclass
class AnalysisExecutor:
    """Configuration for analysis execution"""
    cwe_code: str
    project_name: str
    model_name: str
    cwe_cot_config: Dict[str, Any]  # Configuration for per-unit reasoning.
    
    # Optional analysis function overrides.
    backward_analyzer: Optional[Callable] = None
    forward_analyzer: Optional[Callable] = None
    intermediate_analyzer: Optional[Callable] = None
