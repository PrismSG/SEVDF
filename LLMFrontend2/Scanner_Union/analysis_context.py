"""
Analysis Context for Scanner-Union
Defines the context object used to pass parameters to analysis functions
"""
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from ._01_path_decomposition.path_decomposition_context import Step


@dataclass
class AnalysisContext:
    """
    Context object for passing parameters to Scanner-Union analysis functions
    """
    # Basic info
    cwe_code: str = ""
    project_name: str = ""
    cwe_cot_config: Dict[str, Any] = field(default_factory=dict)
    model_name: str = "gpt-4"
    
    # Variable being tracked
    variable_name: str = ""
    
    # Steps for different analysis types
    backward_steps: List[Step] = field(default_factory=list)
    forward_steps: List[Step] = field(default_factory=list)
    intermediate_steps: List[Step] = field(default_factory=list)
    
    # Results from previous analyses (for intermediate)
    backward_analysis_result: Optional[Dict] = None
    forward_analysis_result: Optional[Dict] = None
    
    # Shared variables for config formatting
    shared_variables: Dict[str, Any] = field(default_factory=dict)
    
    # Additional context
    steps: Optional[List[Step]] = None  # For compatibility
    
    def __post_init__(self):
        """Post-initialization to set steps based on analysis type"""
        if self.backward_steps and not self.steps:
            self.steps = self.backward_steps
        elif self.forward_steps and not self.steps:
            self.steps = self.forward_steps
        elif self.intermediate_steps and not self.steps:
            self.steps = self.intermediate_steps
