from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional, Union, Tuple

from .._01_path_decomposition.path_decomposition_context import Point, Step

class Conditions(BaseModel):
    conditions: List[str]

class SourceBackwardFlowContext(BaseModel):
    steps: List[Step]
    # Simplified fields, only retaining necessary information
    parent_machine: Optional[Any] = None
    
    # Step relationships for call/return analysis
    steps_relationships: Dict[Any, str] = {}
    
    # Additional context fields needed by state machine
    model_name: str = "gpt-4"
    start_function_name: str = ""
    variable_name: str = ""
    outer_backward_behavior_variable: str = ""
    outer_backward_behavior_function_name: str = ""
    outer_backward_behavior_line_code: str = ""
    outer_backward_behavior_line_number: int = 0

class InlineCondition(BaseModel):
    inlinedCode: str
    conditions: List[str]

class RuleCheckResult(BaseModel):
    """Individual rule check result"""
    rule_text: str = Field(..., description="The original rule text")
    check_result: str = Field(..., description="Detailed result of checking this rule")
    code_references: List[str] = Field(default_factory=list, description="Relevant code lines")

class DetailedAnalysisResult(BaseModel):
    """Enhanced analysis result with rule-by-rule breakdown"""
    
    # Reachability analysis
    feasibility: bool = Field(..., description="Indicates if the call chain is reachable (True) or not (False).")
    feasibility_reason: str = Field(..., description="Explanation of why the call chain is reachable or not.")
    required_conditions_code: List[str] = Field(
        ..., 
        description="List of additional condition codes required for the call chain to be executed."
    )
    
    # Purpose Rules check results
    purpose_rule_checks: List[RuleCheckResult] = Field(
        default_factory=list,
        description="Detailed results for each purpose rule"
    )
    
    # Overall assessment
    overall_assessment: Optional[str] = Field(None, description="Overall assessment of the analysis")
    
    # Overall determination (optional - may be determined at a higher level)
    is_false_positive: Optional[bool] = Field(None, description="Overall false positive determination (optional)")
    false_positive_confidence: Optional[str] = Field(None, description="Confidence level: high/medium/low (optional)")

class FeasibilityResult(BaseModel):
    """
    This model represents the feasibility analysis result of a call chain execution.

    Attributes:
        feasibility (bool): Indicates whether the call chain is reachable (True) or not (False).
        feasibility_reason (str): Provides a detailed explanation of why the call chain is feasible or not.
        required_conditions_code (List[str]): Lists additional conditions required for the call chain to be executed.
    """
 
    feasibility: bool = Field(..., description="Indicates if the call chain is reachable (True) or not (False).")
    feasibility_reason: str = Field(..., description="Explanation of why the call chain is reachable or not.")
    required_conditions_code: List[str] = Field(
        ..., 
        description="List of additional condition codes required for the call chain to be executed."
    )
