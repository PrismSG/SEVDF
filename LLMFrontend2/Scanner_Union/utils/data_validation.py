"""
Data validation utilities for the Scanner-Union analysis pipeline.
Ensures data integrity during transmission between analysis phases.
"""

import json
import logging
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, ValidationError
from colorama import Fore

def validate_json_string(json_str: str) -> tuple[bool, Optional[Dict[str, Any]]]:
    """
    Validate and parse a JSON string.
    
    Returns:
        tuple: (is_valid, parsed_data or None)
    """
    if not json_str:
        return False, None
        
    try:
        data = json.loads(json_str)
        return True, data
    except json.JSONDecodeError as e:
        # Only log at debug level for empty strings, which are common
        if json_str.strip() == "":
            logging.debug(f"Empty JSON string provided")
        else:
            # Provide detailed error information for debugging
            logging.debug(f"JSON parsing error: {e}")
            logging.debug(f"Error position: line {e.lineno}, column {e.colno}, char {e.pos}")
            
            # Show context around the error
            lines = json_str.split('\n')
            if e.lineno and e.lineno <= len(lines):
                error_line = lines[e.lineno - 1]
                logging.debug(f"Error line: {error_line}")
                if e.colno:
                    # Show pointer to error position
                    pointer = ' ' * (e.colno - 1) + '^'
                    logging.debug(f"           {pointer}")
            
            # Try to identify common JSON issues
            if '"' in json_str and "'" in json_str:
                logging.debug("Possible issue: Mixed single and double quotes")
            if json_str.count('{') != json_str.count('}'):
                logging.debug(f"Possible issue: Unmatched braces - {{ count: {json_str.count('{')}, }} count: {json_str.count('}')}")
            if json_str.count('[') != json_str.count(']'):
                logging.debug(f"Possible issue: Unmatched brackets - [ count: {json_str.count('[')}, ] count: {json_str.count(']')}")
            if '\\n' in json_str and not '\\\\n' in json_str:
                logging.debug("Possible issue: Unescaped newlines in strings")
                
            # Show first 200 chars of the problematic JSON
            logging.debug(f"JSON content (first 200 chars): {json_str[:200]}...")
            
            # Suggest fixes
            fix_suggestion = suggest_json_fix(json_str, e)
            logging.debug(f"Suggested fix: {fix_suggestion}")
            
        return False, None

def validate_rule_checks(rule_checks: List[Dict[str, Any]]) -> bool:
    """
    Validate the structure of rule check results.
    
    Each rule check should have:
    - rule_text: str
    - check_result: str
    - code_references: List[str]
    """
    if not isinstance(rule_checks, list):
        return False
        
    required_fields = {'rule_text', 'check_result', 'code_references'}
    
    for check in rule_checks:
        if not isinstance(check, dict):
            return False
            
        if not all(field in check for field in required_fields):
            logging.error(f"Missing required fields in rule check: {check}")
            return False
            
        # Validate field types
        if not isinstance(check['rule_text'], str):
            return False
        if not isinstance(check['check_result'], str):
            return False
        if not isinstance(check['code_references'], list):
            return False
            
    return True

def validate_detailed_analysis_result(result_json: str) -> tuple[bool, Optional[Dict[str, Any]]]:
    """
    Validate a DetailedAnalysisResult JSON string.
    
    Returns:
        tuple: (is_valid, parsed_data or None)
    """
    is_valid, data = validate_json_string(result_json)
    if not is_valid:
        return False, None
        
    # Check required fields
    required_fields = {
        'feasibility', 'feasibility_reason', 'required_conditions_code',
        'purpose_rule_checks', 'is_false_positive', 'false_positive_confidence'
    }
    
    if not all(field in data for field in required_fields):
        missing = required_fields - set(data.keys())
        logging.error(f"Missing required fields in DetailedAnalysisResult: {missing}")
        return False, None
        
    # Validate purpose_rule_checks
    if not validate_rule_checks(data.get('purpose_rule_checks', [])):
        logging.error("Invalid purpose_rule_checks structure")
        return False, None
        
    return True, data

def safe_get_detailed_summary(machine: Any, phase: str) -> Optional[str]:
    """
    Safely retrieve detailed summary from a machine object.
    
    Args:
        machine: The state machine object
        phase: The analysis phase ('source_backward' or 'forward_sink')
        
    Returns:
        JSON string of detailed summary or None
    """
    try:
        if phase == 'source_backward':
            if hasattr(machine, 'source_backward_detailed_summary'):
                return machine.source_backward_detailed_summary.json()
            elif hasattr(machine, 'source_backward_raw_result'):
                # Try to validate if it's a detailed result
                is_valid, _ = validate_detailed_analysis_result(machine.source_backward_raw_result)
                if is_valid:
                    return machine.source_backward_raw_result
                    
        elif phase == 'forward_sink':
            if hasattr(machine, 'forward_sink_detailed_summary'):
                return machine.forward_sink_detailed_summary.json()
            elif hasattr(machine, 'forward_sink_raw_result'):
                # Try to validate if it's a detailed result
                is_valid, _ = validate_detailed_analysis_result(machine.forward_sink_raw_result)
                if is_valid:
                    return machine.forward_sink_raw_result
                    
    except Exception as e:
        logging.error(f"Error retrieving detailed summary for {phase}: {e}")
        
    return None

def extract_rule_checks_from_result(result_str: str) -> List[Dict[str, Any]]:
    """
    Extract rule checks from analysis result string.
    
    All analysis results should now be in DetailedAnalysisResult format.
    """
    if not result_str:
        return []

    # Current B/F responses use rule_checks and do not make an FP judgment.
    is_valid, data = validate_json_string(result_str)
    if is_valid and isinstance(data, dict) and 'rule_checks' in data:
        checks = data['rule_checks']
        if not isinstance(checks, list):
            return []
        normalized = [
            {
                'rule_text': check.get('rule_text', ''),
                'check_result': check.get('check_result', check.get('findings', '')),
                'code_references': check.get('code_references', [check.get('what_checked', '')]),
            }
            for check in checks if isinstance(check, dict)
        ]
        return normalized if validate_rule_checks(normalized) else []
        
    # Strategy 1: Try to parse as DetailedAnalysisResult JSON (standard format)
    is_valid, data = validate_detailed_analysis_result(result_str)
    if is_valid and data:
        return data.get('purpose_rule_checks', [])
        
    # Strategy 2: Try to parse as plain JSON with purpose_rule_checks
    is_valid, data = validate_json_string(result_str)
    if is_valid and isinstance(data, dict):
        if 'purpose_rule_checks' in data:
            return data['purpose_rule_checks']
            
    # Strategy 3: Look for inline JSON in text (fallback)
    try:
        import re
        json_pattern = r'\{[^{}]*"purpose_rule_checks"[^{}]*\}'
        matches = re.findall(json_pattern, result_str, re.DOTALL)
        for match in matches:
            is_valid, data = validate_json_string(match)
            if is_valid and 'purpose_rule_checks' in data:
                return data['purpose_rule_checks']
    except Exception as e:
        logging.debug(f"Failed to extract JSON from text: {e}")
        
    logging.warning(f"Could not extract rule checks from result string")
    return []

def clean_analysis_result_for_display(result_str: str) -> str:
    """
    Clean analysis result JSON by removing null/empty fields for cleaner display.
    
    This is important for intermediate analysis to avoid confusion from fields
    that are not relevant to the specific analysis type.
    
    Args:
        result_str: JSON string of analysis result
        
    Returns:
        Cleaned JSON string with null/empty fields removed
    """
    if not result_str:
        return ""
        
    try:
        # Parse JSON
        is_valid, data = validate_json_string(result_str)
        if not is_valid:
            return result_str  # Return original if not valid JSON
            
        # Remove null, None, empty lists, and empty strings
        def clean_dict(d):
            if not isinstance(d, dict):
                return d
            
            cleaned = {}
            for k, v in d.items():
                if v is None or v == [] or v == "":
                    continue  # Skip null/empty values
                elif isinstance(v, dict):
                    cleaned_v = clean_dict(v)
                    if cleaned_v:  # Only include non-empty dicts
                        cleaned[k] = cleaned_v
                elif isinstance(v, list):
                    cleaned_list = []
                    for item in v:
                        if isinstance(item, dict):
                            cleaned_item = clean_dict(item)
                            if cleaned_item:
                                cleaned_list.append(cleaned_item)
                        else:
                            cleaned_list.append(item)
                    if cleaned_list:  # Only include non-empty lists
                        cleaned[k] = cleaned_list
                else:
                    cleaned[k] = v
                    
            return cleaned
        
        cleaned_data = clean_dict(data)
        
        # Return cleaned JSON with nice formatting
        return json.dumps(cleaned_data, indent=2)
        
    except Exception as e:
        logging.debug(f"Failed to clean analysis result: {e}")
        return result_str  # Return original on any error


def log_data_transmission(phase: str, data_type: str, success: bool, details: str = ""):
    """
    Log data transmission events for debugging.
    """
    status = "SUCCESS" if success else "FAILED"
    color = Fore.GREEN if success else Fore.RED
    
    message = f"[{phase}] Data transmission {status} - {data_type}"
    if details:
        message += f" - {details}"
        
    logging.debug(color + message + Fore.RESET)

def validate_analysis_phase_transition(
    from_phase: str,
    to_phase: str,
    machine: Any
) -> tuple[bool, List[str]]:
    """
    Validate data availability when transitioning between analysis phases.
    
    Returns:
        tuple: (is_valid, list_of_warnings)
    """
    warnings = []
    
    # Define phase dependencies
    phase_dependencies = {
        'intermediate_transition': {
            'required': [],  # Can work without previous results
            'optional': ['source_backward_raw_result', 'forward_sink_raw_result']
        }
    }
    
    if to_phase not in phase_dependencies:
        return True, []  # No specific validation needed
        
    deps = phase_dependencies[to_phase]
    
    # Check required dependencies
    for dep in deps.get('required', []):
        if not hasattr(machine, dep) or not getattr(machine, dep):
            warnings.append(f"Missing required data: {dep}")
            
    # Check optional dependencies
    for dep in deps.get('optional', []):
        if not hasattr(machine, dep) or not getattr(machine, dep):
            warnings.append(f"Missing optional data: {dep} (analysis may be incomplete)")
            
    is_valid = len([w for w in warnings if "required" in w]) == 0
    
    return is_valid, warnings

def create_fallback_rule_check(rule_text: str, error_msg: str) -> Dict[str, Any]:
    """
    Create a fallback rule check result when parsing fails.
    """
    return {
        "rule_text": rule_text,
        "check_result": f"Analysis unavailable: {error_msg}",
        "code_references": []
    }

def suggest_json_fix(json_str: str, error: json.JSONDecodeError) -> str:
    """
    Suggest a fix for common JSON errors.
    
    Returns a suggested fix as a string.
    """
    suggestions = []
    
    # Check for common issues
    if "Expecting property name" in str(error):
        suggestions.append("Remove trailing comma before closing brace/bracket")
    
    if "Expecting ',' delimiter" in str(error):
        suggestions.append("Add missing comma between elements")
    
    if "Unterminated string" in str(error):
        suggestions.append("Check for missing closing quotes in strings")
    
    if error.pos and error.pos < len(json_str):
        # Check character at error position
        char_at_error = json_str[error.pos] if error.pos < len(json_str) else 'EOF'
        prev_char = json_str[error.pos - 1] if error.pos > 0 else 'BOF'
        
        if char_at_error == '}' and prev_char == ',':
            suggestions.append("Remove the comma before the closing brace")
        
        if char_at_error == '"' and prev_char not in ['{', '[', ',', ':']:
            suggestions.append("Add a comma before this property")
    
    # Check for unescaped characters
    if '\n' in json_str or '\t' in json_str:
        in_string = False
        escape_needed = False
        for i, char in enumerate(json_str):
            if char == '"' and (i == 0 or json_str[i-1] != '\\'):
                in_string = not in_string
            elif in_string and char in '\n\t':
                escape_needed = True
                break
        
        if escape_needed:
            suggestions.append("Escape newline/tab characters inside strings (\\n, \\t)")
    
    return " | ".join(suggestions) if suggestions else "No specific fix identified"

def ensure_data_integrity(machine: Any) -> None:
    """
    Ensure data integrity across all analysis results in the machine.
    
    This function validates and repairs data where possible.
    """
    phases = ['source_backward', 'forward_sink', 'intermediate_transition']
    
    for phase in phases:
        raw_result_attr = f"{phase}_raw_result"
        
        if hasattr(machine, raw_result_attr):
            raw_result = getattr(machine, raw_result_attr)
            
            if raw_result and isinstance(raw_result, str):
                # Try to validate and potentially repair the data
                is_valid, data = validate_json_string(raw_result)
                
                if not is_valid:
                    # Only log at debug level to reduce noise
                    logging.debug(f"Invalid JSON in {raw_result_attr}, attempting repair")
                    # Could implement JSON repair logic here if needed
                    
    log_data_transmission("ensure_data_integrity", "validation", True, "Data integrity check completed")
