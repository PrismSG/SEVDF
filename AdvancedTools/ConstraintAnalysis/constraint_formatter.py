"""
Constraint Formatter - Shared utilities for formatting constraint analysis results.

This module provides shared functions for:
1. Formatting constraints in natural language for LLM prompts
2. Formatting constraints for human-readable display
"""

from typing import List, Dict


def format_constraints_natural_language(constraints: List[Dict],
                                        constraint_type: str = "must-satisfy") -> List[str]:
    """
    Format constraints in natural language for better comprehension.

    This creates human-readable descriptions of constraints suitable for
    LLM prompts or user-facing output.

    Args:
        constraints: List of constraint dictionaries with keys like 'line', 'branch',
                    'condition_text', 'path_count', 'total_paths'
        constraint_type: Type of constraints ("must-satisfy", "must-take", "optional")

    Returns:
        List of natural language constraint descriptions
    """
    if not constraints:
        return []

    lines = []
    for constraint in constraints:
        line = constraint.get('line', '?')
        branch = constraint.get('branch', '?')
        condition_text = constraint.get('condition_text', '')

        if condition_text and condition_text not in ['UNKNOWN', 'None', '']:
            if branch == 'TRUE':
                lines.append(f"    - At line {line}, the condition '{condition_text}' must evaluate to TRUE")
            elif branch == 'FALSE':
                lines.append(f"    - At line {line}, the condition '{condition_text}' must evaluate to FALSE")
            else:
                lines.append(f"    - At line {line}, take the {branch} branch when evaluating '{condition_text}'")
        else:
            lines.append(f"    - At line {line}, take the {branch} branch")

        # Add path count info for optional constraints
        if constraint_type == "optional" and 'path_count' in constraint and 'total_paths' in constraint:
            path_count = constraint.get('path_count', 0)
            total_paths = constraint.get('total_paths', path_count)
            lines[-1] += f" (in {path_count}/{total_paths} paths)"

    return lines


def format_constraints_for_display(constraints: List[Dict],
                                   indent: str = "    ",
                                   show_blocks: bool = True) -> str:
    """
    Format constraints in a human-readable way for display.

    This creates a formatted string representation of constraints suitable
    for logging or debug output.

    Args:
        constraints: List of constraint dictionaries with keys like 'line', 'branch',
                    'condition_text', 'condition_code', 'iteration_context', 'block_id'
        indent: String to use for indentation (default: 4 spaces)
        show_blocks: Whether to show block IDs in the output (default: True)

    Returns:
        Formatted string with constraint information
    """
    if not constraints:
        return f"{indent}No constraints found"

    lines = []
    for constraint in constraints:
        line_num = constraint.get('line', '?')
        if line_num == 0:
            line_num = '?'
        branch = constraint.get('branch', '?')
        condition_text = constraint.get('condition_text', constraint.get('condition_code', ''))
        context = constraint.get('iteration_context', '')
        block_id = constraint.get('block_id', '')

        constraint_line = f"{indent}- Line {line_num}: {branch}"
        if condition_text:
            # Clean up the condition text
            condition_text = str(condition_text).strip()
            if condition_text and condition_text != 'UNKNOWN' and condition_text != 'None':
                constraint_line += f" - `{condition_text}`"
        if context and context != 'original':
            constraint_line += f" (in {context})"
        if show_blocks and block_id:
            constraint_line += f" [from block: {block_id}]"

        lines.append(constraint_line)

    return '\n'.join(lines)
