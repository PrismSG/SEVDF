"""
Code structure analysis utilities.

This module provides utilities for analyzing code structure,
such as determining positions within function signatures.
"""


def is_function_parameter_position(point) -> bool:
    """
    Determine if a point is at function parameter position (function signature).

    This checks if the given program point appears to be within a function's
    parameter list by analyzing the code structure.

    Args:
        point: A program point object with lineCode and variable attributes

    Returns:
        True if the point is at a function parameter position, False otherwise
    """
    line_code = point.lineCode.strip()

    if '(' in line_code and ')' in line_code:
        before_paren = line_code.split('(')[0]
        type_indicators = ['int', 'void', 'char', 'float', 'double', 'struct',
                          'unsigned', 'signed', 'const', 'static', '*']

        if sum(1 for indicator in type_indicators if indicator in before_paren) >= 1:
            if point.variable in line_code:
                paren_content = line_code[line_code.find('('):line_code.rfind(')')]
                if point.variable in paren_content:
                    return True

    return False
