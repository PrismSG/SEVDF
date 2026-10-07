"""Utility functions for SARIF semantic labels (location.message.text).

These labels come from CodeQL's DataFlow PathNode.toString() and describe
what data is being tracked at each taint step, e.g.:
  - "*call to getenv"
  - "recv output argument"
  - "*badObject [data]"

They are more descriptive than the column-extracted variable names which
often produce broken results like "tmpData->intOne = 0" or "GETENV".
"""


# Patterns that are too noisy / internal to be useful in narratives
NOISY_PATTERNS = [
    '... = ...',
    '[summary param]',
    '[summary] to write:',
    '[summary] read:',
]


def get_display_variable(point) -> str:
    """Return the best variable name: prefer semanticLabel, fallback to column-extracted.

    Args:
        point: A Point object with .variable and optionally .semanticLabel

    Returns:
        The most descriptive variable name available.
    """
    label = getattr(point, 'semanticLabel', None)
    if not label:
        return point.variable

    label = label.strip()
    if not label:
        return point.variable

    # Filter noisy patterns that don't add value
    if any(p in label for p in NOISY_PATTERNS):
        return point.variable

    return label


def format_variable_for_narrative(point) -> str:
    """Rich display combining semantic label + code span for behavior narratives.

    Returns formats like:
      - "the *call to getenv (`GETENV`)"   when semantic label differs from variable
      - "variable `data`"                   when they match or no semantic label

    Args:
        point: A Point object with .variable and optionally .semanticLabel

    Returns:
        A formatted string suitable for embedding in behavior descriptions.
    """
    display = get_display_variable(point)
    if display != point.variable and getattr(point, 'semanticLabel', None):
        return f"the {display} (`{point.variable}`)"
    return f"variable `{display}`"
