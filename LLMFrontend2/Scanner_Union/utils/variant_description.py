"""
Variant description utilities for Scanner_Union.

Provides functions to format propagation variant details and merged constraints
into human-readable sections for LLM prompts.
"""
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


def build_variant_behavior_section(
    variant_details: Optional[Dict[str, Dict]],
    segment_type: str
) -> str:
    """
    Build a prompt section describing propagation variants for differing functions.

    Args:
        variant_details: Dict mapping func_key -> variant info, or None.
        segment_type: One of 'backward', 'intermediate', 'forward'.

    Returns:
        Formatted string section to append to behavior details, or empty string.
    """
    if not variant_details:
        return ""

    sections = []

    for func_key, info in variant_details.items():
        variant_count = info.get('variant_count', 0)
        variants = info.get('variants', [])
        if variant_count <= 1 or not variants:
            continue

        # Count total paths across all variants
        total_paths = sum(len(v.get('path_ids', [])) for v in variants)

        # Extract function name from func_key ("funcName@file")
        at_idx = func_key.rfind('@')
        func_name = func_key[:at_idx] if at_idx != -1 else func_key

        section_lines = [
            "",
            f"--- Propagation Variants in Function `{func_name}` "
            f"({variant_count} variants across {total_paths} paths) ---",
            ""
        ]

        for vi, variant in enumerate(variants, 1):
            path_ids = variant.get('path_ids', [])
            lines = variant.get('lines', [])
            code_snippets = variant.get('code_snippets', {})

            path_str = ", ".join(path_ids) if path_ids else "unknown"
            section_lines.append(f"Variant {vi} (paths {path_str}):")

            if lines:
                line_chain = " -> ".join(f"line {ln}" for ln in lines)
                section_lines.append(f"  {line_chain}")

            for snippet_func, code in code_snippets.items():
                if code:
                    section_lines.append(f"  Code in `{snippet_func}`:")
                    section_lines.append("  ```")
                    for code_line in code.splitlines():
                        section_lines.append(f"  {code_line}")
                    section_lines.append("  ```")

            section_lines.append("")

        sections.append("\n".join(section_lines))

    if not sections:
        return ""

    header = "\n\n=== Propagation Variant Details ===\n"
    return header + "\n".join(sections)


def format_merged_constraints(merged_constraints: Optional[Dict[str, Dict]]) -> Optional[str]:
    """
    Format merged constraints into a prompt-ready string.

    Args:
        merged_constraints: Dict mapping func_key -> constraint info with
            'dominator_constraints', 'optional_constraints', 'variant_count',
            'is_merged', and optionally 'demoted_from_must'.

    Returns:
        Formatted string, or None if no meaningful constraints exist.
    """
    if not merged_constraints:
        return None

    has_any_constraint = False
    lines = [
        "=== Control Flow Constraints (Merged from Path Variants) ===",
        ""
    ]

    for func_key, info in merged_constraints.items():
        dominators = info.get('dominator_constraints', [])
        optionals = info.get('optional_constraints', [])
        is_merged = info.get('is_merged', False)
        variant_count = info.get('variant_count', 1)

        if not dominators and not optionals:
            continue

        has_any_constraint = True

        # Extract function name
        at_idx = func_key.rfind('@')
        func_name = func_key[:at_idx] if at_idx != -1 else func_key

        merge_note = f" (merged from {variant_count} variants)" if is_merged else ""
        lines.append(f"Function {func_name}{merge_note}:")

        if dominators:
            lines.append("  MUST-satisfy (all variants):")
            for c in dominators:
                line_num = c.get('line', '?')
                branch = c.get('branch', '?')
                cond_text = c.get('condition_text', '')
                suffix = f" - {cond_text}" if cond_text else ""
                lines.append(f"    - Line {line_num}: branch `{branch}`{suffix}")

        if optionals:
            lines.append("  MAY-satisfy (variant-dependent):")
            for c in optionals:
                line_num = c.get('line', '?')
                branch = c.get('branch', '?')
                cond_text = c.get('condition_text', '')
                coverage = c.get('variant_coverage', '')
                demoted = c.get('demoted_from_must', False)

                suffix_parts = []
                if coverage:
                    suffix_parts.append(f"{coverage} variants")
                if demoted:
                    suffix_parts.append("demoted from must")
                if cond_text:
                    suffix_parts.append(cond_text)

                suffix = f" ({', '.join(suffix_parts)})" if suffix_parts else ""
                lines.append(f"    - Line {line_num}: branch `{branch}`{suffix}")

        lines.append("")

    if not has_any_constraint:
        return None

    return "\n".join(lines)
