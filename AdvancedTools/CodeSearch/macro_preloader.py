"""
Macro Preloader - Pre-extracts macro definitions from relatedCode using use-def relationship.

Reduces API calls by identifying macro usages in code snippets via use-def CSV
and pre-fetching their definitions for LLM context injection.
"""

import re
import os
import logging
from typing import List, Dict, Set, Optional, Tuple

from AdvancedTools.CodeSearch.symbol_lookup import SymbolLookup


class MacroPreloader:
    """
    Extracts macro usages from relatedCode using use-def relationship
    and preloads their definitions for prompt injection.
    """

    # Pattern to parse relatedCode format: "File Path: /path/to/file.c\n<line>: <code>"
    FILE_PATH_PATTERN = re.compile(r'^File Path:\s*(.+)$', re.MULTILINE)
    LINE_CODE_PATTERN = re.compile(r'^(\d+):\s*(.*)$', re.MULTILINE)

    def __init__(self, cache_dir: Optional[str] = None):
        """
        Initialize MacroPreloader.

        Args:
            cache_dir: Directory containing macro use-def CSV files.
                       If None, uses AI_ANALYSIS_DIR/cache.
        """
        self.symbol_lookup = SymbolLookup(cache_dir=cache_dir)
        self._collected_macros: Dict[str, Dict] = {}  # name -> macro info (deduplicated)

    def parse_related_code(self, related_code: str) -> List[Tuple[str, int]]:
        """
        Parse relatedCode to extract (file_path, line_number) pairs.

        relatedCode format:
            File Path: /path/to/file.c
            10: int x = MACRO_NAME;
            11: process(x);

        Args:
            related_code: The relatedCode string from context

        Returns:
            List of (file_path, line_number) tuples
        """
        if not related_code:
            return []

        locations = []

        # Extract file path
        file_match = self.FILE_PATH_PATTERN.search(related_code)
        if not file_match:
            return []

        file_path = file_match.group(1).strip()

        # Extract all line numbers
        for match in self.LINE_CODE_PATTERN.finditer(related_code):
            line_num = int(match.group(1))
            locations.append((file_path, line_num))

        return locations

    def extract_locations_from_steps(self, steps: List) -> List[Tuple[str, int]]:
        """
        Extract all (file_path, line_number) pairs from context steps.

        Args:
            steps: List of Step objects with fromPoint/toPoint containing relatedCode

        Returns:
            List of unique (file_path, line_number) tuples
        """
        all_locations = []
        seen = set()

        for step in steps:
            # Check fromPoint.relatedCode
            from_point = getattr(step, 'fromPoint', None)
            if from_point:
                related_code = getattr(from_point, 'relatedCode', '')
                if related_code:
                    for loc in self.parse_related_code(related_code):
                        if loc not in seen:
                            seen.add(loc)
                            all_locations.append(loc)

            # Check toPoint.relatedCode
            to_point = getattr(step, 'toPoint', None)
            if to_point:
                related_code = getattr(to_point, 'relatedCode', '')
                if related_code:
                    for loc in self.parse_related_code(related_code):
                        if loc not in seen:
                            seen.add(loc)
                            all_locations.append(loc)

        return all_locations

    def lookup_macros_at_locations(self, locations: List[Tuple[str, int]]) -> Dict[str, Dict]:
        """
        Look up all macros used at the given locations using use-def relationship.

        Args:
            locations: List of (file_path, line_number) tuples

        Returns:
            Dict mapping macro name to its definition info (deduplicated)
        """
        found_macros = {}

        for file_path, line in locations:
            # Use the new get_macros_at_location method
            macros = self.symbol_lookup.get_macros_at_location(file_path, line)

            for macro in macros:
                name = macro.get('name')
                if name and name not in found_macros:
                    found_macros[name] = macro
                    logging.debug(f"[MacroPreload] Found macro via use-def: {name} at {os.path.basename(file_path)}:{line}")

        return found_macros

    def preload_macros_for_context(self, context) -> Dict[str, Dict]:
        """
        Main entry point: Extract and preload all macros from a context using use-def.

        Args:
            context: Context object with steps attribute

        Returns:
            Dict of macro name -> definition info
        """
        if not context:
            return {}

        # Get steps from context
        steps = getattr(context, 'steps', None)
        if not steps:
            return {}

        # Extract all locations from relatedCode
        locations = self.extract_locations_from_steps(steps)
        logging.info(f"[MacroPreload] Extracted {len(locations)} code locations from context")

        if not locations:
            return {}

        # Look up macros at each location using use-def
        found_macros = self.lookup_macros_at_locations(locations)
        logging.info(f"[MacroPreload] Found {len(found_macros)} unique macros via use-def")

        return found_macros

    def format_macros_for_prompt(self, macros: Dict[str, Dict]) -> Optional[str]:
        """
        Format macro definitions for LLM prompt injection.

        Args:
            macros: Dict of macro name -> definition info from lookup

        Returns:
            Formatted string for prompt injection, or None if no macros
        """
        if not macros:
            return None

        lines = []
        lines.append("=== Macro Definitions ===")
        lines.append("")
        lines.append("The following macros are used in the code (pre-resolved via use-def analysis):")
        lines.append("")

        for name, info in sorted(macros.items()):
            body = info.get('body', 'UNKNOWN')
            def_file = info.get('file_path', 'unknown')
            def_line = info.get('start_line', '?')

            # Format: MACRO_NAME: definition (from file:line)
            file_basename = os.path.basename(def_file) if def_file else 'unknown'
            lines.append(f"  {name}: {body}")
            lines.append(f"    (defined in {file_basename}:{def_line})")
            lines.append("")

        return '\n'.join(lines)


def extract_and_format_macros_for_prompt(context, cache_dir: Optional[str] = None) -> Tuple[Dict, Optional[str]]:
    """
    Convenience function: Extract macros from context using use-def and format for prompt.

    Args:
        context: Context object with steps
        cache_dir: Optional cache directory

    Returns:
        Tuple of (macros_dict, formatted_text_for_prompt)
    """
    preloader = MacroPreloader(cache_dir=cache_dir)
    macros = preloader.preload_macros_for_context(context)
    formatted_text = preloader.format_macros_for_prompt(macros)
    return macros, formatted_text
