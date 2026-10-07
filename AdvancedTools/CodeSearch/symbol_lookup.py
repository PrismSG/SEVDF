"""
Symbol Lookup - CSV-based symbol resolution without OpenGrok dependency.

This module provides fast symbol lookup by querying pre-computed CSV files
exported from CodeQL. It replaces the OpenGrok-based approach with a simpler,
faster, and more reliable solution.

CSV Files Used:
- functionlist.csv: name, qualifiedName, file_path, start_line, end_line
- macros.csv: name, body, file_path, start_line, end_line
- globalvars.csv: name, qualifiedName, type, file_path, start_line, end_line
- classes.csv: name, qualifiedName, file_path, start_line, end_line

Symbol Lookup Flow:
==================
Query (symbol_name)     CSV Cache (in memory)         Source File
+----------------+      +-------------------+         +------------+
| "BASEPATH"     | ---> | macros.csv cache  | ------> | Read code  |
| "bad"          | ---> | functions cache   | ------> | lines      |
+----------------+      +-------------------+         +------------+
"""

import os
import csv
import glob
import logging
from typing import Dict, List, Optional, Tuple, Union


class SymbolLookup:
    """
    Unified symbol lookup using CSV files exported from CodeQL.
    Replaces OpenGrok-based lookup with faster CSV-based approach.
    """

    def __init__(self, cache_dir: Optional[str] = None):
        """
        Initialize SymbolLookup with CSV cache directory.

        Args:
            cache_dir: Directory containing CSV files. If None, uses AI_ANALYSIS_DIR/cache.
        """
        self.cache_dir = cache_dir or self._discover_cache_dir()
        self.source_path = os.environ.get('OPENGROK_SEARCH_PATH', '')

        # In-memory caches (loaded lazily)
        self._functions_cache: Optional[Dict] = None
        self._macros_cache: Optional[Dict] = None
        self._globalvars_cache: Optional[Dict] = None
        self._classes_cache: Optional[Dict] = None

        # File content cache for reading source code
        self._file_cache: Dict[str, List[str]] = {}

        # Basename index for fast get_function_by_location lookups
        self._functions_by_basename: Optional[Dict[str, List]] = None

    def _discover_cache_dir(self) -> str:
        """Auto-discover cache directory from environment."""
        ai_analysis_dir = os.environ.get('AI_ANALYSIS_DIR')
        if ai_analysis_dir:
            cache_dir = os.path.join(ai_analysis_dir, 'cache')
            if os.path.exists(cache_dir):
                return cache_dir

        raise FileNotFoundError(
            "Cache directory not found. Set AI_ANALYSIS_DIR environment variable."
        )

    # Environment variable names for each CSV type
    CSV_ENV_VARS = {
        '*_function_use_def.csv': 'FUNCTION_USE_DEF_CSV',
        '*_functionlist.csv': 'FUNCTION_CSV',
        '*_macro_use_def.csv': 'MACRO_USE_DEF_CSV',
        '*_macros.csv': 'MACRO_CSV',
        '*_globalvars.csv': 'GLOBALVAR_CSV',
        '*_classes.csv': 'CLASS_CSV',
    }

    def _find_csv_file(self, pattern: str) -> Optional[str]:
        """
        Find CSV file using environment variable or pattern in cache directory.

        Priority:
        1. Environment variable (e.g., FUNCTION_USE_DEF_CSV, MACRO_USE_DEF_CSV)
        2. Glob pattern in cache directory
        """
        # Priority 1: Check for environment variable
        env_var = self.CSV_ENV_VARS.get(pattern)
        if env_var:
            csv_path = os.environ.get(env_var)
            if csv_path:
                if os.path.exists(csv_path):
                    logging.debug(f"[SymbolLookup] Using {env_var}: {csv_path}")
                    return csv_path
                else:
                    logging.warning(f"[SymbolLookup] {env_var} set but file not found: {csv_path}")

        # Priority 2: Glob pattern in cache directory
        search_pattern = os.path.join(self.cache_dir, pattern)
        files = glob.glob(search_pattern)
        if files:
            csv_path = files[0]
            logging.debug(f"[SymbolLookup] Auto-discovered CSV: {csv_path}")
            return csv_path

        return None

    # =========================================================================
    # Function Lookup (Use-Def based)
    # =========================================================================

    def _load_functions_cache(self):
        """Load function CSV into memory cache."""
        if self._functions_cache is not None:
            return

        self._functions_cache = {}
        self._functions_by_call = {}  # Index by (call_file, call_line) for precise lookup

        # Try use-def CSV first, fall back to simple functionlist CSV
        csv_file = self._find_csv_file('*_function_use_def.csv')
        if csv_file:
            self._load_function_use_def_csv(csv_file)
        else:
            csv_file = self._find_csv_file('*_functionlist.csv')
            if csv_file:
                self._load_simple_functions_csv(csv_file)
            else:
                logging.warning("No function CSV found")

    def _load_function_use_def_csv(self, csv_file: str):
        """Load function use-def CSV (7 cols: name, qualifiedName, use_file, use_line, def_file, def_start, def_end)."""
        try:
            with open(csv_file, 'r') as f:
                reader = csv.reader(f)
                next(reader, None)  # Skip header
                for row in reader:
                    if len(row) < 7:
                        continue
                    name, qualified_name, use_file, use_line, def_file, def_start, def_end = row[:7]
                    if not name:
                        continue

                    func_info = {
                        'name': name,
                        'qualified_name': qualified_name,
                        'use_file': use_file,
                        'use_line': int(use_line) if use_line else 0,
                        'file_path': def_file,
                        'start_line': int(def_start) if def_start else 0,
                        'end_line': int(def_end) if def_end else 0,
                    }

                    # Index by name
                    if name not in self._functions_cache:
                        self._functions_cache[name] = []
                    self._functions_cache[name].append(func_info)

                    # Index by call location for precise lookup
                    call_key = (os.path.basename(use_file), int(use_line) if use_line else 0)
                    if call_key not in self._functions_by_call:
                        self._functions_by_call[call_key] = []
                    self._functions_by_call[call_key].append(func_info)

            logging.debug(f"[SymbolLookup] Loaded {len(self._functions_cache)} functions (use-def) from CSV")
        except Exception as e:
            logging.error(f"Error loading function use-def CSV: {e}")

    def _load_simple_functions_csv(self, csv_file: str):
        """Load simple functionlist CSV (5 cols: name, qualifiedName, file_path, start_line, end_line)."""
        try:
            with open(csv_file, 'r') as f:
                reader = csv.reader(f)
                next(reader, None)  # Skip header
                for row in reader:
                    if len(row) < 5:
                        continue
                    name, qualified_name, file_path, start_line, end_line = row[:5]
                    if not name:
                        continue

                    func_info = {
                        'name': name,
                        'qualified_name': qualified_name,
                        'use_file': '',
                        'use_line': 0,
                        'file_path': file_path,
                        'start_line': int(start_line) if start_line else 0,
                        'end_line': int(end_line) if end_line else 0,
                    }

                    if name not in self._functions_cache:
                        self._functions_cache[name] = []
                    self._functions_cache[name].append(func_info)

            logging.debug(f"[SymbolLookup] Loaded {len(self._functions_cache)} functions (simple) from CSV")
        except Exception as e:
            logging.error(f"Error loading function CSV: {e}")

    def get_function(self, function_name: str, file_path: str = None, line: int = None,
                     less_strict: bool = False) -> Optional[Dict]:
        """
        Get function definition by name, optionally using call site for precise lookup.

        Args:
            function_name: Function name (simple like "bad" or qualified like "MyClass::bad")
            file_path: Optional file path where function is called (for use-def lookup)
            line: Optional line number where function is called (for use-def lookup)
            less_strict: If True, use partial matching

        Returns:
            Dict with function info and code, or None if not found
        """
        self._load_functions_cache()

        # Extract simple name from qualified name
        simple_name = function_name.split("::")[-1]

        # If file_path and line provided, try precise use-def lookup first
        if file_path and line and self._functions_by_call:
            call_key = (os.path.basename(file_path), line)
            if call_key in self._functions_by_call:
                for func in self._functions_by_call[call_key]:
                    if func['name'] == simple_name:
                        return self._add_code_to_result(func)

        candidates = []

        # Find all matching functions by name
        if simple_name in self._functions_cache:
            for func in self._functions_cache[simple_name]:
                # If qualified name provided, match it
                if "::" in function_name:
                    if func['qualified_name'] == function_name or func['qualified_name'].endswith(function_name):
                        candidates.append(func)
                else:
                    candidates.append(func)

        # No partial/substring matching - only exact match on name or qualified_name
        # This prevents "connect_socket" from matching class names like
        # "CWE23_Relative_Path_Traversal__char_connect_socket_fopen_81_bad"

        if not candidates:
            return None

        # If file_path provided, filter by file (for definition location)
        if file_path:
            file_basename = os.path.basename(file_path)
            filtered = []
            for func in candidates:
                func_basename = os.path.basename(func['file_path'])
                use_basename = os.path.basename(func.get('use_file', ''))
                if (func_basename == file_basename or
                    use_basename == file_basename or
                    func['file_path'].endswith(file_path) or
                    file_path.endswith(func['file_path'])):
                    filtered.append(func)
            if filtered:
                candidates = filtered

        # Return first match
        return self._add_code_to_result(candidates[0]) if candidates else None

    def _build_basename_index(self):
        """Build a basename -> [func_info] index for fast location lookups."""
        self._functions_by_basename = {}
        for name, funcs in self._functions_cache.items():
            for func in funcs:
                basename = os.path.basename(func['file_path'])
                if basename not in self._functions_by_basename:
                    self._functions_by_basename[basename] = []
                self._functions_by_basename[basename].append(func)

    def get_function_by_location(self, file_path: str, line: int) -> Optional[Dict]:
        """
        Get function definition by file path and line number (within definition).

        Args:
            file_path: File path containing the function
            line: Line number within the function definition

        Returns:
            Dict with function info and code, or None if not found
        """
        self._load_functions_cache()

        # Build basename index on first call
        if self._functions_by_basename is None:
            self._build_basename_index()

        file_basename = os.path.basename(file_path)
        candidates = self._functions_by_basename.get(file_basename, [])

        # Candidates already share the same basename.
        # Check line range; if multiple files share a basename, path suffix match breaks ties.
        for func in candidates:
            if func['start_line'] <= line <= func['end_line']:
                if (func['file_path'].endswith(file_path) or
                    file_path.endswith(func['file_path'])):
                    return self._add_code_to_result(func)

        # Fallback: basename matched + line range matched (different path representations)
        for func in candidates:
            if func['start_line'] <= line <= func['end_line']:
                return self._add_code_to_result(func)

        return None

    def get_function_code_by_location(self, file_path: str, line: int) -> Optional[str]:
        """
        Get function source code by file path and line number.

        Args:
            file_path: File path containing the function
            line: Line number within the function definition

        Returns:
            Function source code string, or None if not found
        """
        result = self.get_function_by_location(file_path, line)
        return result.get('functionBody') if result else None

    def get_function_qname_by_location(self, file_path: str, line: int) -> Optional[str]:
        """
        Get function qualified name by file path and line number.

        Args:
            file_path: File path containing the function
            line: Line number within the function definition

        Returns:
            Function qualified name string, or None if not found
        """
        result = self.get_function_by_location(file_path, line)
        return result.get('qualified_name') if result else None

    def get_function_start_line(self, function_name: str, file_path: str) -> Optional[int]:
        """
        Get the start line for a function.

        Args:
            function_name: Qualified name of the function (e.g., "CWE23_xxx::goodG2B")
            file_path: Path to the file containing the function

        Returns:
            Start line number or None if not found
        """
        self._load_functions_cache()

        file_basename = os.path.basename(file_path)
        normalized_path = os.path.normpath(file_path)

        # Extract simple name for matching
        simple_name = function_name.split("::")[-1]

        # Search all functions
        for name, funcs in self._functions_cache.items():
            for func in funcs:
                func_basename = os.path.basename(func['file_path'])
                func_path = os.path.normpath(func['file_path'])

                # Check file match
                if not (func_basename == file_basename or
                        func_path.endswith(normalized_path) or
                        normalized_path.endswith(func_path)):
                    continue

                # Check name match - support both simple and qualified names
                qname = func.get('qualified_name', '')
                if qname == function_name or qname.endswith(function_name) or name == simple_name:
                    return func['start_line']

        logging.debug(f"[SymbolLookup] Function {function_name} not found in {file_path}")
        return None

    def get_function_info(self, function_name: str, file_path: str) -> Optional[Tuple[str, int, int]]:
        """
        Get full function information (name, start_line, end_line).

        Args:
            function_name: Qualified name of the function
            file_path: Path to the file containing the function

        Returns:
            Tuple of (qualified_name, start_line, end_line) or None if not found
        """
        self._load_functions_cache()

        file_basename = os.path.basename(file_path)
        normalized_path = os.path.normpath(file_path)
        simple_name = function_name.split("::")[-1]

        for name, funcs in self._functions_cache.items():
            for func in funcs:
                func_basename = os.path.basename(func['file_path'])
                func_path = os.path.normpath(func['file_path'])

                if not (func_basename == file_basename or
                        func_path.endswith(normalized_path) or
                        normalized_path.endswith(func_path)):
                    continue

                qname = func.get('qualified_name', '')
                if qname == function_name or qname.endswith(function_name) or name == simple_name:
                    return (qname, func['start_line'], func['end_line'])

        return None

    def lookup_by_qualified_name(self, qualified_name: str, file_path: str) -> Optional[Tuple[str, int]]:
        """
        Lookup function by qualified name and file path.
        Used for CFG cache key generation.

        Args:
            qualified_name: Qualified function name (e.g., "CWE23_xxx::bad")
            file_path: File path from SARIF

        Returns:
            Tuple of (qualified_name, start_line) or None if not found
        """
        self._load_functions_cache()

        # Build basename index on first call (reuse same index as get_function_by_location)
        if self._functions_by_basename is None:
            self._build_basename_index()

        file_basename = os.path.basename(file_path)
        candidates = self._functions_by_basename.get(file_basename, [])

        for func in candidates:
            qname = func.get('qualified_name', '')
            if qname == qualified_name:
                return (qname, func['start_line'])

        logging.debug(f"[SymbolLookup] NO MATCH: '{qualified_name}' in '{file_path}'")
        return None

    def get_functions_in_file(self, file_path: str) -> List[Dict]:
        """
        Get all functions defined in a file.

        Args:
            file_path: Path to the file

        Returns:
            List of function info dicts
        """
        self._load_functions_cache()

        file_basename = os.path.basename(file_path)
        normalized_path = os.path.normpath(file_path)
        results = []

        for name, funcs in self._functions_cache.items():
            for func in funcs:
                func_basename = os.path.basename(func['file_path'])
                func_path = os.path.normpath(func['file_path'])

                if (func_basename == file_basename or
                    func_path.endswith(normalized_path) or
                    normalized_path.endswith(func_path)):
                    results.append(func)

        return results

    # =========================================================================
    # Macro Lookup (Use-Def based)
    # =========================================================================

    def _load_macros_cache(self):
        """Load macro use-def CSV into memory cache."""
        if self._macros_cache is not None:
            return

        self._macros_cache = {}
        self._macros_by_use = {}  # Index by (use_file, use_line) for precise lookup

        # Try use-def CSV first, fall back to simple macros CSV
        csv_file = self._find_csv_file('*_macro_use_def.csv')
        if csv_file:
            self._load_macro_use_def_csv(csv_file)
        else:
            csv_file = self._find_csv_file('*_macros.csv')
            if csv_file:
                self._load_simple_macros_csv(csv_file)
            else:
                logging.debug("No macros CSV found")

    def _load_macro_use_def_csv(self, csv_file: str):
        """Load macro use-def CSV (6 columns: name, use_file, use_line, def_file, def_line, body)."""
        try:
            with open(csv_file, 'r') as f:
                reader = csv.reader(f)
                next(reader, None)  # Skip header
                for row in reader:
                    if len(row) < 6:
                        continue
                    name, use_file, use_line, def_file, def_line, body = row[:6]
                    if not name:  # Skip empty names
                        continue

                    macro_info = {
                        'name': name,
                        'body': body,
                        'use_file': use_file,
                        'use_line': int(use_line) if use_line else 0,
                        'def_file': def_file,
                        'def_line': int(def_line) if def_line else 0,
                    }

                    # Index by name
                    if name not in self._macros_cache:
                        self._macros_cache[name] = []
                    self._macros_cache[name].append(macro_info)

                    # Index by use location for precise lookup
                    use_key = (os.path.basename(use_file), int(use_line) if use_line else 0)
                    if use_key not in self._macros_by_use:
                        self._macros_by_use[use_key] = []
                    self._macros_by_use[use_key].append(macro_info)

            logging.debug(f"[SymbolLookup] Loaded {len(self._macros_cache)} macros (use-def) from CSV")
        except Exception as e:
            logging.error(f"Error loading macro use-def CSV: {e}")

    def _load_simple_macros_csv(self, csv_file: str):
        """Load simple macros CSV (5 columns: name, body, file_path, start_line, end_line)."""
        try:
            with open(csv_file, 'r') as f:
                reader = csv.reader(f)
                next(reader, None)  # Skip header
                for row in reader:
                    if len(row) < 5:
                        continue
                    name, body, file_path, start_line, end_line = row[:5]
                    if not name:
                        continue

                    macro_info = {
                        'name': name,
                        'body': body,
                        'use_file': '',
                        'use_line': 0,
                        'def_file': file_path,
                        'def_line': int(start_line) if start_line else 0,
                    }

                    if name not in self._macros_cache:
                        self._macros_cache[name] = []
                    self._macros_cache[name].append(macro_info)

            logging.debug(f"[SymbolLookup] Loaded {len(self._macros_cache)} macros (simple) from CSV")
        except Exception as e:
            logging.error(f"Error loading macros CSV: {e}")

    def get_macro(self, macro_name: str, file_path: str = None, line: int = None,
                  less_strict: bool = False) -> Optional[Dict]:
        """
        Get macro definition by name, optionally filtered by use location.

        Args:
            macro_name: Macro name
            file_path: Optional file path where macro is used (for precise lookup)
            line: Optional line number where macro is used
            less_strict: If True, use partial matching

        Returns:
            Dict with macro info, or None if not found
        """
        self._load_macros_cache()

        # If file_path and line provided, try precise lookup first
        if file_path and line and self._macros_by_use:
            use_key = (os.path.basename(file_path), line)
            if use_key in self._macros_by_use:
                for macro in self._macros_by_use[use_key]:
                    if macro['name'] == macro_name:
                        return self._format_macro_result(macro)

        # Exact match by name
        if macro_name in self._macros_cache:
            # If file_path provided, try to find matching definition
            if file_path:
                file_basename = os.path.basename(file_path)
                for macro in self._macros_cache[macro_name]:
                    def_basename = os.path.basename(macro['def_file'])
                    use_basename = os.path.basename(macro.get('use_file', ''))
                    if def_basename == file_basename or use_basename == file_basename:
                        return self._format_macro_result(macro)
            # Return first match
            return self._format_macro_result(self._macros_cache[macro_name][0])

        # No partial/substring matching - only exact match on macro name

        return None

    def _format_macro_result(self, macro: Dict) -> Dict:
        """Format macro info for output."""
        return {
            'name': macro['name'],
            'body': macro['body'],
            'file_path': macro['def_file'],
            'def_file': macro['def_file'],  # Also include def_file for directory matching
            'start_line': macro['def_line'],
            'end_line': macro['def_line'],
            'functionBody': f"File Path: {macro['def_file']}\n{macro['body']}"
        }

    def get_all_macros_by_name(self, macro_name: str) -> List[Dict]:
        """
        Get all macro definitions matching name (for fallback with directory preference).

        Args:
            macro_name: Macro name to look up

        Returns:
            List of macro info dicts for all definitions with this name
        """
        self._load_macros_cache()
        if macro_name not in self._macros_cache:
            return []
        return [self._format_macro_result(m) for m in self._macros_cache[macro_name]]

    def get_macros_at_location(self, file_path: str, line: int) -> List[Dict]:
        """
        Get all macros used at a specific location using use-def relationship.

        Args:
            file_path: File path where macros are used
            line: Line number where macros are used

        Returns:
            List of macro info dicts for all macros used at this location
        """
        self._load_macros_cache()

        if not self._macros_by_use:
            return []

        # Look up by (basename, line)
        use_key = (os.path.basename(file_path), line)
        if use_key not in self._macros_by_use:
            return []

        # Return all macros at this location (deduplicated by name)
        seen_names = set()
        results = []
        for macro in self._macros_by_use[use_key]:
            if macro['name'] not in seen_names:
                seen_names.add(macro['name'])
                results.append(self._format_macro_result(macro))

        return results

    # =========================================================================
    # Global Variable Lookup
    # =========================================================================

    def _load_globalvars_cache(self):
        """Load global variables CSV into memory cache."""
        if self._globalvars_cache is not None:
            return

        self._globalvars_cache = {}
        csv_file = self._find_csv_file('*_globalvars.csv')
        if not csv_file:
            logging.debug("GlobalVars CSV not found")
            return

        try:
            with open(csv_file, 'r') as f:
                reader = csv.reader(f)
                next(reader, None)  # Skip header
                for row in reader:
                    if len(row) < 6:
                        continue
                    name, qualified_name, var_type, file_path, start_line, end_line = row[:6]
                    if name not in self._globalvars_cache:
                        self._globalvars_cache[name] = []
                    self._globalvars_cache[name].append({
                        'name': name,
                        'qualified_name': qualified_name,
                        'type': var_type,
                        'file_path': file_path,
                        'start_line': int(start_line),
                        'end_line': int(end_line)
                    })
            logging.debug(f"[SymbolLookup] Loaded {len(self._globalvars_cache)} global variables from CSV")
        except Exception as e:
            logging.error(f"Error loading globalvars CSV: {e}")

    def get_global_var(self, var_name: str, less_strict: bool = False) -> Optional[Dict]:
        """
        Get global variable definition by name.

        Args:
            var_name: Variable name (can be qualified)
            less_strict: If True, use partial matching

        Returns:
            Dict with variable info and code, or None if not found
        """
        self._load_globalvars_cache()

        simple_name = var_name.split("::")[-1]

        # Exact match
        if simple_name in self._globalvars_cache:
            return self._add_code_to_result(self._globalvars_cache[simple_name][0])

        # No partial/substring matching - only exact match on variable name

        return None

    # =========================================================================
    # Class/Struct Lookup
    # =========================================================================

    def _load_classes_cache(self):
        """Load classes CSV into memory cache."""
        if self._classes_cache is not None:
            return

        self._classes_cache = {}
        csv_file = self._find_csv_file('*_classes.csv')
        if not csv_file:
            logging.debug("Classes CSV not found")
            return

        try:
            with open(csv_file, 'r') as f:
                reader = csv.reader(f)
                next(reader, None)  # Skip header
                for row in reader:
                    if len(row) < 5:
                        continue
                    name, qualified_name, file_path, start_line, end_line = row[:5]
                    if name not in self._classes_cache:
                        self._classes_cache[name] = []
                    self._classes_cache[name].append({
                        'name': name,
                        'qualified_name': qualified_name,
                        'file_path': file_path,
                        'start_line': int(start_line),
                        'end_line': int(end_line)
                    })
            logging.debug(f"[SymbolLookup] Loaded {len(self._classes_cache)} classes from CSV")
        except Exception as e:
            logging.error(f"Error loading classes CSV: {e}")

    def get_class(self, class_name: str, less_strict: bool = False) -> Optional[Dict]:
        """
        Get class/struct definition by name.

        Args:
            class_name: Class name (can be qualified)
            less_strict: If True, use partial matching

        Returns:
            Dict with class info and code, or None if not found
        """
        self._load_classes_cache()

        simple_name = class_name.split("::")[-1]

        # Exact match
        if simple_name in self._classes_cache:
            return self._add_code_to_result(self._classes_cache[simple_name][0])

        # No partial/substring matching - only exact match on class name

        return None

    # =========================================================================
    # Unified Symbol Query
    # =========================================================================

    def query_definition(self, symbol_name: str) -> List[Dict]:
        """
        Query definition of any symbol type (function, macro, global var, class).
        Tries all symbol types and returns matches.

        Args:
            symbol_name: Symbol name to search for

        Returns:
            List of matching symbol definitions
        """
        results = []

        # Try function first (most common)
        func = self.get_function(symbol_name)
        if func:
            results.append(func)
            return results

        # Try macro
        macro = self.get_macro(symbol_name)
        if macro:
            results.append(macro)
            return results

        # Try global variable
        gvar = self.get_global_var(symbol_name)
        if gvar:
            results.append(gvar)
            return results

        # Try class
        cls = self.get_class(symbol_name)
        if cls:
            results.append(cls)
            return results

        # No partial/substring matching - only exact match on symbol name
        return results

    # =========================================================================
    # Helper Methods
    # =========================================================================

    def _add_code_to_result(self, symbol_info: Dict) -> Dict:
        """Add source code to symbol info dict."""
        file_path = symbol_info.get('file_path', '')
        start_line = symbol_info.get('start_line', 0)
        end_line = symbol_info.get('end_line', 0)

        code = self._read_code(file_path, start_line, end_line)
        if code:
            symbol_info['functionBody'] = code

        return symbol_info

    def _resolve_source_path(self, file_path: str) -> Optional[str]:
        """
        Resolve CSV file path to actual source file path.

        Handles various path formats:
        - Docker paths: /results/ai-analysis/sourcecode/project/src/file.c
        - Absolute paths: /path/to/source/file.c
        - Relative paths: src/main.c
        """
        candidates = []

        # Strategy 1: Direct join with source_path
        relative_path = file_path.lstrip('/')
        candidates.append(os.path.join(self.source_path, relative_path))

        # Strategy 2: Strip Docker-style prefixes
        docker_prefixes = [
            '/results/ai-analysis/sourcecode/',
            '/results/ai-analysis/',
            '/results/',
        ]
        for prefix in docker_prefixes:
            if file_path.startswith(prefix):
                stripped = file_path[len(prefix):]
                # Try with and without leading path components
                candidates.append(os.path.join(self.source_path, stripped))
                candidates.append('/' + stripped)  # Absolute path after strip

        # Strategy 3: Find file by basename in source_path
        basename = os.path.basename(file_path)
        # Try to find the file - this is expensive so only as last resort

        # Strategy 4: Try matching end of path with source_path structure
        # E.g., if file_path ends with "pngread.c" and source_path/.../pngread.c exists
        path_parts = file_path.split('/')
        for i in range(len(path_parts)):
            partial = '/'.join(path_parts[i:])
            if partial:
                candidates.append(os.path.join(self.source_path, partial))

        # Return first existing path
        for candidate in candidates:
            if os.path.exists(candidate):
                return candidate

        return None

    def _read_code(self, file_path: str, start_line: int, end_line: int) -> Optional[str]:
        """Read source code from file."""
        original_path = file_path

        # Try direct path first
        if os.path.exists(file_path):
            pass  # Use as-is
        elif self.source_path:
            # Try multiple path resolution strategies
            resolved = self._resolve_source_path(file_path)
            if resolved:
                file_path = resolved
            else:
                return None
        else:
            return None

        if not os.path.exists(file_path):
            return None

        try:
            if file_path not in self._file_cache:
                with open(file_path, 'r', errors='replace') as f:
                    self._file_cache[file_path] = f.readlines()

            lines = self._file_cache[file_path]
            code_lines = lines[start_line - 1:end_line]
            numbered_lines = [
                f"{i + start_line}: {line}"
                for i, line in enumerate(code_lines)
            ]
            return f"File Path: {file_path}\n" + "".join(numbered_lines)
        except Exception as e:
            logging.error(f"Error reading file {file_path}: {e}")
            return None


# Singleton instance for easy access
_symbol_lookup_instance: Optional[SymbolLookup] = None


def get_symbol_lookup() -> SymbolLookup:
    """Get or create singleton SymbolLookup instance."""
    global _symbol_lookup_instance
    if _symbol_lookup_instance is None:
        _symbol_lookup_instance = SymbolLookup()
    return _symbol_lookup_instance


def query_symbol_definition(symbol: str, port=8080) -> List[Dict]:
    """
    Query symbol definition - drop-in replacement for OpenGrok-based query.

    Args:
        symbol: Symbol name to search for
        port: Ignored (kept for API compatibility)

    Returns:
        List of matching symbol definitions
    """
    try:
        lookup = get_symbol_lookup()
        return lookup.query_definition(symbol)
    except Exception as e:
        logging.error(f"Error querying symbol {symbol}: {e}")
        return []


def get_function_start_line_from_csv(function_name: str, file_path: str) -> Optional[int]:
    """
    Convenience function to get function start line.
    Drop-in replacement for function_csv_reader.get_function_start_line_from_csv.

    Args:
        function_name: Name of the function
        file_path: Path to the file containing the function

    Returns:
        Start line number or None if not found
    """
    lookup = get_symbol_lookup()
    return lookup.get_function_start_line(function_name, file_path)
