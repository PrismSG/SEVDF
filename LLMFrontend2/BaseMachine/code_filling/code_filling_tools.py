"""
Code Filling Tools - Symbol lookup tools for LLM function calling.

Provides separate tools for different symbol types:
- get_function_definition: Look up function implementations
- get_macro_definition: Look up macro definitions
- get_global_var_definition: Look up global variable definitions
- get_class_definition: Look up class/struct definitions

Auto-extracts use-site information from machine context for precise lookup.
"""

import os
import sys
import re
import logging
import ctypes
import ctypes.util
from typing import List, Tuple, Optional, Any, Dict

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(current_dir, '../../AdvancedTools/CodeSearch'))
sys.path.append(parent_dir)

from AdvancedTools.CodeSearch.symbol_lookup import get_symbol_lookup, query_symbol_definition


# =============================================================================
# Dynamic C Library Function Detection (using ctypes)
# =============================================================================

# Load system libraries once at module level (lazy initialization)
_libc = None
_libm = None
_libs_loaded = False


def _load_system_libraries():
    """Load libc and libm for function lookup (lazy loading)."""
    global _libc, _libm, _libs_loaded
    if _libs_loaded:
        return
    _libs_loaded = True

    try:
        libc_path = ctypes.util.find_library('c')
        if libc_path:
            _libc = ctypes.CDLL(libc_path)
    except Exception:
        pass

    try:
        libm_path = ctypes.util.find_library('m')
        if libm_path:
            _libm = ctypes.CDLL(libm_path)
    except Exception:
        pass


def _is_common_library_function(function_name: str) -> bool:
    """Check if a function is a C/C++ library function using ctypes."""
    # Check common prefixes that indicate library/compiler functions
    lib_prefixes = ('__builtin_', '__libc_', '_IO_', '__cxa_', 'std::')
    if any(function_name.startswith(p) for p in lib_prefixes):
        return True

    # Load libraries if not already loaded
    _load_system_libraries()

    # Check libc
    if _libc:
        try:
            getattr(_libc, function_name)
            return True
        except AttributeError:
            pass

    # Check libm (math functions)
    if _libm:
        try:
            getattr(_libm, function_name)
            return True
        except AttributeError:
            pass

    return False


# =============================================================================
# Tool Definitions (Simplified - no file_path/line needed from LLM)
# =============================================================================

GET_FUNCTION_DEFINITION_TOOL = {
    "type": "function",
    "function": {
        "name": "get_function_definition",
        "description": "Look up a C/C++ function definition by its name. "
                       "CRITICAL: When you see a function call in the provided code (e.g., 'result = someFunction(arg)'), you MUST use this tool to look up the function's definition BEFORE concluding the definition is 'not visible' or 'unavailable'. "
                       "Only if this tool returns 'NOT FOUND' can you say the function definition is unavailable. "
                       "Use this for any function you see called in the code context - the system has access to definitions across the entire codebase. "
                       "Functions typically use camelCase or snake_case naming. "
                       "WRONG: Do NOT pass file paths (*.cpp, *.c, *.h) or preprocessor macros (ALL_CAPS identifiers) - use get_macro_definition for macros.",
        "parameters": {
            "type": "object",
            "properties": {
                "function_name": {
                    "type": "string",
                    "description": "Function identifier only. Can be simple name or qualified (e.g., 'ClassName::method'). NOT a file path, NOT an ALL_CAPS macro."
                }
            },
            "required": ["function_name"]
        }
    }
}

GET_MACRO_DEFINITION_TOOL = {
    "type": "function",
    "function": {
        "name": "get_macro_definition",
        "description": "Look up a C/C++ preprocessor macro (#define). Use this for identifiers that are ALL_CAPS - these are typically macros. "
                       "Macros are defined with #define and expanded at compile time. For actual functions with code bodies, use get_function_definition instead.",
        "parameters": {
            "type": "object",
            "properties": {
                "macro_name": {
                    "type": "string",
                    "description": "Macro identifier only. Macros are typically ALL_CAPS (e.g., MAX_SIZE, DEFAULT_PATH). Just the name, not a file path."
                }
            },
            "required": ["macro_name"]
        }
    }
}

GET_GLOBAL_VAR_DEFINITION_TOOL = {
    "type": "function",
    "function": {
        "name": "get_global_var_definition",
        "description": "Look up a C/C++ global variable declaration. Use this for variables declared at file scope (outside any function). "
                       "Do NOT use for local variables, function parameters, or macros.",
        "parameters": {
            "type": "object",
            "properties": {
                "var_name": {
                    "type": "string",
                    "description": "Global variable identifier only. Must be a valid C/C++ identifier, not a file path."
                }
            },
            "required": ["var_name"]
        }
    }
}

GET_CLASS_DEFINITION_TOOL = {
    "type": "function",
    "function": {
        "name": "get_class_definition",
        "description": "Look up a C/C++ class or struct definition. Use this to see the full declaration including member variables and methods. "
                       "Do NOT use for functions (use get_function_definition) or standard library types.",
        "parameters": {
            "type": "object",
            "properties": {
                "class_name": {
                    "type": "string",
                    "description": "Class or struct identifier only. Must be a valid C/C++ type name, not a file path."
                }
            },
            "required": ["class_name"]
        }
    }
}

# All tools for easy registration
ALL_SYMBOL_TOOLS = [
    GET_FUNCTION_DEFINITION_TOOL,
    GET_MACRO_DEFINITION_TOOL,
    # TEMPORARILY DISABLED: get_global_var_definition always returns NOT FOUND (empty CSV)
    # GET_GLOBAL_VAR_DEFINITION_TOOL,
    GET_CLASS_DEFINITION_TOOL,
]


# =============================================================================
# Tool Executors
# =============================================================================

def _validate_symbol_name(name):
    """Validate symbol name format."""
    if not name:
        return False, "Symbol name is required"

    # Check for common mistakes and give helpful error messages
    if name.endswith(('.cpp', '.c', '.h', '.hpp', '.cc', '.cxx')):
        return False, f"'{name}' appears to be a file path, not a symbol name. Use just the function/macro name without file extension."

    if '/' in name or '\\' in name:
        return False, f"'{name}' contains path separators. Use just the symbol name without file path."

    # Allow qualified names like MyClass::method or namespace::func
    # Pattern: identifier (:: identifier)*
    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*(::[a-zA-Z_][a-zA-Z0-9_]*)*$', name):
        return False, f"Invalid symbol name '{name}'. Must be a valid C/C++ identifier (letters, digits, underscores only)."
    return True, None


def _format_result(symbol_name, result):
    """Format lookup result in relatedCode style with file path and line numbers."""
    if not result:
        return None

    file_path = result.get('file_path', 'unknown')
    start_line = result.get('start_line', 1)
    code = result.get('functionBody', '')

    if not code:
        return f"[NOT FOUND] No code body for {symbol_name}"

    # Format with line numbers like relatedCode
    lines = []
    lines.append(f"File Path: {file_path}")
    for i, line in enumerate(code.split('\n')):
        lines.append(f"{start_line + i}: {line}")

    return '\n'.join(lines)


def _add_to_definition_pool(machine, file_path: str, start_line: int, end_line: int, code: str):
    """
    Add a fetched definition to the machine's definition pool for subsequent use-def lookups.

    Args:
        machine: The state machine instance
        file_path: Path to the source file
        start_line: Start line of the definition
        end_line: End line of the definition
        code: The source code of the definition
    """
    if machine is None:
        return

    # Initialize pool on first use (dynamic field, like other machine attributes)
    if not hasattr(machine, 'definition_pool'):
        machine.definition_pool = []

    machine.definition_pool.append({
        'file_path': file_path,
        'start_line': start_line,
        'end_line': end_line,
        'code': code
    })


def _extract_use_sites_from_context(machine, symbol_name: str) -> List[Tuple[str, int]]:
    """
    Extract potential use sites (file_path, line) from machine context.

    Searches through context.steps AND fetched definitions pool to find
    where the symbol might be used, based on the relatedCode and line numbers.

    Uses word boundary matching to avoid false matches like:
    - "bad" matching "badData" (variable name)
    - "CWE191_..._bad" matching "CWE191_..._badData"

    Args:
        machine: The state machine with context
        symbol_name: The symbol to find use sites for

    Returns:
        List of (file_path, line) tuples where the symbol might be used
    """
    import re

    use_sites = []

    if machine is None:
        return use_sites

    context = getattr(machine, 'context', None)
    if context is None:
        return use_sites

    # Extract simple name for pattern matching
    simple_name = symbol_name.split('::')[-1]

    # Create regex pattern for word boundary matching
    # Match function/macro calls: symbol_name(
    # This avoids matching "bad" in "badData"
    call_pattern = rf'\b{re.escape(simple_name)}\s*\('

    # Search in context.steps
    steps = getattr(context, 'steps', None)
    if steps:
        try:
            for step in steps:
                # Check fromPoint
                from_point = getattr(step, 'fromPoint', None)
                if from_point:
                    file_path = getattr(from_point, 'file', '')
                    line = getattr(from_point, 'line', 0)
                    related_code = getattr(from_point, 'relatedCode', '') or getattr(step, 'relatedCode', '')

                    # Check if symbol appears as a function/macro call
                    if file_path and line and re.search(call_pattern, related_code):
                        use_sites.append((file_path, line))

                # Check toPoint
                to_point = getattr(step, 'toPoint', None)
                if to_point:
                    file_path = getattr(to_point, 'file', '')
                    line = getattr(to_point, 'line', 0)
                    related_code = getattr(to_point, 'relatedCode', '') or getattr(step, 'relatedCode', '')

                    if file_path and line and re.search(call_pattern, related_code):
                        use_sites.append((file_path, line))
        except Exception as e:
            logging.debug(f"Error extracting use sites from steps: {e}")

    # Search in fetched definitions pool (dynamic field, created on first use)
    definition_pool = getattr(machine, 'definition_pool', [])
    for definition in definition_pool:
        code = definition.get('code', '')
        # Use pattern matching for definition pool as well
        if re.search(call_pattern, code):
            file_path = definition.get('file_path', '')
            start_line = definition.get('start_line', 0)
            end_line = definition.get('end_line', 0)

            # Find the specific line where symbol appears
            if file_path and code:
                code_lines = code.split('\n')
                for i, line_content in enumerate(code_lines):
                    if re.search(call_pattern, line_content):
                        line_num = start_line + i
                        if line_num <= end_line:
                            use_sites.append((file_path, line_num))

    # Deduplicate while preserving order
    seen = set()
    unique_sites = []
    for site in use_sites:
        if site not in seen:
            seen.add(site)
            unique_sites.append(site)

    return unique_sites


def _macro_fallback_lookup(macro_name: str, machine) -> Optional[Dict]:
    """
    Fallback lookup for macros when use-def chain is incomplete.
    Prefers definitions from same directory as context files.

    Args:
        macro_name: The macro name to look up
        machine: The state machine with context

    Returns:
        Macro info dict, or None if not found
    """
    lookup = get_symbol_lookup()
    results = lookup.get_all_macros_by_name(macro_name)
    if not results:
        return None

    if len(results) == 1:
        result = results[0]
        result['_lookup_method'] = 'fallback'
        return result

    # Extract context directories for preference
    context_dirs = set()
    if machine and hasattr(machine, 'context'):
        for step in getattr(machine.context, 'steps', []):
            for point in ['fromPoint', 'toPoint']:
                if point in step:
                    file_path = step[point].get('physicalLocation', {}).get('artifactLocation', {}).get('uri', '')
                    if file_path:
                        context_dirs.add(os.path.dirname(file_path))

    # Prefer definition from same directory
    for macro in results:
        def_dir = os.path.dirname(macro.get('def_file', '') or macro.get('file_path', ''))
        if def_dir in context_dirs:
            macro['_lookup_method'] = 'fallback-directory-matched'
            return macro

    # Return first match with warning
    results[0]['_lookup_method'] = 'fallback'
    logging.debug(f"[SymbolLookup] Multiple definitions for '{macro_name}', returning first match")
    return results[0]


def _lookup_with_context(lookup_func, symbol_name: str, machine, less_strict: bool = False, symbol_type: str = 'function'):
    """
    Try to lookup symbol using context-extracted use sites first, then fallback.

    Args:
        lookup_func: The lookup function (get_function or get_macro)
        symbol_name: The symbol to look up
        machine: The state machine with context
        less_strict: Whether to use less strict matching
        symbol_type: Type of symbol ('function' or 'macro') - fallback only enabled for macros

    Returns:
        Tuple of (result, lookup_method) where lookup_method is 'use-def' or 'fallback'
    """
    # First try: use context-extracted use sites for precise lookup
    use_sites = _extract_use_sites_from_context(machine, symbol_name)

    if use_sites:
        for file_path, line in use_sites:
            result = lookup_func(symbol_name, file_path=file_path, line=line, less_strict=less_strict)
            if result:
                # Check if this is truly a use-def match
                # Use-def CSV results have use_file and use_line fields
                if result.get('use_file') and result.get('use_line'):
                    # True use-def match: use the CSV's use_line, not our extracted line
                    result['_lookup_method'] = 'use-def'
                    result['_use_site'] = f"{os.path.basename(result['use_file'])}:{result['use_line']}"
                else:
                    # Fallback match: lookup_func found it by name, not by use site
                    result['_lookup_method'] = 'fallback'
                return result

    # Fallback: Only enabled for macros, not functions
    # This allows macro lookups to succeed even without complete use-def chain
    if symbol_type == 'macro':
        result = _macro_fallback_lookup(symbol_name, machine)
        if result:
            logging.debug(f"[SymbolLookup] Macro '{symbol_name}' found via fallback")
            return result

    # Return None if no use-def match found (functions require precise use-def matching)
    logging.debug(f"[SymbolLookup] No use site found in context for '{symbol_name}' ({symbol_type})")
    return None


def get_function_definition_tool_executor(args, machine=None):
    """Look up function definition using context-aware lookup."""
    function_name = args.get("function_name", "")

    valid, error = _validate_symbol_name(function_name)
    if not valid:
        logging.warning(f"[SymbolTool] get_function_definition: invalid name '{function_name}' - {error}")
        return f"Error: {error}"

    try:
        lookup = get_symbol_lookup()

        # Try context-aware lookup (exact match only - no partial/substring matching)
        result = _lookup_with_context(lookup.get_function, function_name, machine)

        if not result:
            # Check if it's a common library function
            if _is_common_library_function(function_name):
                logging.info(f"[SymbolTool] get_function_definition('{function_name}'): LIBRARY FUNCTION")
                return f"[LIBRARY] '{function_name}' is a standard C/C++ library function. Its implementation is provided by the system library (libc/libstdc++) and is not part of this codebase. You can assume standard behavior as documented."
            logging.info(f"[SymbolTool] get_function_definition('{function_name}'): NOT FOUND")
            return f"[NOT FOUND] Function '{function_name}' does not exist in the codebase. Do not retry this lookup."

        # Log success with lookup method info
        file_path = result.get('file_path', 'unknown')
        start_line = result.get('start_line', 0)
        end_line = result.get('end_line', 0)
        code = result.get('functionBody', '')
        lookup_method = result.pop('_lookup_method', 'unknown')
        use_site = result.pop('_use_site', None)

        if lookup_method == 'use-def' and use_site:
            logging.info(f"[SymbolTool] get_function_definition('{function_name}'): FOUND via use-def (use@{use_site}) -> def@{os.path.basename(file_path)}:{start_line}")
        else:
            logging.info(f"[SymbolTool] get_function_definition('{function_name}'): FOUND via fallback at {os.path.basename(file_path)}:{start_line}")

        # Add to definition pool for subsequent use-def lookups
        _add_to_definition_pool(machine, file_path, start_line, end_line, code)

        return _format_result(function_name, result)

    except Exception as e:
        logging.error(f"[SymbolTool] get_function_definition('{function_name}'): ERROR - {e}")
        return f"Error: {str(e)}"


def get_macro_definition_tool_executor(args, machine=None):
    """Look up macro definition using context-aware lookup."""
    macro_name = args.get("macro_name", "")

    valid, error = _validate_symbol_name(macro_name)
    if not valid:
        logging.warning(f"[SymbolTool] get_macro_definition: invalid name '{macro_name}' - {error}")
        return f"Error: {error}"

    try:
        lookup = get_symbol_lookup()

        # Try context-aware lookup with fallback enabled for macros
        result = _lookup_with_context(lookup.get_macro, macro_name, machine, symbol_type='macro')

        if not result:
            logging.info(f"[SymbolTool] get_macro_definition('{macro_name}'): NOT FOUND")
            return f"[NOT FOUND] Macro '{macro_name}' does not exist in the codebase. Do not retry this lookup."

        # Log success with lookup method info
        file_path = result.get('file_path', 'unknown')
        start_line = result.get('start_line', 0)
        end_line = result.get('end_line', 0)
        code = result.get('functionBody', '')
        body = result.get('body', '')[:40]
        lookup_method = result.pop('_lookup_method', 'unknown')
        use_site = result.pop('_use_site', None)

        if lookup_method == 'use-def' and use_site:
            logging.info(f"[SymbolTool] get_macro_definition('{macro_name}'): FOUND via use-def (use@{use_site}) -> {body}")
        else:
            logging.info(f"[SymbolTool] get_macro_definition('{macro_name}'): FOUND via fallback -> {body}")

        # Add to definition pool for subsequent use-def lookups
        _add_to_definition_pool(machine, file_path, start_line, end_line, code)

        return _format_result(macro_name, result)

    except Exception as e:
        logging.error(f"[SymbolTool] get_macro_definition('{macro_name}'): ERROR - {e}")
        return f"Error: {str(e)}"


def get_global_var_definition_tool_executor(args, machine=None):
    """Look up global variable definition."""
    var_name = args.get("var_name", "")

    valid, error = _validate_symbol_name(var_name)
    if not valid:
        logging.warning(f"[SymbolTool] get_global_var_definition: invalid name '{var_name}' - {error}")
        return f"Error: {error}"

    try:
        lookup = get_symbol_lookup()
        # Exact match only - no partial/substring matching
        result = lookup.get_global_var(var_name)

        if not result:
            logging.info(f"[SymbolTool] get_global_var_definition('{var_name}'): NOT FOUND")
            return f"[NOT FOUND] Global variable '{var_name}' does not exist in the codebase. Do not retry this lookup."

        file_path = result.get('file_path', 'unknown')
        start_line = result.get('start_line', '?')
        logging.info(f"[SymbolTool] get_global_var_definition('{var_name}'): FOUND at {file_path}:{start_line}")
        return _format_result(var_name, result)

    except Exception as e:
        logging.error(f"[SymbolTool] get_global_var_definition('{var_name}'): ERROR - {e}")
        return f"Error: {str(e)}"


def get_class_definition_tool_executor(args, machine=None):
    """Look up class/struct definition."""
    class_name = args.get("class_name", "")

    valid, error = _validate_symbol_name(class_name)
    if not valid:
        logging.warning(f"[SymbolTool] get_class_definition: invalid name '{class_name}' - {error}")
        return f"Error: {error}"

    try:
        lookup = get_symbol_lookup()
        # Exact match only - no partial/substring matching
        result = lookup.get_class(class_name)

        if not result:
            logging.info(f"[SymbolTool] get_class_definition('{class_name}'): NOT FOUND")
            return f"[NOT FOUND] Class/struct '{class_name}' does not exist in the codebase. Do not retry this lookup."

        file_path = result.get('file_path', 'unknown')
        start_line = result.get('start_line', '?')
        logging.info(f"[SymbolTool] get_class_definition('{class_name}'): FOUND at {file_path}:{start_line}")
        return _format_result(class_name, result)

    except Exception as e:
        logging.error(f"[SymbolTool] get_class_definition('{class_name}'): ERROR - {e}")
        return f"Error: {str(e)}"


# All executors for easy registration
ALL_SYMBOL_EXECUTORS = {
    "get_function_definition": get_function_definition_tool_executor,
    "get_macro_definition": get_macro_definition_tool_executor,
    # TEMPORARILY DISABLED: get_global_var_definition always returns NOT FOUND (empty CSV)
    # "get_global_var_definition": get_global_var_definition_tool_executor,
    "get_class_definition": get_class_definition_tool_executor,
}
