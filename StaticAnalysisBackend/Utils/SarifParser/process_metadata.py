import get_pathproblem_metadata as SarifPathParser
from AdvancedTools.CodeSearch.symbol_lookup import get_symbol_lookup
import os
import subprocess
from urllib.parse import urlparse
from pathlib import Path
import json
from collections import defaultdict
import numpy as np

def uniform_interval_sampling(infos_list, max_paths):
    """
    Sample evenly to the requested count while preserving the original order

    Args:
        infos_list: Original path list in CodeQL order
        max_paths: Maximum number of paths

    Returns:
        Sampled path list
    """
    original_count = len(infos_list)

    if original_count <= max_paths or max_paths <= 0:
        return infos_list

    # Use linspace to generate evenly spaced indices
    indices = np.linspace(0, original_count - 1, max_paths, dtype=int)
    sampled = [infos_list[i] for i in indices]

    print(f"[SAMPLING] Uniform interval sampling: {original_count} → {len(sampled)} paths")
    print(f"[SAMPLING] Sample indices: first={indices[0]}, last={indices[-1]}, interval≈{(indices[-1]-indices[0])/(len(indices)-1):.1f}")

    return sampled

ENABLE_KEYWORDS = False
# binutils 190
# KEYWORDS = [
#     "display_debug_frames",
#     "elf_object_p",
#     "pe_bfd_read_buildid",
#     "rewrite_elf_program_header",
#     "_bfd_coff_get_external_symbols",
#     "coff_get_normalized_symtab",
#     "_bfd_elf_get_symtab_upper_bound",
#     "_bfd_elf_get_dynamic_symtab_upper_bound",
#     "_bfd_elf_canonicalize_dynamic_symtab",
#     "_bfd_elf_get_dynamic_reloc_upper_bound",
#     "elf_i386_get_synthetic_symtab",
#     "elf_x86_64_get_synthetic_symtab",
#     "dump_relocs_in_section",
#     "process_version_sections",
#     "load_specific_debug_section",
#     "print_gnu_property_note",
#     "simple_object_elf_match",
#     "demangle_template"
# ]
# binutils 476
KEYWORDS = [
    "function_to_cve",
    "coff_slurp_reloc_table",
    "scan_unit_for_symbols",
    "elf_i386_get_synthetic_symtab",
    "elf_x86_64_get_synthetic_symtab",
    "bfd_mach_o_read_symtab_strtab",
    "nlm_swap_auxiliary_headers_in",
    "bfd_make_section_with_flags",
    "evax_bfd_print_emh",
    "read_formatted_entries",
    "setup_group",
    "concat_filename",
    "decode_line_info",
    "parse_comp_unit"   
]
# binutils 476
# KEYWORDS = [
#     "bfd_generic_archive_p"
# ]




# Metadata Extractor class
class Extractor:
    def __init__(self, sarif_file, function_csv, source_path):
        self.sarif_file = sarif_file
        self.function_csv = function_csv
        self.source_path = source_path
        # Add file cache to avoid reading the same file multiple times
        self.file_cache = {}

    def get_variable_from_file(self, file_path, start_line, start_column, end_column):
        # Properly resolve file path
        absolute_file_path = self.resolve_path(file_path)

        # Use cached file contents if available
        if absolute_file_path not in self.file_cache:
            try:
                with open(absolute_file_path, 'r') as file:
                    self.file_cache[absolute_file_path] = file.readlines()
            except Exception as e:
                print(f"Error reading file {absolute_file_path}: {e}")
                return ""

        try:
            lines = self.file_cache[absolute_file_path]
            code_line = lines[start_line - 1]  # note that the line number in the file starts from 1
            return code_line[start_column-1:end_column-1]
        except Exception as e:
            print(f"Error extracting variable from {absolute_file_path}:{start_line}: {e}")
            return ""
    
    def get_line_code(self, file_path, line):
        # Properly resolve file path
        absolute_file_path = self.resolve_path(file_path)

        # Use cached file contents if available
        if absolute_file_path not in self.file_cache:
            try:
                with open(absolute_file_path, 'r') as file:
                    self.file_cache[absolute_file_path] = file.readlines()
            except Exception as e:
                print(f"Error reading file {absolute_file_path}: {e}")
                return ""

        try:
            lines = self.file_cache[absolute_file_path]
            return lines[line - 1]
        except Exception as e:
            print(f"Error getting line code from {absolute_file_path}:{line}: {e}")
            return ""
    
    def clean_file_path(self, path):
        """
        Removes file: prefix from file paths if present.
        Only cleans paths that actually need cleaning.
        """
        if not path:
            return path
        
        clean_path = path
        
        # Handle file: prefix (URI format from SARIF)
        if clean_path.startswith('file:'):
            # Remove file: prefix
            clean_path = clean_path[5:]
            # Remove extra slashes if present (file:///path -> /path)
            while clean_path.startswith('//'):
                clean_path = clean_path[1:]
        
        # If it's just a filename without path, keep it as is
        # If it's a full path, keep it as is
        # We're not trying to remove any project prefixes anymore
        
        return clean_path
    
    def resolve_path(self, path):
        """
        Resolves the path by finding the file within source_path directory structure.

        Maintains a list of known prefixes sorted by hit count. On each call,
        tries prefixes in order (most frequently hit first). On miss, falls back
        to glob and learns the new prefix for future calls.
        """
        if not path:
            raise ValueError("Empty path provided")

        if not self.source_path:
            raise ValueError("Source path is not set")

        # Handle file: prefix by removing it
        if path.startswith('file:'):
            path = path[5:]
            if path and path[0] == '/':
                path = path[1:]

        clean_path = path
        source_path_obj = Path(self.source_path)

        # Initialize prefix list on first call: list of [prefix, hit_count]
        if not hasattr(self, '_prefix_entries'):
            self._prefix_entries = []

        # Fast path: try known prefixes in order (sorted by hit count descending)
        for entry in self._prefix_entries:
            resolved = source_path_obj / entry[0] / clean_path if entry[0] else source_path_obj / clean_path
            if resolved.exists():
                entry[1] += 1
                # Re-sort if this entry overtook the one above it
                self._prefix_entries.sort(key=lambda e: e[1], reverse=True)
                return str(resolved.absolute())

        # All known prefixes missed — try exact match (empty prefix)
        exact_match = source_path_obj / clean_path
        if exact_match.exists():
            self._add_prefix("")
            return str(exact_match.absolute())

        # Glob fallback
        potential_matches = list(source_path_obj.glob(f"**/{path}"))

        if not potential_matches:
            raise FileNotFoundError(f"File '{path}' not found in source directory '{self.source_path}'")

        if len(potential_matches) > 1:
            raise ValueError(f"Multiple matches found for '{path}'. Found: {[str(p) for p in potential_matches]}")

        resolved = potential_matches[0]

        # Extract and learn the new prefix
        rel_resolved = resolved.relative_to(source_path_obj)
        rel_str = str(rel_resolved)
        if rel_str.endswith(clean_path):
            prefix = rel_str[:-len(clean_path)].rstrip('/')
            self._add_prefix(prefix)

        return str(resolved.absolute())

    def _add_prefix(self, prefix):
        """Add a new prefix to the known list (or bump its count if already known)."""
        for entry in self._prefix_entries:
            if entry[0] == prefix:
                entry[1] += 1
                self._prefix_entries.sort(key=lambda e: e[1], reverse=True)
                return
        self._prefix_entries.append([prefix, 1])
        self._prefix_entries.sort(key=lambda e: e[1], reverse=True)
        display = f"'{prefix}'" if prefix else "(none - direct match)"
        print(f"[resolve_path] New source prefix learned: {display} (total: {len(self._prefix_entries)})", flush=True)

    def is_valid_flow_info(self, flow_info):
        """
        Validates that all fields in flow_info and its subfields are not None or empty strings.
        
        Args:
            flow_info: Dictionary containing flow information
            
        Returns:
            bool: True if all fields have valid values, False otherwise
        """
        # Fields that are optional and legitimately None
        OPTIONAL_FIELDS = {'semanticLabel'}

        # Check source fields
        source = flow_info.get("source", {})
        if not source:
            return False

        for key, value in source.items():
            if key in OPTIONAL_FIELDS:
                continue
            if value is None or value == "":
                return False

        # Check sink fields
        sink = flow_info.get("sink", {})
        if not sink:
            return False

        for key, value in sink.items():
            if key in OPTIONAL_FIELDS:
                continue
            if value is None or value == "":
                return False

        # Check path entries - path can be empty after filtering
        path = flow_info.get("path", [])
        # Path is allowed to be empty after filtering out locations with missing function names
        # But if there are entries, they should be valid
        for step in path:
            if not step:
                return False

            for key, value in step.items():
                if key in OPTIONAL_FIELDS:
                    continue
                if value is None or value == "":
                    return False
                    
        return True

    def format_info_as_json(self, flow_info):
        source = flow_info["source"]
        sink = flow_info["sink"]
        path = flow_info["path"]

        try:
            # Initialize the main JSON structure
            # Use pre-computed lineCode and variable from flow_info instead of recalculating
            main_result = {
                "source": {
                    "file_path": self.clean_file_path(source['file_path']),
                    "line": source['start_line'],
                    "lineCode": source.get('lineCode', ''),
                    "variable": source.get('variable', ''),
                    "semanticLabel": source.get('semanticLabel'),
                    "relatedCode": source['code'],
                    "functionName": source['function_name'],
                    "startColumn": source['start_column'],
                    "endColumn": source['end_column']
                },
                "propagation path": [],
                "sink": {
                "file_path": self.clean_file_path(sink['file_path']),
                "line": sink['start_line'],
                "lineCode": sink.get('lineCode', ''),
                "variable": sink.get('variable', ''),
                    "semanticLabel": sink.get('semanticLabel'),
                    "relatedCode": sink['code'],
                    "functionName": sink['function_name'],
                    "startColumn": sink['start_column'],
                    "endColumn": sink['end_column']
                }
            }

            # Populate the propagation path
            # Use pre-computed lineCode and variable from path instead of recalculating
            for index in range(len(path) - 1):
                loc = path[index]
                next_loc = path[index + 1]

                main_result["propagation path"].append({
                    "propagation step": index + 1,
                    "from": {
                        "file_path": self.clean_file_path(loc['file_path']),
                        "line": loc['start_line'],
                        "lineCode": loc.get('lineCode', ''),
                        "variable": loc.get('variable', ''),
                        "semanticLabel": loc.get('semanticLabel'),
                        "relatedCode": loc['code'],
                        "functionName": loc['function_name'],
                        "startColumn": loc['start_column'],
                        "endColumn": loc['end_column']
                    },
                    "to": {
                        "file_path": self.clean_file_path(next_loc['file_path']),
                        "line": next_loc['start_line'],
                        "lineCode": next_loc.get('lineCode', ''),
                        "variable": next_loc.get('variable', ''),
                        "semanticLabel": next_loc.get('semanticLabel'),
                        "relatedCode": next_loc['code'],
                        "functionName": next_loc['function_name'],
                        "startColumn": next_loc['start_column'],
                        "endColumn": next_loc['end_column']
                    }
                })

            # Fields that are optional and legitimately None
            OPTIONAL_FIELDS = {'semanticLabel'}

            # Check if the formatted result has any empty fields
            for key, value in main_result.items():
                if isinstance(value, dict):
                    for sub_key, sub_value in value.items():
                        if sub_key in OPTIONAL_FIELDS:
                            continue
                        if sub_value is None or sub_value == "":
                            return None
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            for sub_key, sub_value in item.items():
                                if isinstance(sub_value, dict):
                                    for sub_sub_key, sub_sub_value in sub_value.items():
                                        if sub_sub_key in OPTIONAL_FIELDS:
                                            continue
                                        if sub_sub_value is None or sub_sub_value == "":
                                            return None
                                elif sub_key in OPTIONAL_FIELDS:
                                    continue
                                elif sub_value is None or sub_value == "":
                                    return None
                
            return json.dumps(main_result, indent=4)
            
        except Exception as e:
            # Keep minimal error logging for debugging
            print(f"Exception in format_info_as_json: {type(e).__name__}: {str(e)}")
            return None

    def _process_thread_flow(self, thread_flow, symbol_lookup, skipped_locations_summary):
        """Process a single threadFlow into a flow_info dict. Returns None on failure."""
        if not hasattr(thread_flow, 'locations') or len(thread_flow.locations) < 2:
            return None

        source = thread_flow.locations[0]
        sink = thread_flow.locations[-1]
        path = list(thread_flow.locations)

        try:
            source_resolved = self.resolve_path(source.file_path)
            sink_resolved = self.resolve_path(sink.file_path)

            flow_info = {
                "source": {
                    "file_path": source.file_path,
                    "start_line": source.start_line,
                    "start_column": source.start_column,
                    "end_column": source.end_column,
                    "code": symbol_lookup.get_function_code_by_location(source_resolved, source.start_line),
                    "function_name": symbol_lookup.get_function_qname_by_location(source_resolved, source.start_line),
                    "lineCode": self.get_line_code(source.file_path, source.start_line),
                    "variable": self.get_variable_from_file(source.file_path, source.start_line, source.start_column, source.end_column),
                    "semanticLabel": getattr(source, 'message_text', None)
                },
                "sink": {
                    "file_path": sink.file_path,
                    "start_line": sink.start_line,
                    "start_column": sink.start_column,
                    "end_column": sink.end_column,
                    "code": symbol_lookup.get_function_code_by_location(sink_resolved, sink.start_line),
                    "function_name": symbol_lookup.get_function_qname_by_location(sink_resolved, sink.start_line),
                    "lineCode": self.get_line_code(sink.file_path, sink.start_line),
                    "variable": self.get_variable_from_file(sink.file_path, sink.start_line, sink.start_column, sink.end_column),
                    "semanticLabel": getattr(sink, 'message_text', None)
                },
                "path": []
            }

            # Build path list, filtering out locations with None function_name
            for loc in path:
                try:
                    resolved_path = self.resolve_path(loc.file_path)
                    loc_func_name = symbol_lookup.get_function_qname_by_location(resolved_path, loc.start_line)
                    if loc_func_name is not None:
                        flow_info["path"].append({
                            "file_path": loc.file_path,
                            "start_line": loc.start_line,
                            "start_column": loc.start_column,
                            "end_column": loc.end_column,
                            "code": symbol_lookup.get_function_code_by_location(resolved_path, loc.start_line),
                            "function_name": loc_func_name,
                            "lineCode": self.get_line_code(loc.file_path, loc.start_line),
                            "variable": self.get_variable_from_file(loc.file_path, loc.start_line, loc.start_column, loc.end_column),
                            "semanticLabel": getattr(loc, 'message_text', None)
                        })
                    else:
                        location_key = f"{loc.file_path}:{loc.start_line}"
                        skipped_locations_summary[location_key] += 1
                except Exception:
                    location_key = f"{loc.file_path}:{loc.start_line}"
                    skipped_locations_summary[location_key] += 1

            return flow_info
        except Exception:
            return None

    def _dedup_by_endpoints(self, flow_info_list, compression_level):
        """Deduplicate flow_info by endpoint pairs. Keep shortest path per group."""
        groups = defaultdict(list)
        for flow_info in flow_info_list:
            src = flow_info['source']
            sink = flow_info['sink']
            if compression_level == 2:
                key = (src['file_path'], src['function_name'], sink['file_path'], sink['function_name'])
            else:  # level 3
                key = (src['file_path'], sink['file_path'])
            groups[key].append(flow_info)

        result = []
        for key, group in groups.items():
            # Keyword filtering (only when ENABLE_KEYWORDS is True)
            if ENABLE_KEYWORDS:
                keyword_found = False
                for fi in group:
                    for step in fi['path']:
                        if step.get('function_name') and any(kw in step['function_name'] for kw in KEYWORDS):
                            keyword_found = True
                            break
                    if keyword_found:
                        break
                if not keyword_found:
                    continue

            shortest = min(group, key=lambda fi: len(fi['path']))
            result.append(shortest)
        return result

    def extract_info(self, compression_level=0):
        """
        Extract flow info from SARIF with configurable compression.

        Levels:
          0 - Keep all threadFlows (no dedup)
          1 - 1 threadFlow per codeFlow (keep shortest)
          2 - 1 path per (source_file, source_func, sink_file, sink_func)
          3 - 1 path per (source_file, sink_file)
        """
        import time
        overall_start = time.time()

        processor = SarifPathParser.SARIFProcessor(self.sarif_file)
        processor.parse_sarif()
        codeql_results = processor.codeql_results

        print(f"[DEBUG] Total CodeQL results to process: {len(codeql_results)}")
        print(f"[DEBUG] Compression level: {compression_level}")

        # Use SymbolLookup for function resolution
        print(f"[TIMING] Initializing SymbolLookup...")
        fg_start = time.time()
        symbol_lookup = get_symbol_lookup()
        print(f"[TIMING] SymbolLookup initialized in {time.time() - fg_start:.2f}s")

        # Collect threadFlows based on compression level
        all_thread_flows = []
        results_with_flows = 0
        total_thread_flows_seen = 0

        for result in codeql_results:
            if not hasattr(result, 'code_flows'):
                continue
            results_with_flows += 1
            for code_flow in result.code_flows:
                if not hasattr(code_flow, 'thread_flows'):
                    continue
                total_thread_flows_seen += len(code_flow.thread_flows)
                if compression_level >= 1:
                    # Keep only shortest threadFlow per codeFlow
                    if code_flow.thread_flows:
                        shortest = min(code_flow.thread_flows, key=lambda tf: len(tf.locations))
                        all_thread_flows.append(shortest)
                else:
                    # Keep all threadFlows
                    all_thread_flows.extend(code_flow.thread_flows)

        print(f"[DEBUG] Results with code flows: {results_with_flows}")
        print(f"[DEBUG] Total threadFlows seen: {total_thread_flows_seen}")
        print(f"[DEBUG] ThreadFlows after level {compression_level} filtering: {len(all_thread_flows)}")

        # Process each threadFlow into flow_info
        flow_info_list = []
        invalid_flow_info_count = 0
        path_resolution_failures = 0
        skipped_locations_summary = defaultdict(int)

        print(f"[TIMING] Starting to process {len(all_thread_flows)} thread flows...")
        loop_start = time.time()

        for tf_idx, thread_flow in enumerate(all_thread_flows):
            if tf_idx > 0 and tf_idx % 500 == 0:
                elapsed = time.time() - loop_start
                print(f"[TIMING] Processed {tf_idx}/{len(all_thread_flows)} thread flows in {elapsed:.2f}s")

            flow_info = self._process_thread_flow(thread_flow, symbol_lookup, skipped_locations_summary)
            if flow_info is None:
                path_resolution_failures += 1
                continue
            if self.is_valid_flow_info(flow_info):
                flow_info_list.append(flow_info)
            else:
                invalid_flow_info_count += 1

        # Apply dedup for levels 2-3
        pre_dedup_count = len(flow_info_list)
        if compression_level >= 2:
            flow_info_list = self._dedup_by_endpoints(flow_info_list, compression_level)
            print(f"[DEBUG] Dedup (level {compression_level}): {pre_dedup_count} -> {len(flow_info_list)} paths")

        print(f"[DEBUG] Processing summary:")
        print(f"  Results with code flows: {results_with_flows}")
        print(f"  Total thread flows seen: {total_thread_flows_seen}")
        print(f"  Path resolution failures: {path_resolution_failures}")
        print(f"  Invalid flow info: {invalid_flow_info_count}")
        print(f"  Successfully processed: {len(flow_info_list)}")

        # Report aggregated skipped locations
        if skipped_locations_summary:
            total_skipped = sum(skipped_locations_summary.values())
            print(f"[INFO] Total skipped points: {total_skipped} across {len(skipped_locations_summary)} unique locations")
            top_skipped = sorted(skipped_locations_summary.items(), key=lambda x: x[1], reverse=True)[:10]
            if top_skipped:
                print(f"[INFO] Top {min(10, len(top_skipped))} most frequently skipped locations:")
                for location, count in top_skipped:
                    print(f"  {location}: {count} times")

        return flow_info_list

    def extract_info_min(self):
        """Backward-compatible wrapper. Use extract_info(compression_level=2) instead."""
        return self.extract_info(compression_level=2)
