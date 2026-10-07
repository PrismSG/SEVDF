import os
import importlib
import json
import sys
import csv
import signal
import subprocess
import shutil

# Import CFG Manager for function-level CFG caching
from AdvancedTools.ConstraintAnalysis.cfg_manager import FunctionCFGManager

# Import SymbolLookup for CSV lookup
from AdvancedTools.CodeSearch.symbol_lookup import get_symbol_lookup

# ensure the current directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))

# Timeout in seconds (72 hours)
TIMEOUT = 259200

class CodeProcessor:
    def __init__(self):
        # Read configuration from environment variables (no config file needed)
        self.cwe_code = os.environ.get('VK_CWE_CODE', '')
        self.project_name = os.environ.get('VK_PROJECT_NAME', 'unknown')
        self.analysis_path = os.environ.get('VK_ANALYSIS_PATH', '')
        self.function_csv = os.environ.get('VK_FUNCTION_CSV', '')
        self.source_path = os.environ.get('VK_SOURCE_PATH', '')
        self.db_path = os.environ.get('VK_DB_PATH', 'codeql_analysis.db')
        self.codeql_db_path = os.environ.get('VK_CODEQL_DB_PATH', '')

        # Validate required parameters
        if not self.cwe_code:
            raise ValueError("VK_CWE_CODE environment variable is required")
        if not self.codeql_db_path:
            raise ValueError("VK_CODEQL_DB_PATH environment variable is required")

        # Normalize CWE code: remove 'CWE-' prefix if present
        # Supports both formats: "416-UseAfterFree" and "CWE-416-UseAfterFree"
        if self.cwe_code.upper().startswith('CWE-'):
            self.cwe_code = self.cwe_code[4:]  # Remove 'CWE-' prefix

        # construct the path of the CWE module, for example 'CWE-416'
        self.cwe_module_name = f'CWE-{self.cwe_code}'

        # add the builds directory to sys.path, so that the module can be imported
        # New architecture: scanner modules are in builds/ directory
        builds_dir = os.path.join(os.path.dirname(__file__), 'builds')
        cwe_module_path = os.path.join(builds_dir, self.cwe_module_name)

        # Check whether the CWE path exists
        if not os.path.exists(cwe_module_path):
            raise FileNotFoundError(f"CWE path does not exist: {cwe_module_path}. Please run './build.py build {self.cwe_code}' to generate the scanner module.")

        sys.path.insert(0, builds_dir)

        # dynamically import the corresponding codeql module
        try:
            # Import as a submodule to preserve relative imports
            module_name = f'builds.{self.cwe_module_name}.codeql'
            self.cwe_codeql_module = importlib.import_module(module_name)
        except ImportError as e:
            print(f'Failed to import codeql module from {self.cwe_module_name}: {e}')
            print(f'Please ensure that codeql.py file exists in the {cwe_module_path} directory')
            print(f'Run: ./build.py build {self.cwe_code}')
            raise ImportError(f"The analysis module for CWE-{self.cwe_code} is incomplete, missing codeql.py file")

        # get the CodeQLAnalysisHelper class from the imported module
        self.CodeQLAnalysisHelper = getattr(self.cwe_codeql_module, 'CodeQLAnalysisHelper')

        # Initialize a file cache to avoid repeatedly reading the same files
        self.file_cache = {}

        # Lazy-initialized symbol lookup for CFG building
        self._symbol_lookup = None

    def _get_symbol_lookup(self):
        """Get or create SymbolLookup instance."""
        if self._symbol_lookup is None:
            self._symbol_lookup = get_symbol_lookup()
        return self._symbol_lookup

    def adjust_start_line(self, path, start):
        """
        Adjust the start line of a function to find its true beginning.
        
        This looks backward from the reported start line until finding a blank
        line or closing brace, which typically indicates the boundary between functions.
        
        Args:
            path: Path to the source file
            start: Original start line number reported by CodeQL
            
        Returns:
            Adjusted start line number
        """
        if path not in self.file_cache:
            if os.path.exists(path):
                try:
                    with open(path, 'r', encoding='utf-8') as file:
                        self.file_cache[path] = file.readlines()
                except Exception as e:
                    print(f"Error reading file {path}: {e}")
                    return start  # Return original start line if file can't be read
            else:
                print(f"File not found: {path}")
                return start  # Return original start line if file doesn't exist
                
        lines = self.file_cache[path]
        
        # Validate lines and start parameters
        if not lines:
            print(f"Warning: File {path} is empty or could not be read properly")
            return start
            
        if not isinstance(start, int) or start < 1:
            print(f"Warning: Invalid start line number {start} for file {path}. Using original value.")
            return start
            
        # Ensure start doesn't exceed file length
        if start > len(lines):
            print(f"Warning: Start line {start} exceeds file length {len(lines)} for {path}")
            return min(start, len(lines))
            
        try:
            # Look backwards until we find a blank line or closing brace
            # Add bounds checking to prevent index errors
            while start > 1 and start - 2 >= 0 and start - 2 < len(lines):
                line_content = lines[start - 2]
                
                # Ensure line_content is a string before calling strip()
                if not isinstance(line_content, str):
                    print(f"Warning: Non-string content found at line {start - 1} in file {path}")
                    break
                    
                stripped_line = line_content.strip()
                if stripped_line in {'', '}'}:
                    break
                    
                start -= 1
                
        except (IndexError, AttributeError) as e:
            print(f"Error adjusting start line for {path} at line {start}: {e}")
            # Return the original start value if any error occurs during adjustment
            return start
        except Exception as e:
            print(f"Unexpected error adjusting start line for {path} at line {start}: {e}")
            return start
            
        return start

    def generate_symbol_csvs(self):
        """
        Export all symbol types from CodeQL database to CSV files.
        Includes: functions, macros, global variables, classes.
        """
        if not self.codeql_db_path:
            raise ValueError("CodeQL database path not set")

        if not os.path.exists(self.codeql_db_path):
            raise FileNotFoundError(f"CodeQL database not found at {self.codeql_db_path}")

        cache_dir = os.path.dirname(self.function_csv)

        # Export functions (required for basic lookup)
        self._export_functions()

        # Export use-def relationships (for precise lookup from call sites)
        self._export_function_use_def(cache_dir)

        # Export additional symbols (optional, for code filling)
        self._export_macros(cache_dir)
        self._export_globalvars(cache_dir)
        self._export_classes(cache_dir)

    def _export_functions(self):
        """Export function definitions to CSV."""
        if os.path.exists(self.function_csv):
            print(f"Function CSV already exists at {self.function_csv}. Skipping.")
            return

        from Utils.CodeDumper.functions import FunctionListExtractor
        extractor = FunctionListExtractor(
            codeql_db_path=self.codeql_db_path,
            output_csv=self.function_csv
        )
        extractor.extract_functions()

        # Process the CSV file to update file paths
        self._update_csv_paths()

    def _export_function_use_def(self, cache_dir):
        """Export function call use-def relationships to CSV."""
        func_use_def_csv = os.path.join(cache_dir, f'{self.project_name}_function_use_def.csv')
        if os.path.exists(func_use_def_csv):
            print(f"Function use-def CSV already exists. Skipping.")
            return

        try:
            from Utils.CodeDumper.symbol_extractor import FunctionUseDefExtractor
            extractor = FunctionUseDefExtractor(self.codeql_db_path, func_use_def_csv)
            extractor.extract()
            # Update paths: function_use_def.csv format is name, qualifiedName, use_file, use_line, def_file, def_start, def_end
            # Update both use_file (col 2) and def_file (col 4)
            self._update_symbol_csv_paths(func_use_def_csv, path_column_index=2)
            self._update_symbol_csv_paths(func_use_def_csv, path_column_index=4)
        except Exception as e:
            print(f"[!] Function use-def export failed (optional): {e}")

    def _export_macros(self, cache_dir):
        """Export macro definitions and use-def relationships to CSV."""
        # Export simple macros.csv (all definitions, for fallback lookup)
        macros_csv = os.path.join(cache_dir, f'{self.project_name}_macros.csv')
        if not os.path.exists(macros_csv):
            try:
                from Utils.CodeDumper.symbol_extractor import MacroExtractor
                extractor = MacroExtractor(self.codeql_db_path, macros_csv)
                extractor.extract()
                # Update paths: macros.csv format is name, body, file_path, start_line, end_line
                self._update_symbol_csv_paths(macros_csv, path_column_index=2)
            except Exception as e:
                print(f"[!] Macro export failed (optional): {e}")

        # Export macro_use_def.csv (for precise lookup from use sites)
        macro_use_def_csv = os.path.join(cache_dir, f'{self.project_name}_macro_use_def.csv')
        if not os.path.exists(macro_use_def_csv):
            try:
                from Utils.CodeDumper.symbol_extractor import MacroUseDefExtractor
                extractor = MacroUseDefExtractor(self.codeql_db_path, macro_use_def_csv)
                extractor.extract()
                # Update paths: macro_use_def.csv format is name, use_file, use_line, def_file, def_line, body
                # Update both use_file (col 1) and def_file (col 3)
                self._update_symbol_csv_paths(macro_use_def_csv, path_column_index=1)
                self._update_symbol_csv_paths(macro_use_def_csv, path_column_index=3)
            except Exception as e:
                print(f"[!] Macro use-def export failed (optional): {e}")

    def _export_globalvars(self, cache_dir):
        """Export global variable definitions to CSV."""
        globalvars_csv = os.path.join(cache_dir, f'{self.project_name}_globalvars.csv')
        if os.path.exists(globalvars_csv):
            print(f"GlobalVars CSV already exists. Skipping.")
            return

        try:
            from Utils.CodeDumper.symbol_extractor import GlobalVarExtractor
            extractor = GlobalVarExtractor(self.codeql_db_path, globalvars_csv)
            extractor.extract()
            # Update paths: globalvars.csv format is name, qualifiedName, type, file_path, start_line, end_line
            self._update_symbol_csv_paths(globalvars_csv, path_column_index=3)
        except Exception as e:
            print(f"[!] GlobalVars export failed (optional): {e}")

    def _export_classes(self, cache_dir):
        """Export class/struct definitions to CSV."""
        classes_csv = os.path.join(cache_dir, f'{self.project_name}_classes.csv')
        if os.path.exists(classes_csv):
            print(f"Classes CSV already exists. Skipping.")
            return

        try:
            from Utils.CodeDumper.symbol_extractor import ClassExtractor
            extractor = ClassExtractor(self.codeql_db_path, classes_csv)
            extractor.extract()
            # Update paths: classes.csv format is name, qualifiedName, file_path, start_line, end_line
            self._update_symbol_csv_paths(classes_csv, path_column_index=2)
        except Exception as e:
            print(f"[!] Classes export failed (optional): {e}")


    def _update_symbol_csv_paths(self, csv_file: str, path_column_index: int):
        """
        Update file paths in a symbol CSV file with source_path prefix.

        Args:
            csv_file: Path to the CSV file to update
            path_column_index: Index of the column containing file paths (0-based)
        """
        if not os.path.exists(csv_file):
            print(f"CSV file not found: {csv_file}. Skipping path update.")
            return

        if not self.source_path:
            print(f"Source path not set. Skipping path update for {csv_file}.")
            return

        print(f"Updating paths in: {os.path.basename(csv_file)}")

        # Read the original CSV file
        original_rows = []
        header = None
        with open(csv_file, 'r') as csvfile:
            reader = csv.reader(csvfile)
            header = next(reader, None)
            for row in reader:
                if len(row) > path_column_index:
                    original_rows.append(row)

        if not original_rows:
            print(f"  No data found in {csv_file}.")
            return

        # Process rows to update paths
        updated_rows = []
        path_update_count = 0

        for row in original_rows:
            path = row[path_column_index]

            if not path:
                updated_rows.append(row)
                continue

            # Normalize and add source_path prefix
            normalized_path = path
            if normalized_path.startswith('/'):
                normalized_path = normalized_path[1:]
            elif normalized_path.startswith('file:/'):
                normalized_path = normalized_path[6:]

            full_path = self.source_path + "/" + normalized_path
            full_path = full_path.replace('//', '/')

            if full_path != path:
                path_update_count += 1

            # Create updated row
            updated_row = list(row)
            updated_row[path_column_index] = full_path
            updated_rows.append(updated_row)

        # Write back to CSV
        with open(csv_file, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            if header:
                writer.writerow(header)
            writer.writerows(updated_rows)

        print(f"  Updated {path_update_count}/{len(original_rows)} paths")

    def _update_csv_paths(self):
        """
        Process the CSV file to update file paths with source_path prefix.
        Reads the original CSV, adds source_path prefix to ALL paths,
        and writes back the updated data.
        """
        if not os.path.exists(self.function_csv):
            print(f"Function CSV file not found at {self.function_csv}. Cannot update paths.")
            return
            
        print(f"Processing function CSV file: {self.function_csv}")
        
        # Read the original CSV file
        original_rows = []
        with open(self.function_csv, 'r') as csvfile:
            reader = csv.reader(csvfile)
            # Get the header row if it exists
            header = next(reader, None)
            for row in reader:
                if len(row) >= 4:  # Ensure we have at least function name, path, start, end
                    original_rows.append(row)
                    
        print(f"Read {len(original_rows)} functions from CSV file")
            
        if not original_rows:
            print("No function data found in CSV or CSV is empty. Nothing to update.")
            return
            
        # Process rows to update paths only
        updated_rows = []
        path_update_count = 0
        empty_path_count = 0
        
        for i, row in enumerate(original_rows):
            # New 5-column format: name, qualifiedName, file_path, start_line, end_line
            if len(row) < 5:
                print(f"Warning: Skipping invalid row (expected 5 columns): {row}")
                continue
            function_name, qualified_name, path, start, end = row[:5]

            # Log progress for large files
            if i > 0 and i % 100 == 0:
                print(f"Processed {i}/{len(original_rows)} functions...")

            # Check if path is empty
            if not path:
                print(f"Warning: Empty path found for function '{function_name}' at line {start}-{end}. Skipping.")
                empty_path_count += 1
                continue

            # Always add source_path for file access regardless of path format
            # This ensures we can locate the file on the current file system
            if self.source_path:
                # Remove the first '/' or 'file:/' prefix from the path to avoid
                # os.path.join() discarding source_path when path is absolute
                normalized_path = path
                if normalized_path.startswith('/'):
                    normalized_path = normalized_path[1:]
                elif normalized_path.startswith('file:/'):
                    normalized_path = normalized_path[6:]

                full_path = self.source_path + "/" + normalized_path
                full_path = full_path.replace('//', '/')
            else:
                print(f"Source path is not set, using the original path: {path}")
                full_path = path

            # Use the full_path for updating the CSV entry
            # This ensures we use the same path we used for finding the file
            if full_path != path:
                path_update_count += 1

            updated_rows.append([function_name, qualified_name, full_path, start, end])
            
        # Write the updated data back to the CSV file
        with open(self.function_csv, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            if header:
                writer.writerow(header)
            writer.writerows(updated_rows)
            
        print(f"Completed processing {len(original_rows)} functions:")
        print(f"  - Paths updated: {path_update_count}")
        if empty_path_count > 0:
            print(f"  - Empty paths skipped: {empty_path_count}")
        print(f"Updated paths in {self.function_csv}")

    def process(self):
        """
        Process the code analysis with a timeout of 2 hours.
        
        Returns:
            Analysis results if completed within the timeout period.
            
        Raises:
            TimeoutError: If the analysis exceeds the timeout period.
        """
        # Define timeout handler
        def timeout_handler(signum, frame):
            raise TimeoutError(f"Analysis timed out after {TIMEOUT} seconds")
            
        # Set timeout alarm
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(TIMEOUT)
        
        try:
            # generate symbol CSVs (functions, macros, globalvars, classes)
            self.generate_symbol_csvs()

            # create an instance of CodeQLAnalysisHelper, pass in codeql_db_path
            db_helper = self.CodeQLAnalysisHelper(self.db_path, self.codeql_db_path)

            # get the analysis results
            analysis_results = db_helper.get_analysis_results(
                self.analysis_path,
                self.project_name,
                self.function_csv,
                self.source_path
            )

            # Format results for Scanner consumption BEFORE CFG building
            # Scanner and CFG building expect JSON strings with "propagation path" format
            formatted_results = []
            for result in analysis_results:
                # Check if result is already formatted (has "propagation path")
                if isinstance(result, str):
                    # Already a JSON string, parse it to check format
                    try:
                        result_dict = json.loads(result)
                        if "propagation path" in result_dict:
                            # Already in correct format
                            formatted_results.append(result)
                        else:
                            # Need to format
                            from Utils.SarifParser.process_metadata import Extractor
                            # Create a temporary extractor just for formatting
                            temp_extractor = Extractor(None, None, None)
                            formatted = temp_extractor.format_info_as_json(result_dict)
                            formatted_results.append(formatted)
                    except:
                        formatted_results.append(result)
                elif isinstance(result, dict):
                    # Dictionary format
                    if "propagation path" in result:
                        # Already formatted, convert to JSON string
                        formatted_results.append(json.dumps(result, ensure_ascii=False, indent=4))
                    else:
                        # Raw flow_info, needs formatting
                        from Utils.SarifParser.process_metadata import Extractor
                        temp_extractor = Extractor(None, None, None)
                        formatted = temp_extractor.format_info_as_json(result)
                        if formatted:
                            formatted_results.append(formatted)
                else:
                    # Unknown format, keep as-is
                    formatted_results.append(result)

            # Build CFGs for functions found in analysis results
            # This provides cached CFGs for later constraint analysis
            symbol_lookup = self._get_symbol_lookup()
            if symbol_lookup:
                cfg_manager = FunctionCFGManager(self.project_name)
                cfg_manager.build_cfgs_for_analysis(
                    formatted_results, symbol_lookup, self.codeql_db_path, self.source_path
                )
            else:
                print("[+] SymbolLookup not available, skipping CFG building")

            # close the database connection
            db_helper.close()

            return formatted_results
            
        except TimeoutError:
            raise
        finally:
            # Ensure alarm is canceled even if another exception occurs
            signal.alarm(0)
            
            # Clean up CodeQL cache directory (not ai-analysis cache)
            if hasattr(self, 'codeql_db_path') and self.codeql_db_path and os.path.exists(self.codeql_db_path):
                try:
                    # Look for db-* directories (could be db-cpp, db-java, db-python, etc.)
                    db_dirs = [d for d in os.listdir(self.codeql_db_path) if d.startswith('db-') and os.path.isdir(os.path.join(self.codeql_db_path, d))]
                    
                    cache_cleaned = False
                    for db_dir in db_dirs:
                        codeql_cache_path = os.path.join(self.codeql_db_path, db_dir, 'default', 'cache')
                        if os.path.exists(codeql_cache_path):
                            shutil.rmtree(codeql_cache_path)
                            print(f"[+] Cleaned up CodeQL cache directory: {codeql_cache_path}")
                            cache_cleaned = True
                    
                    if not cache_cleaned:
                        print(f"[-] No CodeQL cache directories found in {self.codeql_db_path}")
                except Exception as e:
                    print(f"[-] Error cleaning up CodeQL cache directory: {e}")

# example usage
if __name__ == '__main__':
    # Note: Requires environment variables to be set:
    # VK_CWE_CODE, VK_PROJECT_NAME, VK_CODEQL_DB_PATH, etc.
    processor = CodeProcessor()
    processor.process()
