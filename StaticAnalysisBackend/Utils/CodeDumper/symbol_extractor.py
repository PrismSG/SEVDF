"""
Symbol Extractor - Export various symbol types from CodeQL database to CSV files.

This module provides extractors for:
- Functions (functionlist.csv)
- Macros (macros.csv)
- Global Variables (globalvars.csv)
- Classes/Structs (classes.csv)
"""

import os
import subprocess
from typing import Optional


class SymbolExtractor:
    """Base class for extracting symbols from CodeQL database."""

    def __init__(self, codeql_db_path: str, output_csv: str, query_file: str):
        self.codeql_db_path = codeql_db_path
        self.output_csv = output_csv
        self.query_file = query_file
        self.bqrs_output = f'/tmp/codeql-{os.path.basename(query_file)}.bqrs'
        self.ql_search_path = os.path.join(os.path.dirname(__file__), '../codeql')

    def run_codeql_query(self):
        """Run CodeQL query and generate BQRS output."""
        if not os.path.exists(self.codeql_db_path):
            raise FileNotFoundError(f"CodeQL database not found at {self.codeql_db_path}")

        if not os.path.exists(self.query_file):
            raise FileNotFoundError(f"Query file not found at {self.query_file}")

        cmd = [
            'codeql', 'query', 'run',
            self.query_file,
            '--database', self.codeql_db_path,
            '--search-path', self.ql_search_path,
            '--output', self.bqrs_output
        ]
        print(f'Running CodeQL query: {os.path.basename(self.query_file)}...')
        subprocess.run(cmd, check=True)

    def decode_bqrs_to_csv(self):
        """Decode BQRS file to CSV format."""
        cmd = [
            'codeql', 'bqrs', 'decode',
            '--format=csv',
            '--output', self.output_csv,
            self.bqrs_output
        ]
        print(f'Decoding to CSV: {self.output_csv}...')
        subprocess.run(cmd, check=True)

    def cleanup(self):
        """Remove temporary BQRS file."""
        if os.path.exists(self.bqrs_output):
            os.remove(self.bqrs_output)

    def extract(self):
        """Run the full extraction pipeline."""
        self.run_codeql_query()
        self.decode_bqrs_to_csv()
        self.cleanup()
        print(f'Exported to {self.output_csv}')


# Query file paths
QUERY_DIR = os.path.dirname(__file__)
FUNCTION_QUERY = os.path.join(QUERY_DIR, 'function_dump.ql')
FUNCTION_USE_DEF_QUERY = os.path.join(QUERY_DIR, 'function_use_def.ql')
MACRO_QUERY = os.path.join(QUERY_DIR, 'macro_dump.ql')
MACRO_USE_DEF_QUERY = os.path.join(QUERY_DIR, 'macro_use_def.ql')
GLOBALVAR_QUERY = os.path.join(QUERY_DIR, 'global_var_dump.ql')
CLASS_QUERY = os.path.join(QUERY_DIR, 'class_dump.ql')


class FunctionExtractor(SymbolExtractor):
    """Extract function definitions to CSV."""

    def __init__(self, codeql_db_path: str, output_csv: str):
        super().__init__(codeql_db_path, output_csv, FUNCTION_QUERY)


class FunctionUseDefExtractor(SymbolExtractor):
    """Extract function call use-def relationships to CSV."""

    def __init__(self, codeql_db_path: str, output_csv: str):
        super().__init__(codeql_db_path, output_csv, FUNCTION_USE_DEF_QUERY)


class MacroExtractor(SymbolExtractor):
    """Extract macro definitions to CSV."""

    def __init__(self, codeql_db_path: str, output_csv: str):
        super().__init__(codeql_db_path, output_csv, MACRO_QUERY)


class MacroUseDefExtractor(SymbolExtractor):
    """Extract macro use-def relationships to CSV."""

    def __init__(self, codeql_db_path: str, output_csv: str):
        super().__init__(codeql_db_path, output_csv, MACRO_USE_DEF_QUERY)


class GlobalVarExtractor(SymbolExtractor):
    """Extract global variable definitions to CSV."""

    def __init__(self, codeql_db_path: str, output_csv: str):
        super().__init__(codeql_db_path, output_csv, GLOBALVAR_QUERY)


class ClassExtractor(SymbolExtractor):
    """Extract class/struct definitions to CSV."""

    def __init__(self, codeql_db_path: str, output_csv: str):
        super().__init__(codeql_db_path, output_csv, CLASS_QUERY)


def extract_all_symbols(codeql_db_path: str, cache_dir: str, project_name: str):
    """
    Extract all symbol types from CodeQL database.

    Args:
        codeql_db_path: Path to CodeQL database
        cache_dir: Directory to store CSV files
        project_name: Project name for CSV file prefix
    """
    os.makedirs(cache_dir, exist_ok=True)

    extractors = [
        ('functions', FunctionExtractor, f'{project_name}_functionlist.csv'),
        ('macros', MacroExtractor, f'{project_name}_macros.csv'),
        ('globalvars', GlobalVarExtractor, f'{project_name}_globalvars.csv'),
        ('classes', ClassExtractor, f'{project_name}_classes.csv'),
    ]

    results = {}
    for name, extractor_cls, csv_name in extractors:
        csv_path = os.path.join(cache_dir, csv_name)
        try:
            extractor = extractor_cls(codeql_db_path, csv_path)
            extractor.extract()
            results[name] = csv_path
            print(f'[+] {name.capitalize()} exported to {csv_path}')
        except FileNotFoundError as e:
            print(f'[!] Skipping {name}: {e}')
            results[name] = None
        except subprocess.CalledProcessError as e:
            print(f'[!] Error extracting {name}: {e}')
            results[name] = None

    return results
