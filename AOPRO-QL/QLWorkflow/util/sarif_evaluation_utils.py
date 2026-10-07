#!/usr/bin/env python3
"""
Fixed SARIF evaluation utilities with better path matching.
"""

import json
import os
import re
import csv
import subprocess
import time
from collections import defaultdict
from pathlib import Path


def generate_function_csv(cwe_number, output_csv):
    """
    Generate function CSV using function_dump.ql for a specific CWE.
    """
    # Get the project root directory
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    
    # Paths
    query_file = os.path.join(project_root, 'QLWorkflow', 'util', 'function_dump.ql')
    util_dir = os.path.dirname(output_csv)
    
    # Run query using run_juliet.py
    command = [
        'python3',
        os.path.join(project_root, 'run_juliet.py'),
        '--run-query-csv',
        '--cwe', f'{cwe_number:03d}',
        '--ql', query_file,
        '--output', util_dir
    ]
    
    print(f"Running command: {' '.join(command)}")
    result = subprocess.run(command, capture_output=True, text=True)
    
    if result.returncode != 0:
        error_msg = f"Failed to run function_dump.ql query for CWE-{cwe_number}: {result.stderr}"
        print(f"Error: {error_msg}")
        print(f"STDOUT: {result.stdout}")
        # Don't raise exception, just continue with empty function map
        return
    
    # The output file might have a different name pattern
    # Look for the generated CSV file
    expected_patterns = [
        f"CWE-{cwe_number:03d}_function_dump.csv",
        f"CWE-{cwe_number}_function_dump.csv",
        f"CWE{cwe_number}_function_dump.csv"
    ]
    
    generated_file = None
    for pattern in expected_patterns:
        candidate = os.path.join(util_dir, pattern)
        if os.path.exists(candidate):
            generated_file = candidate
            break
    
    if generated_file and generated_file != output_csv:
        # Move to expected location
        print(f"Moving {generated_file} to {output_csv}")
        os.rename(generated_file, output_csv)
    elif not generated_file:
        print(f"Warning: Could not find generated CSV file for CWE-{cwe_number}")


def extract_function_list_for_cwe(cwe_number):
    """
    Extract function list for a specific CWE from cached CSV.
    If CSV doesn't exist, generate it using function_dump.ql.
    Returns both a direct lookup dict and a relative path lookup dict.
    """
    # The CSV files are in {project_root}/qlworkspace/util/
    # Get the project root directory (3 levels up from this file)
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    csv_path = os.path.join(project_root, 'qlworkspace', 'util', f'cwe{cwe_number}_functions.csv')
    
    print(f"Loading function list from {csv_path}")
    
    function_map = {}
    relative_path_map = {}  # Maps relative paths to full paths
    
    # If CSV doesn't exist or is older than 1 week, generate it
    if not os.path.exists(csv_path) or (time.time() - os.path.getmtime(csv_path) > 604800):
        print(f"  CSV file missing or outdated (>1 week), generating it using function_dump.ql...")
        generate_function_csv(cwe_number, csv_path)
    
    if os.path.exists(csv_path):
        with open(csv_path, 'r') as f:
            reader = csv.DictReader(f)
            count = 0
            unique_files = set()
            for row in reader:
                # Handle both old column names and new column names
                if 'col1' in row:
                    # New format: col0=function, col1=file, col2=start_line, col3=end_line
                    function_name = row['col0']
                    file_path = row['col1']
                    line_number = int(row['col2'])
                    # Determine function type from name
                    function_type = 'bad' if 'bad' in function_name.lower() else ('good' if 'good' in function_name.lower() else 'unknown')
                else:
                    # Old format with named columns
                    file_path = row['file']
                    line_number = int(row['line'])
                    function_name = row['function']
                    function_type = row['type']
                
                # For new format with col3, also get end line and create entries for all lines in range
                if 'col3' in row and row['col3']:
                    end_line = int(row['col3'])
                    # Store entries for all lines in the function range
                    for line in range(line_number, end_line + 1):
                        function_map[(file_path, line)] = {
                            'function_name': function_name,
                            'function_type': function_type
                        }
                else:
                    # Old format or no end line - just store the single line
                    function_map[(file_path, line_number)] = {
                        'function_name': function_name,
                        'function_type': function_type
                    }
                
                # Also create relative path mapping
                if '/testcases/' in file_path:
                    # Extract relative path after testcases/CWE*/
                    parts = file_path.split('/testcases/')
                    if len(parts) > 1:
                        after_testcases = parts[1]
                        # Extract part after CWE directory
                        if '/' in after_testcases:
                            cwe_dir_end = after_testcases.find('/')
                            if cwe_dir_end > 0:
                                relative_part = after_testcases[cwe_dir_end + 1:]
                                relative_path_map[relative_part] = file_path
                
                count += 1
                unique_files.add(file_path)
            
            print(f"  Loaded {count} functions from {len(unique_files)} files")
    else:
        print(f"  Warning: Function list CSV not found: {csv_path}")
    
    return function_map, relative_path_map


def classify_function_name(func_name):
    """Classify function based on its name."""
    clean_name = func_name.strip()
    
    # Direct patterns
    if clean_name == 'bad':
        return 'bad'
    elif clean_name == 'good':
        return 'good'
    elif 'bad' in clean_name.lower() and 'Sink' in clean_name:
        return 'bad'
    elif 'good' in clean_name.lower() and ('B2G' in clean_name or 'G2B' in clean_name):
        return 'good'
    
    # CWE pattern matching
    cwe_pattern = r'CWE\d+_'
    if re.match(cwe_pattern, clean_name):
        parts = clean_name.split('_')
        if parts:
            last_part = parts[-1]
            # Check for bad indicators
            if any(x in last_part for x in ['bad', 'Bad', 'BAD']):
                return 'bad'
            # Check for good indicators
            elif any(x in last_part for x in ['good', 'Good', 'GOOD']):
                return 'good'
            # Pure numbers after CWE pattern are usually bad function variants
            elif re.match(r'^\d+$', last_part):
                return 'bad'
    
    # Check for destructor patterns
    if clean_name.startswith('~CWE'):
        # Destructors for CWE test cases are typically bad functions
        if '_bad' in clean_name or re.search(r'_\d+$', clean_name):
            return 'bad'
        elif '_good' in clean_name:
            return 'good'
    
    return 'unknown'


def get_cwe_function_counts(cwe_number, function_map=None):
    """Get total counts of bad and good functions for a CWE."""
    if function_map is None:
        function_map, _ = extract_function_list_for_cwe(cwe_number)
    
    # Count unique (file, function) combinations
    # IMPORTANT: Only count functions that have "bad" or "good" in their name
    bad_functions = set()
    good_functions = set()
    
    for (file_path, line_number), info in function_map.items():
        function_name = info['function_name']
        function_type = info['function_type']
        
        # Skip non-Juliet files
        if '/juliet-test-suite-c/' not in file_path and '/workspace/juliet-test-suite-c/' not in file_path:
            continue
        
        # Create unique key as (file_path, function_name)
        unique_key = (file_path, function_name)
        
        # Only count functions with "bad" in the name for bad functions
        if function_type == 'bad' and 'bad' in function_name.lower():
            bad_functions.add(unique_key)
        # Only count functions with "good" in the name for good functions
        elif function_type == 'good' and 'good' in function_name.lower():
            good_functions.add(unique_key)
    
    print(f"CWE-{cwe_number}: Found {len(bad_functions)} unique bad functions (with 'bad' in name) and {len(good_functions)} unique good functions (with 'good' in name)")
    return len(bad_functions), len(good_functions)


def get_function_from_line_optimized(file_path, line_number, function_map, relative_path_map):
    """
    Optimized version that uses pre-loaded function list and handles path variations.
    Returns (function_type, function_info) or ('unknown', None).
    """
    # Try to resolve relative path first
    resolved_path = file_path
    if file_path in relative_path_map:
        resolved_path = relative_path_map[file_path]
    
    # Look up in the function map
    key = (resolved_path, line_number)
    if key in function_map:
        info = function_map[key]
        return info['function_type'], info
    
    # If exact line not found, try nearby lines (within 5 lines)
    for offset in range(1, 6):
        for delta in [offset, -offset]:
            key = (resolved_path, line_number + delta)
            if key in function_map:
                info = function_map[key]
                return info['function_type'], info
    
    return 'unknown', None


def count_sarif_results_deduplicated(sarif_path, cwe_number=None):
    """Count SARIF results using function-level deduplication."""
    print(f"[Deduplicated Count] Counting results from {sarif_path} with CWE-{cwe_number}")
    
    # If CWE number not provided, try to extract from path
    if cwe_number is None:
        path_match = re.search(r'CWE-(\d+)', sarif_path)
        if path_match:
            cwe_number = int(path_match.group(1))
    
    if not os.path.exists(sarif_path):
        return {
            'total_alerts': 0,
            'deduplicated_count': 0,
            'unique_bad_functions': 0,
            'unique_good_functions': 0,
            'unique_unknown_functions': 0,
            'details': {}
        }
    
    # Load function list for the CWE if available
    function_map = {}
    relative_path_map = {}
    if cwe_number:
        function_map, relative_path_map = extract_function_list_for_cwe(cwe_number)
    
    # Load and parse SARIF
    with open(sarif_path, 'r', encoding='utf-8') as f:
        sarif_data = json.load(f)
    
    # Track unique functions with alerts
    bad_functions_with_alerts = set()
    good_functions_with_alerts = set()
    unknown_functions_with_alerts = set()
    total_alerts = 0
    
    # Process results
    for run in sarif_data.get('runs', []):
        for result in run.get('results', []):
            for code_flow in result.get('codeFlows', []):
                for thread_flow in code_flow.get('threadFlows', []):
                    total_alerts += 1
                    
                    # Get the source location of the alert
                    if thread_flow.get('locations'):
                        first_location = thread_flow['locations'][0]
                        physical_location = first_location.get('location', {}).get('physicalLocation', {})
                        artifact_location = physical_location.get('artifactLocation', {})
                        region = physical_location.get('region', {})
                        
                        file_path = artifact_location.get('uri', '')
                        line_number = region.get('startLine', 0)
                        
                        # Determine function type using the function list
                        if function_map and line_number > 0:
                            func_type, func_info = get_function_from_line_optimized(
                                file_path, line_number, function_map, relative_path_map
                            )
                            if func_info:
                                function_name = func_info['function_name']
                                function_key = (file_path, function_name)
                                
                                if func_type == 'bad':
                                    bad_functions_with_alerts.add(function_key)
                                elif func_type == 'good':
                                    good_functions_with_alerts.add(function_key)
                                else:
                                    unknown_functions_with_alerts.add(function_key)
                        else:
                            # No function list, try to classify by file name
                            if 'bad' in file_path.lower():
                                bad_functions_with_alerts.add((file_path, 'unknown_function'))
                            elif 'good' in file_path.lower():
                                good_functions_with_alerts.add((file_path, 'unknown_function'))
                            else:
                                unknown_functions_with_alerts.add((file_path, 'unknown_function'))
    
    # The deduplicated count is the number of unique bad functions with alerts
    deduplicated_count = len(bad_functions_with_alerts)
    
    return {
        'total_alerts': total_alerts,
        'deduplicated_count': deduplicated_count,
        'unique_bad_functions': len(bad_functions_with_alerts),
        'unique_good_functions': len(good_functions_with_alerts),
        'unique_unknown_functions': len(unknown_functions_with_alerts),
        'details': {
            'bad_functions': list(bad_functions_with_alerts),
            'good_functions': list(good_functions_with_alerts),
            'unknown_functions': list(unknown_functions_with_alerts)
        }
    }


def analyze_result_distribution(results):
    """Analyze the distribution of query results."""
    file_counts = defaultdict(int)
    function_counts = defaultdict(int)
    
    for result in results:
        file_path = result.get('file', '')
        function = result.get('function', '')
        
        file_counts[file_path] += 1
        function_counts[function] += 1
    
    return {
        'total_files': len(file_counts),
        'total_functions': len(function_counts),
        'top_files': sorted(file_counts.items(), key=lambda x: x[1], reverse=True)[:10],
        'top_functions': sorted(function_counts.items(), key=lambda x: x[1], reverse=True)[:10],
    }


def evaluate_sarif_results_deduplicated(sarif_path, output_dir=None, source_base_dir=None):
    """Enhanced evaluation with function-level deduplication."""
    print(f"Evaluating SARIF results with deduplication: {sarif_path}")
    
    # Try to detect CWE number from path
    cwe_number = None
    path_match = re.search(r'CWE-(\d+)', sarif_path)
    if path_match:
        cwe_number = int(path_match.group(1))
    
    print(f"Loading function list for CWE-{cwe_number}...")
    
    # Load function boundaries for the CWE
    function_map = {}
    relative_path_map = {}
    total_bad_functions = 0
    total_good_functions = 0
    if cwe_number:
        function_map, relative_path_map = extract_function_list_for_cwe(cwe_number)
        total_bad_functions, total_good_functions = get_cwe_function_counts(cwe_number, function_map)
    
    if not os.path.exists(sarif_path):
        return {
            'true_positive_count': 0,
            'false_positive_count': 0,
            'true_positive_rate': 0,
            'false_positive_rate': 0,
            'good_result_count': 0,
            'bad_result_count': 0,
            'unknown_result_count': 0,
            'total_alerts': 0,
            'unique_functions_with_alerts': 0,
            'recall': 0,
            'precision': 0,
            'f1_score': 0,
            'total_bad_functions': total_bad_functions,
            'total_good_functions': total_good_functions
        }
    
    # Load and parse SARIF
    with open(sarif_path, 'r', encoding='utf-8') as f:
        sarif_data = json.load(f)
    
    # Process results with function-level deduplication
    bad_results = {}  # file -> {functions: set()}
    good_results = {}
    unknown_results = {}
    
    # Track unique functions for metrics
    unique_bad_functions = set()
    unique_good_functions = set()
    unique_unknown_functions = set()
    total_alerts = 0
    
    for run in sarif_data.get('runs', []):
        for result in run.get('results', []):
            message = result.get('message', {}).get('text', '')
            
            for code_flow in result.get('codeFlows', []):
                for thread_flow in code_flow.get('threadFlows', []):
                    total_alerts += 1
                    
                    # Get all locations in the thread flow
                    for location in thread_flow.get('locations', []):
                        physical_location = location.get('location', {}).get('physicalLocation', {})
                        artifact_location = physical_location.get('artifactLocation', {})
                        region = physical_location.get('region', {})
                        
                        file_path = artifact_location.get('uri', '')
                        line_number = region.get('startLine', 0)
                        
                        # Skip if not in Juliet test suite - check for CWE pattern in filename
                        # SARIF files often contain relative paths, so check for CWE patterns
                        if not (('/juliet-test-suite-c/' in file_path) or 
                                file_path.startswith('s') or 
                                re.search(r'CWE\d+_', file_path)):
                            continue
                        
                        # Skip main.cpp and other non-test files
                        if file_path.endswith('main.cpp') or file_path.endswith('main_linux.cpp'):
                            continue
                        
                        # Determine function type
                        function_type = 'unknown'
                        function_name = 'unknown'
                        
                        if function_map and line_number > 0:
                            func_type, func_info = get_function_from_line_optimized(
                                file_path, line_number, function_map, relative_path_map
                            )
                            if func_info:
                                function_type = func_type
                                function_name = func_info['function_name']
                        else:
                            # Fallback to file path classification
                            if 'bad' in os.path.basename(file_path).lower():
                                function_type = 'bad'
                            elif 'good' in os.path.basename(file_path).lower():
                                function_type = 'good'
                        
                        # Create result entry
                        result_entry = {
                            'file': file_path,
                            'line': line_number,
                            'message': message,
                            'function': function_name
                        }
                        
                        # Add to appropriate category
                        if function_type == 'bad':
                            if file_path not in bad_results:
                                bad_results[file_path] = {'functions': set(), 'alerts': []}
                            bad_results[file_path]['functions'].add(function_name)
                            bad_results[file_path]['alerts'].append(result_entry)
                            # Use (file_path, function_name) tuple for uniqueness
                            unique_bad_functions.add((file_path, function_name))
                        elif function_type == 'good':
                            if file_path not in good_results:
                                good_results[file_path] = {'functions': set(), 'alerts': []}
                            good_results[file_path]['functions'].add(function_name)
                            good_results[file_path]['alerts'].append(result_entry)
                            # Use (file_path, function_name) tuple for uniqueness
                            unique_good_functions.add((file_path, function_name))
                        else:
                            if file_path not in unknown_results:
                                unknown_results[file_path] = {'functions': set(), 'alerts': []}
                            unknown_results[file_path]['functions'].add(function_name)
                            unknown_results[file_path]['alerts'].append(result_entry)
                            # Use (file_path, function_name) tuple for uniqueness
                            unique_unknown_functions.add((file_path, function_name))
    
    # Calculate metrics based on unique functions
    true_positive_count = len(unique_bad_functions)
    false_positive_count = len(unique_good_functions)
    
    # Calculate rates
    true_positive_rate = (true_positive_count / total_bad_functions * 100) if total_bad_functions > 0 else 0
    false_positive_rate = (false_positive_count / total_good_functions * 100) if total_good_functions > 0 else 0
    
    # Calculate precision, recall, F1
    recall = (true_positive_count / total_bad_functions) * 100 if total_bad_functions > 0 else 0
    precision = (true_positive_count / (true_positive_count + false_positive_count)) * 100 if (true_positive_count + false_positive_count) > 0 else 0
    f1_score = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    # Save results if output directory is provided
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        
        # Save bad results
        bad_results_list = []
        for file_path, data in bad_results.items():
            for func in data['functions']:
                bad_results_list.append({
                    'file': file_path,
                    'function': func,
                    'alert_count': len([a for a in data['alerts'] if a['function'] == func])
                })
        
        with open(os.path.join(output_dir, 'bad_results.json'), 'w') as f:
            json.dump(bad_results_list, f, indent=2)
        
        # Save good results (false positives)
        good_results_list = []
        for file_path, data in good_results.items():
            for func in data['functions']:
                good_results_list.append({
                    'file': file_path,
                    'function': func,
                    'alert_count': len([a for a in data['alerts'] if a['function'] == func])
                })
        
        with open(os.path.join(output_dir, 'good_results.json'), 'w') as f:
            json.dump(good_results_list, f, indent=2)
        
        # Save unknown results
        unknown_results_list = []
        for file_path, data in unknown_results.items():
            for func in data['functions']:
                unknown_results_list.append({
                    'file': file_path,
                    'function': func,
                    'alert_count': len([a for a in data['alerts'] if a['function'] == func])
                })
        
        with open(os.path.join(output_dir, 'unknown_results.json'), 'w') as f:
            json.dump(unknown_results_list, f, indent=2)
        
        # Save evaluation summary
        summary = {
            'sarif_file': sarif_path,
            'true_positive_count': true_positive_count,
            'false_positive_count': false_positive_count,
            'unknown_count': len(unique_unknown_functions),
            'total_alerts': total_alerts,
            'unique_functions_with_alerts': len(unique_bad_functions) + len(unique_good_functions) + len(unique_unknown_functions),
            'true_positive_rate': round(true_positive_rate, 2),
            'false_positive_rate': round(false_positive_rate, 2),
            'recall': round(recall, 2),
            'precision': round(precision, 2),
            'f1_score': round(f1_score, 2),
            'total_bad_functions_in_suite': total_bad_functions,
            'total_good_functions_in_suite': total_good_functions
        }
        
        with open(os.path.join(output_dir, 'evaluation_summary.json'), 'w') as f:
            json.dump(summary, f, indent=2)
    
    return {
        'true_positive_count': true_positive_count,
        'false_positive_count': false_positive_count,
        'true_positive_rate': round(true_positive_rate, 2),
        'false_positive_rate': round(false_positive_rate, 2),
        'good_result_count': len(unique_good_functions),
        'bad_result_count': len(unique_bad_functions),
        'unknown_result_count': len(unique_unknown_functions),
        'total_alerts': total_alerts,
        'unique_functions_with_alerts': len(unique_bad_functions) + len(unique_good_functions) + len(unique_unknown_functions),
        'recall': round(recall, 2),
        'precision': round(precision, 2),
        'f1_score': round(f1_score, 2),
        'total_bad_functions': total_bad_functions,
        'total_good_functions': total_good_functions
    }


# Wrapper for backward compatibility
def evaluate_sarif_results_optimized(sarif_path, output_dir=None, source_base_dir=None):
    """Wrapper for backward compatibility."""
    return evaluate_sarif_results_deduplicated(sarif_path, output_dir, source_base_dir)