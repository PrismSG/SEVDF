"""
QL Query Execution Configuration
Defines the state machine for running QL queries using CodeQL.
"""

import subprocess
import os
import json

# Get the directory of the script for relative paths
SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def run_ql_query_action(machine):
    """
    Action to execute the QL query using run_juliet.py.
    """
    # Get the QL file path to run
    ql_path = machine.context.ql_file_path
    cwe_number = machine.context.cwe_number
    
    print(f"\n[Run QL Query] Executing query for CWE-{cwe_number} iteration {machine.context.current_iteration}")
    print(f"[Run QL Query] Input QL file: {ql_path}")
    
    # Create output directory for this iteration
    iteration_dir = os.path.join(machine.context.output_dir, f"iteration_{machine.context.current_iteration}")
    os.makedirs(iteration_dir, exist_ok=True)
    
    # Use query_results directory for both input and output
    query_output_dir = os.path.join(iteration_dir, 'query_results')
    os.makedirs(query_output_dir, exist_ok=True)
    
    # The modified query should already be in the passed ql_path
    print(f"[Run QL Query] Using query from: {ql_path}")
    
    # For proper module resolution, we need to run from the project's codeql directory
    # If the query is not already in the codeql directory, copy it there with a different name
    if hasattr(machine.context, 'original_ql_path') and not ql_path.startswith(os.path.dirname(machine.context.original_ql_path)):
        import shutil
        original_dir = os.path.dirname(machine.context.original_ql_path)
        # Use the actual ql_path filename, not the original
        current_name = os.path.basename(ql_path)
        
        # Create a temporary file with a unique name to avoid conflicts
        # If already has _modified suffix, don't add it again
        base_name = os.path.splitext(current_name)[0]
        if '_modified' not in base_name:
            temp_name = f"{base_name}_modified_{machine.context.current_iteration}.ql"
        else:
            # Already modified, just add iteration number
            temp_name = f"{base_name}_{machine.context.current_iteration}.ql"
        temp_ql_path = os.path.join(original_dir, temp_name)
        
        # Copy the modified QL file to the codeql directory with temp name
        shutil.copy2(ql_path, temp_ql_path)
        print(f"[Run QL Query] Copied modified QL to codeql directory as: {temp_ql_path}")
        
        # Use the temp path in codeql directory for execution
        ql_path = temp_ql_path
        machine.context.temp_ql_path = temp_ql_path  # Store for cleanup later
    else:
        print(f"[Run QL Query] Query already in codeql directory: {ql_path}")
    
    # Construct the command with custom output directory
    command = [
        'python3',
        os.path.join(SCRIPT_DIR, 'run_juliet.py'),
        '--run-query-sarif',
        '--cwe', f'{cwe_number:03d}',
        '--ql', ql_path,
        '--output', query_output_dir
    ]
    
    # Run the command
    try:
        print(f"[Run QL Query] Running command: {' '.join(command)}")
        # record running time
        import time
        start_time = time.time()
        result = subprocess.run(command, capture_output=True, text=True)
        end_time = time.time()
        running_time = end_time - start_time
        print(f"[Run QL Query] Running time: {running_time:.2f} seconds")
        
        # Save command output
        output_log = {
            'command': ' '.join(command),
            'stdout': result.stdout,
            'stderr': result.stderr,
            'returncode': result.returncode,
            'running_time': running_time
        }
        
        # Save log in the query output directory
        log_file = os.path.join(query_output_dir, 'query_execution_log.json')
        with open(log_file, 'w') as f:
            json.dump(output_log, f, indent=2)
        
        if result.returncode != 0:
            return f"Query execution failed: {result.stderr}"
        
        # Look for SARIF file in the output directory
        sarif_file = None
        
        # Find SARIF file in the output directory
        for file in os.listdir(query_output_dir):
            if file.endswith('.sarif'):
                sarif_file = os.path.join(query_output_dir, file)
                print(f"[Run QL Query] Found SARIF file: {sarif_file}")
                break
        
        if not sarif_file:
            print(f"[Run QL Query] WARNING: No SARIF file found in {query_output_dir}")
        
        machine.context.sarif_file = sarif_file
        
        # Clean up temporary file if created
        if hasattr(machine.context, 'temp_ql_path') and os.path.exists(machine.context.temp_ql_path):
            os.remove(machine.context.temp_ql_path)
            print(f"[Run QL Query] Cleaned up temporary QL file: {machine.context.temp_ql_path}")
        
        return "Query executed successfully"
        
    except Exception as e:
        # Clean up temporary file in case of error
        if hasattr(machine.context, 'temp_ql_path') and os.path.exists(machine.context.temp_ql_path):
            os.remove(machine.context.temp_ql_path)
            print(f"[Run QL Query] Cleaned up temporary QL file after error: {machine.context.temp_ql_path}")
        
        return f"Error executing query: {str(e)}"


def parse_query_results_action(machine):
    """
    Parse the SARIF results from the query execution and count threadFlows.
    """
    print(f"[Run QL Query] Parsing query results...")
    
    # Use the SARIF file path from context
    sarif_path = getattr(machine.context, 'sarif_file', None)
    
    if not sarif_path:
        print(f"[Run QL Query] No SARIF file path in context")
        machine.context.result_count = 0
        return "No SARIF file found"
    
    print(f"[Run QL Query] SARIF file path: {sarif_path}")
    
    # First try to parse SARIF for deduplicated count
    threadflow_count = 0
    deduplicated_count = 0
    if sarif_path and os.path.exists(sarif_path):
        try:
            # Use deduplicated counting for validation consistency with evaluation
            from QLWorkflow.util.sarif_evaluation_utils import count_sarif_results_deduplicated
            
            # Get CWE number from context
            cwe_number = getattr(machine.context, 'cwe_number', None)
            
            # Count using deduplicated logic
            count_result = count_sarif_results_deduplicated(sarif_path, cwe_number)
            deduplicated_count = count_result['deduplicated_count']  # Unique bad functions
            threadflow_count = count_result['total_alerts']  # Total alerts/threadflows
            
            # Store detailed count info in context for validation
            machine.context.count_details = count_result
            
            print(f"[Run QL Query] Found SARIF file with {threadflow_count} total alerts")
            print(f"[Run QL Query] Deduplicated count: {deduplicated_count} unique bad functions")
            print(f"[Run QL Query] Count details: {count_result['unique_bad_functions']} bad, "
                  f"{count_result['unique_good_functions']} good, {count_result['unique_unknown_functions']} unknown")
            
        except Exception as e:
            print(f"[Run QL Query] Error with deduplicated counting, falling back to simple count: {str(e)}")
            # Fall back to simple threadflow counting
            try:
                with open(sarif_path, 'r', encoding='utf-8') as f:
                    sarif_data = json.load(f)
                
                # Count all threadFlows
                for run in sarif_data.get('runs', []):
                    for result in run.get('results', []):
                        for code_flow in result.get('codeFlows', []):
                            threadflow_count += len(code_flow.get('threadFlows', []))
                
                print(f"[Run QL Query] Simple count: {threadflow_count} threadFlows")
            except Exception as e2:
                print(f"[Run QL Query] Error parsing SARIF: {str(e2)}")
    
    # Set result count based on SARIF parsing
    machine.context.query_results = []  # We don't need CSV results anymore
    
    # Use deduplicated count for validation consistency with evaluation
    if deduplicated_count > 0:
        machine.context.result_count = deduplicated_count
        print(f"[Run QL Query] Using deduplicated count: {deduplicated_count} unique bad functions")
    else:
        # Fall back to threadFlow count if deduplicated count not available
        machine.context.result_count = threadflow_count if threadflow_count > 0 else 0
        print(f"[Run QL Query] Using simple count: {machine.context.result_count}")
    
    # Result distribution is not needed without CSV
    machine.context.result_distribution = {}
    
    # Determine output directory based on context  
    if machine.context.current_iteration == 1 and hasattr(machine.context, 'is_origin_run') and machine.context.is_origin_run:
        # For origin run in first iteration, save to initial/query_results/
        output_dir = os.path.join(machine.context.output_dir, 'initial', 'query_results')
    else:
        # For all modified queries, save to iteration_X/query_results/
        iteration_dir = os.path.join(machine.context.output_dir, f"iteration_{machine.context.current_iteration}")
        output_dir = os.path.join(iteration_dir, 'query_results')
    
    # Perform evaluation if SARIF exists
    evaluation_metrics = {}
    if sarif_path and os.path.exists(sarif_path):
        from QLWorkflow.util.sarif_evaluation_utils import evaluate_sarif_results_deduplicated as evaluate_sarif_results
        # Pass output_dir to save good/bad results
        # Find the actual CWE directory in Juliet test suite
        testcases_base = os.path.join(SCRIPT_DIR, 'juliet-test-suite-c', 'testcases')
        source_base_dir = None
        if os.path.exists(testcases_base):
            for dirname in os.listdir(testcases_base):
                if dirname.startswith(f'CWE{machine.context.cwe_number}_'):
                    source_base_dir = os.path.join(testcases_base, dirname)
                    break
        
        evaluation_metrics = evaluate_sarif_results(sarif_path, output_dir, source_base_dir)
        print(f"[Run QL Query] Evaluation: TP={evaluation_metrics['true_positive_count']}, FP={evaluation_metrics['false_positive_count']}")
        print(f"[Run QL Query] Saved good_results.json and bad_results.json to {output_dir}")
    
    # Save complete results with evaluation metrics
    complete_results = {
        'ql_file': machine.context.ql_file_path,
        'result_count': machine.context.result_count,
        'sarif_file': sarif_path if sarif_path and os.path.exists(sarif_path) else None
    }
    
    # Add evaluation metrics if available
    if evaluation_metrics:
        complete_results.update(evaluation_metrics)
        # Store in context for later use
        machine.context.evaluation_metrics = evaluation_metrics
    
    complete_results_file = os.path.join(output_dir, 'results_log.json')
    with open(complete_results_file, 'w') as f:
        json.dump(complete_results, f, indent=2)
    
    print(f"[Run QL Query] Parsed {machine.context.result_count} results")
    return f"Parsed {machine.context.result_count} results"


def exit_action(machine):
    """Exit action - cleanup temp files and return the result count."""
    # Clean up temporary QL file if it was created
    if hasattr(machine.context, 'temp_ql_path') and machine.context.temp_ql_path:
        if os.path.exists(machine.context.temp_ql_path):
            try:
                os.remove(machine.context.temp_ql_path)
                print(f"[Run QL Query] Cleaned up temporary file: {machine.context.temp_ql_path}")
            except Exception as e:
                print(f"[Run QL Query] Warning: Failed to clean up temp file: {e}")
    
    return machine.context.result_count


# State machine configuration for query execution
state_definitions = {
    'RunQLQuery': {
        'action': run_ql_query_action,
        'next_state_func': lambda result, machine: 'ParseResults' if 'successfully' in result.lower() else 'Exit',
    },
    'ParseResults': {
        'action': parse_query_results_action,
        'next_state_func': lambda result, machine: 'Exit',
    },
    'Exit': {
        'action': exit_action,
        'next_state_func': None,
    },
}