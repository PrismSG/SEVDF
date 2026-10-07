"""
QL Query Modification Configuration
Defines the state machine for modifying QL queries based on iteration context:
- First iteration: Broaden to capture more results
- Compile error: Fix compilation errors
- Result decrease: Try different broadening strategy
"""

from BaseMachine.agent_action_utils import create_agent_action
import os
import json
from QLWorkflow.util.logging_utils import get_ql_workflow_log_path, get_action_type_from_prompt

# Get the directory of the script for relative paths
SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))



def modify_ql_query_action(machine):
    """
    Action to modify QL query based on the iteration context:
    - First iteration: Broaden constraints to capture more results
    - Compile error: Fix the compilation errors
    - Result decrease: Broaden constraints with warning about decrease
    """
    print(f"\n[QL Query Modification] Starting iteration {machine.context.current_iteration} for CWE-{machine.context.cwe_number}")
    print(f"[QL Query Modification] Output dir: {machine.context.output_dir}")
    print(f"[QL Query Modification] Working dir: {getattr(machine.context, 'working_directory', 'Not set')}")
    
    # Determine the modification type based on previous results
    modification_type = "broaden"  # default for first iteration
    extra_context = ""
    
    # Add previous iteration context if not the first iteration
    if machine.context.current_iteration > 1:
        # Build paths to previous iteration's files
        prev_iteration = machine.context.current_iteration - 1
        prev_iteration_dir = os.path.join(machine.context.output_dir, f"iteration_{prev_iteration}")
        prev_ql_path = os.path.join(prev_iteration_dir, "query_results", os.path.basename(machine.context.ql_file_path))
        prev_validation_path = os.path.join(prev_iteration_dir, "validation_conclusion.json")
        
        extra_context = f"\n\nPREVIOUS ITERATION CONTEXT:"
        extra_context += f"\nPrevious Modified QL: {prev_ql_path}"
        extra_context += f"\nPrevious Validation Conclusion: {prev_validation_path}"
        extra_context += "\n\nPlease read the previous validation conclusion to understand what needs improvement."
    
    if machine.context.previous_results:
        last_result = machine.context.previous_results
        if isinstance(last_result, dict):
            # Check for compile error
            if last_result.get('compile_error'):
                modification_type = "fix_compile_error"
                extra_context += f"\n\nPREVIOUS COMPILATION ERROR:\n{last_result.get('error_message', '')}\n\nYou MUST fix this compilation error."
            # Check for result decrease
            elif last_result.get('result_decreased'):
                modification_type = "broaden_with_warning"
                extra_context += f"\n\nWARNING: The previous modification resulted in FEWER results ({last_result.get('previous_count', 0)} -> {last_result.get('current_count', 0)}).\nThis approach seems to be reducing results instead of increasing them. Please try a different broadening strategy."
    
    # Read library paths from previous iteration if available
    library_paths_info = ""
    if machine.context.current_iteration > 1:
        prev_iteration = machine.context.current_iteration - 1
        prev_iteration_dir = os.path.join(machine.context.output_dir, f"iteration_{prev_iteration}")
        library_paths_file = os.path.join(prev_iteration_dir, "query_results", "library_paths.json")
        if os.path.exists(library_paths_file):
            with open(library_paths_file, 'r') as f:
                library_paths = json.load(f)
                if library_paths:
                    library_paths_info = f"\n\nPREVIOUS LIBRARY MODIFICATIONS:\n"
                    for lib_info in library_paths:
                        library_paths_info += f"- Original: {lib_info['original_path']}\n"
                        library_paths_info += f"  Modified: {lib_info['modified_path']}\n"
    
    
    # Get the base filename without extension for dynamic file naming
    ql_base_name = os.path.splitext(os.path.basename(machine.context.ql_file_path))[0]
    
    
    # Both "broaden" and "broaden_with_warning" use similar prompts
    prompt_template = """You are a CodeQL expert tasked with modifying QL queries to capture more potential security vulnerabilities by removing unnecessary constraints.

CWE Number: {cwe_number}
{extra_context}{library_paths_info}

MANDATORY VERIFICATION WORKFLOW:
You MUST follow this EXACT process and NOT stop until BOTH conditions are satisfied:

STEP 1: Get Origin Result Count and Recall Rate
First, check the origin results from evaluation_summary.json:
```bash
# Check true positive count and recall rate
cat {query_origin_dir}/evaluation_summary.json | jq '.true_positive_count, .recall'
```
RECORD THESE NUMBERS - your goal is to improve the recall rate!

STEP 2: Modify Query and Test Loop
1. Read and modify the query at: {codeql_dir}/{ql_base_name}_modified.ql
   IMPORTANT: You must MODIFY the existing query logic, not rewrite it completely!
   - Keep the same vulnerability pattern (e.g., redundant null checks)
   - Broaden by removing restrictions to improve recall
   - The query should still detect the same TYPE of vulnerability, just MORE instances
2. Broaden the query to capture more results (see guidelines below)
3. Test compilation and execution (use tmp directory for output to avoid overwriting the original query):
```bash
# Create temp directory in the workspace
mkdir -p {output_dir}/.tmp
python3 {run_juliet_path} --run-query-sarif --cwe {cwe_number} --ql {codeql_dir}/{ql_base_name}_modified.ql --output {output_dir}/.tmp/ql_test_{cwe_number} --with-eval
```
4. If compilation fails, go back to step 1 and fix syntax errors
5. If compilation succeeds, check the evaluation results:
```bash
# Check true positive count and recall rate
cat {output_dir}/.tmp/ql_test_{cwe_number}/evaluation_summary.json | jq '.true_positive_count, .recall'
```
6. Compare: If recall rate hasn't improved, go back to step 1 with MORE aggressive broadening
7. Only stop when: COMPILATION SUCCESS AND IMPROVED RECALL RATE

CRITICAL SUCCESS CRITERIA:
[REQUIRED] Query compiles without errors
[REQUIRED] Recall rate is IMPROVED (more bad functions detected)

PRIMARY GOAL: IMPROVE RECALL RATE
- Recall = (True Positives / Total Bad Functions) * 100
- Your goal is to detect more of the bad functions in the test suite
- Even if precision drops slightly, improving recall is the priority
- Focus on broadening the query to catch more vulnerabilities

BROADENING STRATEGIES - Six Restriction Categories:
The framework systematically addresses six restriction categories that commonly suppress vulnerability detection.
Apply these strategies iteratively through a unified optimization process:

1. **Source Restrictions** - Relaxing Input Constraints:
   - The original query may exclude valid taint entry points that could lead to vulnerabilities
   - Expand to include additional input sources: file I/O, network sockets, environment variables,
     command-line arguments, database reads, deserialized data, inter-process communication
   - Remove type-specific restrictions that limit source recognition
   - Consider indirect sources: configuration files, cached data, session state

2. **Sink Restrictions** - Broadening Dangerous Operations:
   - Original sinks may omit security-critical operations where tainted data causes harm
   - Include additional vulnerable operations: memory manipulation, command execution,
     file system operations, SQL queries, dynamic code evaluation, cryptographic functions
   - Add wrapper functions and utility methods that internally invoke dangerous operations
   - Consider framework-specific sinks and library API endpoints

3. **Sanitizer Restrictions** - Preventing Premature Taint Termination:
   - Overly aggressive sanitizers may terminate taint tracking before reaching actual sinks
   - Remove or weaken validation checks that incorrectly mark data as safe
   - Distinguish between partial sanitization (encoding) and complete sanitization (validation)
   - Consider bypass scenarios: double encoding, type juggling, alternative data paths
   - Evaluate whether sanitizers truly neutralize the specific vulnerability class

4. **Flow Restrictions** - Relaxing Dominance and Path Constraints:
   - Strict data flow dominance requirements may miss valid vulnerability paths
   - Allow taint propagation through additional intermediate processing functions
   - Include implicit flows: array indexing, conditional assignments, exception handlers
   - Relax interprocedural constraints that block cross-function taint tracking
   - Consider flow through callbacks, closures, and asynchronous operations

5. **Pattern Restrictions** - Accommodating Structural Variations:
   - Rigid code structure requirements may miss semantically equivalent vulnerability patterns
   - Add alternative syntax patterns and code idioms that represent the same vulnerability
   - Include obfuscated or transformed versions: encoded strings, indirect calls, reflection
   - Consider language-specific variations and coding style differences
   - Account for compiler optimizations and code transformations

6. **Context/Scope Restrictions** - Removing Artificial Analysis Limits:
   - Imposed analysis boundaries may exclude reachable vulnerable code
   - Expand scope to include utility functions, helper classes, and shared libraries
   - Remove namespace or module restrictions that artificially limit analysis
   - Include test code, generated code, and conditional compilation paths
   - Consider cross-module and cross-package vulnerability patterns

FAILURE RECOVERY STRATEGIES:
If recall rate doesn't improve after multiple attempts:
- Try removing ALL validation barriers temporarily
- Add extremely broad operation sinks
- Include indirect vulnerability patterns
- Consider vulnerabilities in utility functions
- Add encoded/obfuscated patterns
- Remove all safety checks temporarily to see if results increase

LIBRARY MODIFICATION GUIDELINES:
When you need to modify QL library files:
1. DO NOT modify the original library file directly
2. Create a copy of the library file in the same directory with '_modified' suffix
   Example: DataFlow.qll -> DataFlow_modified.qll
3. Update the import statement in your query to use the modified library
   Example: import DataFlow -> import DataFlow_modified
4. Track all library modifications in a JSON file at:
   {output_dir}/.tmp/library_paths.json
   Format: [{{"original_path": "...", "modified_path": "...", "import_change": "..."}}]
5. If modifying multiple libraries, ensure they import each other correctly
6. Common library files that can be modified:
   - Data flow configuration files (e.g., DataFlow.qll, TaintTracking.qll)
   - Source/sink definition files
   - Custom library files specific to the CWE
   - Helper predicates and utility libraries
7. Use the Read tool to examine library imports and Write/Edit tools to create modified versions
8. Document changes clearly in the modified library file

FINAL STEP - SAVE YOUR WORK:
After achieving success, you MUST save the final working query to the exact location:
{codeql_dir}/{ql_base_name}_modified.ql

"""
    if modification_type == "fix_compile_error":
        prompt_template += "\n# You MUST fix the compilation errors reported below:\n{extra_context}\n"
    
    # Set up logging context for QLWorkflow
    log_context = {
        'cwe_number': machine.context.cwe_number,
        'query_name': machine.context.query_name if hasattr(machine.context, 'query_name') else f"CWE-{machine.context.cwe_number:03d}",
        'iteration': machine.context.current_iteration,
        'output_dir': machine.context.output_dir
    }
    
    # Get the log path and action type
    log_path = get_ql_workflow_log_path(log_context)
    if log_path:
        machine.context.session_log_path = str(log_path)  # Convert Path to string
    
    # Determine action type from prompt
    run_juliet_path = os.path.join(SCRIPT_DIR, 'run_juliet.py')
    formatted_prompt_preview = prompt_template.format(
        cwe_number=machine.context.cwe_number,
        extra_context="",
        library_paths_info="",
        query_origin_dir="",
        codeql_dir="",
        ql_base_name="",
        ql_file_path="",
        output_path="",
        output_dir="",  # Add the missing output_dir parameter
        run_juliet_path=run_juliet_path
    )[:500]  # Just check the beginning
    machine.context.action_type = get_action_type_from_prompt(formatted_prompt_preview)
    
    # Use agent action for agent mode with streaming JSON logging enabled
    action = create_agent_action(
        prompt_template=prompt_template,
        save_option='both',
        system_prompt="You are a CodeQL expert. Help modify CodeQL queries to capture more potential security vulnerabilities while maintaining accuracy. You have access to tools to write and test the queries. Use Write to save queries, Bash to test compilation and run queries, Read to examine files, and Grep to analyze CSV results. You must ensure both compilation success AND increased result count compared to origin.",
        allowed_tools=["Read", "Write", "Bash", "Edit", "Grep", "LS"],
        max_turns=50,  # Allow more turns for the mandatory verification loop
        enable_stream_logging=True
    )
    
    # Calculate paths for the current iteration
    iteration_dir = os.path.join(machine.context.output_dir, f"iteration_{machine.context.current_iteration}")
    query_results_dir = os.path.join(iteration_dir, "query_results")
    os.makedirs(query_results_dir, exist_ok=True)  # Ensure directory exists for agent
    
    ql_filename = os.path.basename(machine.context.ql_file_path)
    
    # Input: for iteration 1, from initial/query_results/; for others, from previous iteration/query_results/
    if machine.context.current_iteration == 1:
        input_origin_dir = os.path.join(machine.context.output_dir, "initial", "query_results")
        # For iteration 1, use the original filename
        input_filename = ql_filename
    else:
        prev_iteration = machine.context.current_iteration - 1
        input_origin_dir = os.path.join(machine.context.output_dir, f"iteration_{prev_iteration}", "query_results")
        # For subsequent iterations, use the modified filename from previous iteration
        ql_base_name_no_ext = os.path.splitext(ql_filename)[0]
        input_filename = f"{ql_base_name_no_ext}_modified.ql"
    
    input_ql_path = os.path.join(input_origin_dir, input_filename)
    
    # Check if input file exists, if not try with original filename for backward compatibility
    if not os.path.exists(input_ql_path) and machine.context.current_iteration > 1:
        # Try the original filename as fallback
        input_ql_path_fallback = os.path.join(input_origin_dir, ql_filename)
        if os.path.exists(input_ql_path_fallback):
            input_ql_path = input_ql_path_fallback
            print(f"[QL Query Modification] Using fallback path: {input_ql_path}")
        else:
            print(f"[QL Query Modification] ERROR: Input file not found at: {input_ql_path}")
            print(f"[QL Query Modification] Also tried fallback: {input_ql_path_fallback}")
            # List what files are actually in the directory
            if os.path.exists(input_origin_dir):
                print(f"[QL Query Modification] Files in {input_origin_dir}:")
                for f in os.listdir(input_origin_dir):
                    if f.endswith('.ql'):
                        print(f"  - {f}")
    
    # Output should be in current iteration's query_results directory with _modified suffix
    # Remove any existing _modified suffix to prevent _modified_modified.ql
    ql_base_name = os.path.splitext(ql_filename)[0]
    if ql_base_name.endswith('_modified'):
        ql_base_name = ql_base_name[:-9]  # Remove '_modified' suffix
    output_filename = f"{ql_base_name}_modified.ql"
    output_path = os.path.join(query_results_dir, output_filename)
    
    # Get the codeql directory path from original_ql_path
    # This path has already been converted to project codeql path in pipeline_config.py
    original_ql_path = machine.context.original_ql_path
    
    # Since original_ql_path is already pointing to the correct project codeql directory,
    # we just need to extract the directory path
    codeql_dir = os.path.dirname(original_ql_path)
    print(f"[QL Query Modification] Using codeql_dir: {codeql_dir}")
    

    # Copy the input query to codeql directory for modification
    import shutil
    # ql_base_name already calculated above (with _modified suffix removed)
    modified_ql_path = os.path.join(codeql_dir, f'{ql_base_name}_modified.ql')
    shutil.copy2(input_ql_path, modified_ql_path)
    print(f"[QL Query Modification] Copied input query to: {modified_ql_path}")
    
    # Format the prompt for saving
    run_juliet_path = os.path.join(SCRIPT_DIR, 'run_juliet.py')
    formatted_prompt = prompt_template.format(
        cwe_number=machine.context.cwe_number,
        ql_file_path=input_ql_path,  # Use the input path (initial/ or previous iteration/)
        output_path=output_path,
        query_origin_dir=input_origin_dir,  # For checking origin result count
        codeql_dir=codeql_dir,  # For copying and testing
        ql_base_name=ql_base_name,  # For dynamic file naming
        extra_context=extra_context,
        library_paths_info=library_paths_info,
        run_juliet_path=run_juliet_path,
        output_dir=machine.context.output_dir  # Add output_dir for the prompt
    )
    
    # Save the prompt to iteration/reports directory
    iteration_dir = os.path.join(machine.context.output_dir, f"iteration_{machine.context.current_iteration}")
    reports_dir = os.path.join(iteration_dir, "reports")
    os.makedirs(reports_dir, exist_ok=True)
    prompt_file = os.path.join(reports_dir, "01_modification_prompt.txt")
    with open(prompt_file, 'w') as f:
        f.write(formatted_prompt)
    
    # Call the action with the formatted parameters
    print(f"[QL Query Modification] Sending query to LLM for modification (type: {modification_type})...")
    result = action(machine, 
                  cwe_number=machine.context.cwe_number,
                  ql_file_path=input_ql_path,  # Use the input path (initial/ or previous iteration/)
                  output_path=output_path,
                  query_origin_dir=input_origin_dir,  # For checking origin result count
                  query_after_dir=query_results_dir,  # For library_paths.json location
                  codeql_dir=codeql_dir,  # For copying and testing
                  ql_base_name=ql_base_name,  # For dynamic file naming
                  extra_context=extra_context,
                  library_paths_info=library_paths_info,
                  run_juliet_path=run_juliet_path,
                  output_dir=machine.context.output_dir)  # Add output_dir for absolute path construction
    print(f"[QL Query Modification] LLM response received")
    
    # Save the response too - agent mode returns a dict with 'response' key
    response_file = os.path.join(reports_dir, "01_modification_response.txt")
    if isinstance(result, dict) and 'response' in result:
        with open(response_file, 'w') as f:
            f.write(result['response'])
        # Store response for later use
        machine.context.modification_response = result['response']
    elif isinstance(result, str):
        with open(response_file, 'w') as f:
            f.write(result)
        machine.context.modification_response = result
    
    # Copy the modified query from codeql directory to output location
    if os.path.exists(modified_ql_path):
        try:
            shutil.copy2(modified_ql_path, output_path)
            print(f"[QL Query Modification] Copied modified query to: {output_path}")
            
            # Set the modified_ql_path in context immediately after successful copy
            machine.context.modified_ql_path = output_path
            print(f"[QL Query Modification] Set context.modified_ql_path to: {output_path}")
            
            # Keep the modified file for debugging - don't delete it
            # This allows us to compare what the agent tested vs what was run
            print(f"[QL Query Modification] Keeping modified file at: {modified_ql_path} for debugging")
        except Exception as e:
            print(f"[QL Query Modification] Error handling modified file: {e}")
    else:
        print(f"[QL Query Modification] Warning: Modified file not found at {modified_ql_path}")
    
    # Copy .tmp/library_paths.json to reports directory if it exists
    tmp_library_paths = os.path.join(machine.context.output_dir, ".tmp", "library_paths.json")
    if os.path.exists(tmp_library_paths):
        try:
            reports_library_paths = os.path.join(reports_dir, "library_paths.json")
            shutil.copy2(tmp_library_paths, reports_library_paths)
            print(f"[QL Query Modification] Copied library paths to: {reports_library_paths}")
        except Exception as e:
            print(f"[QL Query Modification] Error copying library paths: {e}")
    
    return result


def exit_action(machine):
    """Exit action - returns the output path where agent saved the modified query."""
    import os
    
    # The agent should have saved the file to the output_path specified in the prompt
    iteration_dir = os.path.join(machine.context.output_dir, f"iteration_{machine.context.current_iteration}")
    query_results_dir = os.path.join(iteration_dir, "query_results")
    
    # Get base filename and add _modified suffix
    ql_filename = os.path.basename(machine.context.ql_file_path)
    ql_base_name = os.path.splitext(ql_filename)[0]
    # Remove any existing _modified suffix to prevent double suffixing
    if ql_base_name.endswith('_modified'):
        ql_base_name = ql_base_name[:-9]
    output_filename = f"{ql_base_name}_modified.ql"
    output_path = os.path.join(query_results_dir, output_filename)
    
    # Update context with the path where agent saved the file
    machine.context.modified_ql_path = output_path
    
    print(f"[QL Query Modification] Modified query saved by agent to: {output_path}")
    
    return output_path


# State machine configuration for query modification
state_definitions = {
    'ModifyQLQuery': {
        'action': modify_ql_query_action,
        'next_state_func': lambda result, machine: 'Exit',  # Go directly to Exit since agent saves the file
    },
    'Exit': {
        'action': exit_action,
        'next_state_func': None,
    },
}