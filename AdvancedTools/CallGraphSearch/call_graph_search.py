import os
import tempfile
import subprocess
import re
import shutil
import logging
import time
import random
from pathlib import Path

# Configure logging for this module
logger = logging.getLogger(__name__)

# Get the current directory
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

# Template file path
QLPACK_TEMPLATE_PATH = os.path.join(CURRENT_DIR, "qlpack.yml")

# Default CodeQL search path
DEFAULT_SEARCH_PATH = os.path.join(CURRENT_DIR, "../../StaticAnalysisBackend/Utils/codeql")

class CallGraphTool:
    def __init__(self, codeql_db_path, qlsearch_path=None):
        self.codeql_db_path = codeql_db_path
        self.temp_dir = None
        self.temp_query_path = None
        self.temp_qlpack_path = None
        self.qlsearch_path = qlsearch_path or DEFAULT_SEARCH_PATH
        
    

    def create_point_to_point_query_files(self, to_function_name, to_line, to_file, from_function_name, from_file):
        """Create temporary directory with point-to-point CodeQL query file and qlpack.yml."""
        try:
            # Create a temporary directory
            self.temp_dir = tempfile.mkdtemp(prefix="codeql_query_")
            
            # Use the call_graph_pt.ql template and modify it
            pt_query_path = os.path.join(CURRENT_DIR, "call_graph_pt.ql")
            
            if not os.path.exists(pt_query_path):
                raise FileNotFoundError(f"Template file not found: {pt_query_path}")
                
            with open(pt_query_path, "r") as f:
                query_content = f.read()
            
            # Extract filename from path for matching
            to_filename = os.path.basename(to_file) if to_file else ""
            from_filename = os.path.basename(from_file) if from_file else ""
            
            # Replace the query parameters
            query_content = query_content.replace('callerName = "main"', f'callerName = "{to_function_name}"')
            query_content = query_content.replace('toLine = 123', f'toLine = {to_line}')
            query_content = query_content.replace('toLocation = "src/main.cpp"', f'toLocation = "{to_filename}"')
            query_content = query_content.replace('calleeName = "calculateSum"', f'calleeName = "{from_function_name}"')
            
            # Create the query file in the temporary directory
            self.temp_query_path = os.path.join(self.temp_dir, "point_to_point_query.ql")
            with open(self.temp_query_path, "w", encoding='utf-8') as f:
                f.write(query_content)
            
            # Copy the qlpack.yml to the temporary directory
            if not os.path.exists(QLPACK_TEMPLATE_PATH):
                raise FileNotFoundError(f"qlpack.yml template not found: {QLPACK_TEMPLATE_PATH}")
                
            self.temp_qlpack_path = os.path.join(self.temp_dir, "qlpack.yml")
            shutil.copy(QLPACK_TEMPLATE_PATH, self.temp_qlpack_path)
            
        except Exception as e:
            logger.error(f"Error creating query files: {e}")
            raise

    def run_codeql_query(self):
        """Run the CodeQL query and check if there are any results using the same pattern as functions.py."""
        if not self.temp_query_path or not self.codeql_db_path or not self.temp_dir:
            error_msg = f"Missing required paths - query: {self.temp_query_path}, db: {self.codeql_db_path}, temp_dir: {self.temp_dir}"
            logger.error(error_msg)
            raise ValueError(error_msg)
        
        # Verify database path exists
        if not os.path.exists(self.codeql_db_path):
            error_msg = f"CodeQL database not found: {self.codeql_db_path}"
            logger.error(error_msg)
            raise ValueError(error_msg)
            
        # Check for potential lock files in the database
        db_lock_patterns = [
            os.path.join(self.codeql_db_path, "db-*", "default", "cache", ".lock"),
            os.path.join(self.codeql_db_path, ".lock"),
            os.path.join(self.codeql_db_path, "lock.yml")
        ]
        
        for pattern in db_lock_patterns:
            import glob
            lock_files = glob.glob(pattern)
            for lock_file in lock_files:
                if os.path.exists(lock_file):
                    logger.warning(f"Found lock file: {lock_file}")
                    # Check if we can read/write the lock file
                    try:
                        # Test if we can access the file
                        with open(lock_file, 'r') as f:
                            pass
                        logger.info(f"Lock file {lock_file} is accessible")
                    except PermissionError:
                        logger.error(f"Permission denied accessing lock file: {lock_file}")
                        logger.error("This may cause CodeQL queries to fail. Consider:")
                        logger.error("  1. Running with appropriate permissions")
                        logger.error("  2. Removing the lock file if no other process is using the database")
                        logger.error(f"  3. Command: sudo rm -f {lock_file}")
                    except Exception as e:
                        logger.warning(f"Error checking lock file {lock_file}: {e}")
        
        # Create intermediate and output files
        bqrs_output = os.path.join(self.temp_dir, "query_results.bqrs")
        csv_output = os.path.join(self.temp_dir, "query_results.csv")
        
        try:
            # Step 1: Run codeql query run to generate BQRS file
            cmd1 = [
                "codeql", "query", "run",
                self.temp_query_path,
                "--database", self.codeql_db_path,
                "--output", bqrs_output,
                "--threads", "0"  # Use all available CPU cores for maximum performance
            ]
            
            # Add search path if provided
            if self.qlsearch_path:
                cmd1.extend(["--search-path", self.qlsearch_path])
            
            # Retry logic for handling database lock
            max_retries = 3
            retry_delay = 2
            last_exception = None
            
            for attempt in range(max_retries):
                try:
                    process1 = subprocess.run(
                        cmd1,
                        capture_output=True,
                        text=True,
                        check=True
                    )
                    break  # Success, exit retry loop
                    
                except subprocess.CalledProcessError as e:
                    last_exception = e
                    error_output = e.stderr.lower() if e.stderr else ""
                    
                    # Check for different types of lock errors
                    if "lock" in error_output:
                        # Log the specific error for debugging
                        logger.warning(f"Lock-related error detected: {e.stderr}")
                        
                        # Handle permission denied on lock file
                        if "permission denied" in error_output and ".lock" in e.stderr:
                            logger.error("Permission denied on lock file. This may require fixing file permissions.")
                            # Extract lock file path if possible
                            import re
                            lock_match = re.search(r'([^\s]+\.lock)', e.stderr)
                            if lock_match:
                                lock_path = lock_match.group(1)
                                logger.error(f"Lock file path: {lock_path}")
                                logger.info("Suggestion: Check file permissions or run with appropriate user privileges")
                            
                        # Handle already locked error  
                        elif "already locked" in error_output:
                            if attempt < max_retries - 1:
                                # Add random jitter to avoid thundering herd
                                wait_time = retry_delay + random.uniform(0, 1)
                                logger.warning(f"Database locked, waiting {wait_time:.1f}s before retry {attempt + 1}/{max_retries - 1}")
                                time.sleep(wait_time)
                                continue
                                
                    # Re-raise if not a recoverable lock error or last attempt
                    raise
            
            # If we exhausted retries, raise the last exception
            if last_exception:
                raise last_exception
            
            # Step 2: Decode BQRS to CSV
            if os.path.exists(bqrs_output):
                cmd2 = [
                    "codeql", "bqrs", "decode",
                    "--format=csv",
                    "--output", csv_output,
                    bqrs_output
                ]
                
                process2 = subprocess.run(
                    cmd2,
                    capture_output=True,
                    text=True,
                    check=True
                )
                
                # Step 3: Check if CSV file has results
                if os.path.exists(csv_output):
                    try:
                        with open(csv_output, 'r') as f:
                            content = f.read().strip()
                            lines = content.splitlines()
                            
                            # If there are more than just the header line, we have results
                            has_results = len(lines) > 1 and len(content) > 0
                            
                            return has_results
                    except Exception as e:
                        logger.error(f"Error reading CSV file: {e}")
                        return False
                else:
                    logger.warning("CSV file was not created")
                    return False
            else:
                logger.error("BQRS file was not created")
                return False
                
        except subprocess.CalledProcessError as e:
            logger.error(f"CodeQL process error: {e}")
            logger.error(f"Return code: {e.returncode}")
            logger.error(f"Error output: {e.stderr}")
            logger.error(f"Standard output: {e.stdout}")
            return False
        except FileNotFoundError as e:
            logger.error(f"CodeQL executable not found: {e}")
            logger.error("Please ensure CodeQL is installed and available in PATH")
            return False
        except Exception as e:
            logger.error(f"Unexpected error running CodeQL query: {e}")
            return False

    def cleanup(self):
        """Clean up temporary files and directory."""
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir)
            except Exception as e:
                logger.warning(f"Error during cleanup: {e}")
                
            self.temp_dir = None
            self.temp_query_path = None
            self.temp_qlpack_path = None


def check_point_to_point_call(
    to_function_name: str,
    to_line: int, 
    to_file: str,
    from_function_name: str, 
    from_file: str,
    codeql_db_path: str,
    qlsearch_path: str = None
) -> bool:
    """
    Check if a specific line in to_function calls from_function.
    
    Args:
        to_function_name: The function name that contains the calling line
        to_line: The line number that should contain the call
        to_file: The file containing the to_function
        from_function_name: The function name being called
        from_file: The file containing the from_function
        codeql_db_path: Path to the CodeQL database
        qlsearch_path: Optional path to search for CodeQL libraries
        
    Returns:
        bool: True if the specified line in to_function calls from_function, False otherwise
    """
    # Validate input parameters
    if not all([to_function_name, from_function_name, codeql_db_path]):
        logger.error("Missing required parameters: function names and database path are required")
        return False
        
    if to_line <= 0:
        logger.error(f"Invalid line number: {to_line}")
        return False
    
    # Initialize CallGraphTool with database path and optional search path
    call_graph_tool = CallGraphTool(codeql_db_path, qlsearch_path)
    
    try:
        # Create temporary query files with point-to-point verification
        call_graph_tool.create_point_to_point_query_files(
            to_function_name, to_line, to_file, from_function_name, from_file
        )
        
        # Run the query and return the result directly
        result = call_graph_tool.run_codeql_query()
        return result
        
    except Exception as e:
        logger.error(f"Error in check_point_to_point_call: {e}")
        return False
        
    finally:
        # Always clean up temporary files
        call_graph_tool.cleanup()

if __name__ == "__main__":
    # Configure logging for standalone execution
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Example usage for point-to-point call checking
    # Note: You need to provide the actual CodeQL database path
    db_path = "/path/to/your/codeql/database"  # Replace with actual database path
    
    print("=== Point-to-Point Call Analysis ===")
    print(f"Using CodeQL database: {db_path}")
    
    try:
        point_result = check_point_to_point_call(
            to_function_name="main",
            to_line=123,
            to_file="src/main.cpp",
            from_function_name="calculateSum",
            from_file="src/utils.cpp",
            codeql_db_path=db_path
        )
        
        if point_result:
            print("Line 123 in main() calls calculateSum()")
        else:
            print("Line 123 in main() does NOT call calculateSum()")
        
        # Example with real function names
        print("\n=== Real Example ===")
        real_result = check_point_to_point_call(
            to_function_name="drvdiskintWriteRecord",
            to_line=50,  # Example line number
            to_file="driver.c", 
            from_function_name="drvdiskintR3ReadSectors",
            from_file="driver.c",
            codeql_db_path=db_path
        )
        
        if real_result:
            print("drvdiskintWriteRecord calls drvdiskintR3ReadSectors at line 50")
        else:
            print("drvdiskintWriteRecord does NOT call drvdiskintR3ReadSectors at line 50")
            
    except Exception as e:
        print(f"Error: {e}")
        print("Please ensure you have a valid CodeQL database path and CodeQL is installed.") 