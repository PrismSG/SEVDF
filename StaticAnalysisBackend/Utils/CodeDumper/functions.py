import os
import subprocess

query_file_path = os.path.join(os.path.dirname(__file__), 'function_dump.ql')
ql_search_path = os.path.join(os.path.dirname(__file__), '../codeql')  # CodeQL query file search path

class FunctionListExtractor:
    def __init__(self, codeql_db_path, output_csv):
        self.codeql_db_path = codeql_db_path  # database path as parameter
        self.output_csv = output_csv
        self.query_file = query_file_path  # always use function_dump.ql in the current directory
        self.bqrs_output = '/tmp/codeql-results.bqrs'  # intermediate result file

    def run_codeql_query(self):
        # check if the database exists
        if not os.path.exists(self.codeql_db_path):
            raise FileNotFoundError(f"CodeQL database not found at {self.codeql_db_path}")

        # run codeql query, generate intermediate result file
        cmd = [
            'codeql', 'query', 'run',
            self.query_file,
            '--database', self.codeql_db_path,
            '--search-path', ql_search_path,
            '--output', self.bqrs_output
        ]
        print(cmd)
        print('Running CodeQL query to generate function list...')
        subprocess.run(cmd, check=True)

    def decode_bqrs_to_csv(self):
        # decode .bqrs file to csv format
        cmd = [
            'codeql', 'bqrs', 'decode',
            '--format=csv',
            '--output', self.output_csv,
            self.bqrs_output
        ]
        print('Decoding BQRS to CSV...')
        subprocess.run(cmd, check=True)

    def cleanup(self):
        # delete the intermediate .bqrs file
        if os.path.exists(self.bqrs_output):
            os.remove(self.bqrs_output)
            print(f'Removed temporary file {self.bqrs_output}')

    def extract_functions(self):
        self.run_codeql_query()
        self.decode_bqrs_to_csv()
        self.cleanup()
        print(f'Function list exported to {self.output_csv}')

# Example usage:
# extractor = FunctionListExtractor('/path/to/codeql-db', 'output.csv')
# extractor.extract_functions()
