import sqlite3
import subprocess
import csv
import os
import io
from .utils import Logger
import tempfile

logger = Logger(log_level='error')

class CFGDatabaseHelper:
    def __init__(self, codeql_path, db_path, result_path, query_path="./queries"):
        self.codeql_path = codeql_path
        self.db_path = db_path
        self.result_path = result_path
        self.query_path = query_path
        self.conn = sqlite3.connect(result_path)
        self.cursor = self.conn.cursor()
        self.initialize_database()
        self.initialize_qlpack()

    def initialize_database(self):
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS query_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                query_name TEXT,
                query_params TEXT,
                result_data TEXT
            )
            """
        )
        self.conn.commit()

    def initialize_qlpack(self):
        qlpack_data = """---
name: getting-started/codeql-extra-queries-wasm
version: 1.0.0
dependencies:
    codeql/cpp-all: ^0.12.7
"""
        with open("/tmp/qlpack.yml", "w") as f:
            f.write(qlpack_data)

    def close(self):
        self.conn.close()

    def get_query_result(self, query_name, query_params):
        self.cursor.execute(
            """
            SELECT result_data FROM query_results 
            WHERE query_name = ? AND query_params = ?
            """,
            (query_name, str(query_params)),
        )

        records = self.cursor.fetchall()
        if records:
            logger.log("Found in database.")
            msg = self.parse_query_result(records)
        else:
            msg = self.run_codeql_query(query_name, query_params)
        logger.debug(f"{query_name}")
        logger.debug(msg)
        return msg

    def delete_query_result(self, query_name, query_params):
        self.cursor.execute(
            """
            DELETE FROM query_results
            WHERE query_name = ? AND query_params = ?
            """,
            (query_name, str(query_params)),
        )
        self.conn.commit()

    def parse_query_result(self, records):
        res = []
        for record in records:
            csv_string = record[0]
            if csv_string:
                csv_file_like = io.StringIO(csv_string)
                csv_reader = csv.reader(csv_file_like)
                next(csv_reader)  # Skip header
                for row in csv_reader:
                    res.append(row)
        return res

    def run_codeql_query(self, query_name, query_params):
        logger.log(f"Running query {query_name}")

        query_file = self.query_path + f"/{query_name}.ql"
        with open(query_file, "r") as f:
            query = f.read()

        query = query.format(**query_params)

        temp_query_file = tempfile.mkstemp(".ql", query_name, "/tmp")[1]

        with open(temp_query_file, "w") as f:
            f.write(query)

        output_file = tempfile.mkstemp(".bqrs", query_name, "/tmp")[1]

        # Use codeql query run to generate .bqrs file
        cmd_run = [
            self.codeql_path, 'query', 'run',
            temp_query_file,
            '--database', self.db_path,
            # '--search-path', ql_search_path,
            '--output', output_file
        ]

        print("Running CodeQL query:", cmd_run)
        subprocess.run(cmd_run, check=True)

        # Decode .bqrs file to CSV
        csv_output_file = tempfile.mkstemp(".csv", query_name, "/tmp")[1]
        cmd_decode = [
            self.codeql_path, 'bqrs', 'decode',
            '--format=csv',
            '--output', csv_output_file,
            output_file
        ]

        print("Decoding BQRS to CSV:", cmd_decode)
        subprocess.run(cmd_decode, check=True)

        # Parse CSV file and insert into database
        res = []
        with open(csv_output_file, "r") as f:
            reader = csv.reader(f)
            # Skip the header row
            headers = next(reader)
            # Read the rest of the file and store the rows in 'res'
            for row in reader:
                res.append(row)

            # Go back to the start of the file to read the full content for 'csv_content'
            f.seek(0)
            result_data = f.read()
            # Insert the CSV content into the database
            self.cursor.execute(
                """
                INSERT INTO query_results (query_name, query_params, result_data)
                VALUES (?, ?, ?)
                """,
                (query_name, str(query_params), result_data),
            )

        self.conn.commit()

        os.remove(temp_query_file)
        os.remove(output_file)
        os.remove(csv_output_file)

        return res
