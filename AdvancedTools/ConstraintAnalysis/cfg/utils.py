# logger.py
import json
import re
import os

# Elasticsearch imports (required for ESHelper class)
try:
    from elasticsearch import Elasticsearch
    from elasticsearch.helpers import bulk
except ImportError:
    # Allow file to import even if elasticsearch is not installed
    Elasticsearch = None
    bulk = None

class Logger:
    def __init__(self, log_level: str = "log"):
        self.log_level = log_level

    def set_log_level(self, log_level: str):
        self.log_level = log_level

    def log(self, message: str):
        if self.log_level in ["log"]:
            print(f"[LOG] {message}")

    def debug(self, message: str):
        if self.log_level in ["log", "debug"]:
            print(f"[DEBUG] {message}")

    def error(self, message: str):
        if self.log_level in ["log", "debug", "error"]:
            print(f"[ERROR] {message}")


class FileReader:
    def __init__(self, file_dir: str = ""):
        self.file_dir = file_dir

    def read_file_by_id(self, file_path, block_id):
        startline, startcolumn = map(int, block_id.split("_")[0].split("."))
        endline, endcolumn = map(int, block_id.split("_")[1].split("."))
        return self.read_file_by_lc(
            file_path, startline, startcolumn, endline, endcolumn
        )

    def read_file_by_lc(
        self, file_path, start_line, start_column, end_line, end_column
    ):
        file_path = os.path.join(self.file_dir, file_path)

        if start_line < 1 or end_line < 1:
            print(f"Invalid line {file_path}:{start_line}.{start_column}:{end_line}.{end_column}")
            return ""

        if start_line > end_line:
            end_line = start_line+2
            print(f"Invalid line start_line>end_line {file_path}:{start_line}.{start_column}:{end_line}.{end_column}")

        with open(file_path, "r") as file:
            # Skip lines before start_line
            for _ in range(start_line - 1):
                next(file, None)

            # Read the required line(s)
            if start_line == end_line:
                # If start and end lines are the same, read only one line
                line = next(file, "")
                return line[start_column - 1 : end_column + 1].rstrip("\n")
            else:
                result = []
                for current_line, line in enumerate(file, start=start_line):
                    if current_line > end_line:
                        break

                    if current_line == start_line:
                        line = line[start_column - 1 :]
                    elif current_line == end_line:
                        line = line[: end_column + 1]

                    result.append(line.rstrip("\n"))

                return "".join(result)


    # COMMENTED OUT - Requires CppTokenFinder which uses clang
    # def read_condition_statement_by_id(self, file_path, block_id):
    #     startline, startcolumn = map(int, block_id.split("_")[0].split("."))
    #     endline, endcolumn = map(int, block_id.split("_")[1].split("."))
    #
    #     guess_line = 3
    #     if "0.0_" in block_id:
    #         startline = endline - guess_line if endline - guess_line > 1 else 1
    #     if "_0.0" in block_id:
    #         endline = startline + guess_line
    #
    #     token_finder = CppTokenFinder(os.path.join(self.file_dir, file_path))
    #
    #     # IF
    #     cond_op = ["if", "||", "&&", "or", "and"]
    #     # Guess cond op in [endline - 1, endline]
    #     cond_token = token_finder.find_tokens_reverse(
    #         cond_op, endline -1 if endline - 1 > 1 else 1, 0, endline, endcolumn
    #     )
    #
    #     if cond_token is not None:
    #         print("COND:", cond_token.location.line, cond_token.location.column)
    #         paren= token_finder.get_paren_end_or_logic_op(cond_token)
    #         print("paren", paren.location.line, paren.location.column )
    #         result = self.read_file_by_lc(
    #                 file_path, cond_token.location.line , cond_token.location.column , paren.location.line, paren.location.column
    #             )
    #         result = re.sub(r'^\s*(\|\||&&|or|and)\s*(.*)', r'if (\2', result)
    #         result = re.sub(r'(\|\||&&|or|and)\s*$', ')', result)
    #         return result
    #
    #     # MACRO
    #     macro_reserved_word = [
    #         "VALIDATE_INDEX",
    #         "VALIDATE_UNLESS",  # WAVM
    #         "_   (",
    #         "_throwif",  # wasm3
    #     ]
    #
    #     token = token_finder.find_tokens_reverse(
    #         macro_reserved_word, startline, startcolumn, endline, endcolumn
    #     )
    #     if token is not None:
    #         result = self.read_file_by_lc(
    #             file_path, token.location.line, token.location.column, endline, endcolumn
    #         )
    #         return result
    #
    #     # "_   ("
    #     token = token_finder.find_token_reverse(
    #         "_", startline, startcolumn-1, endline, endcolumn
    #     )
    #     if token is not None:
    #         token1 = token_finder.get_token_after(
    #             token.location.line, token.location.column
    #         )
    #         print("token.location.line1", token1.location.line, token1.location.column)
    #         print("token.location.line", token.location.line, token.location.column)
    #
    #         if token1.spelling == "(":
    #             result = self.read_file_by_lc(
    #                 file_path, token.location.line, token.location.column, endline, endcolumn
    #             )
    #             return result
    #
    #     # Default
    #     print("No IF, No MACRO")
    #     return self.read_file_by_lc(
    #         file_path, endline, 1, endline, endcolumn
    #     )

    # COMMENTED OUT - Requires CppTokenFinder which uses clang
    # def read_code_context_by_id(self, function_id, file_path, block_id):
    #     startline_func, startcolumn_func = map(
    #         int, function_id.split("_")[0].split(".")
    #     )
    #     endline_func, endcolumn_func = map(int, function_id.split("_")[1].split("."))
    #
    #     # If the function is too small, return the entire function
    #     if endline_func - startline_func < 10:
    #         return self.read_file_by_lc(
    #             file_path,
    #             startline_func,
    #             startcolumn_func,
    #             endline_func,
    #             endcolumn_func,
    #         )
    #
    #     startline, startcolumn = map(int, block_id.split("_")[0].split("."))
    #     endline, endcolumn = map(int, block_id.split("_")[1].split("."))
    #
    #     startline = (
    #         startline - 5 if startline - 5 > startline_func + 1 else startline_func + 1
    #     )
    #     endline = endline + 5 if endline + 5 < endline_func - 1 else endline_func - 1
    #
    #     token_finder = CppTokenFinder(os.path.join(self.file_dir, file_path))
    #     token1 = token_finder.find_token_forward(
    #         "{", startline, startcolumn, endline, endcolumn
    #     )
    #     token2 = token_finder.find_token_after(
    #         "}", endline, endcolumn
    #     )
    #     if token1 is not None and token2 is not None:
    #         return self.read_file_by_lc(
    #             file_path, token1.location.line, token1.location.column, token2.location.line, token2.location.column
    #         )
    #     else:
    #         text = self.read_file_by_lc(
    #             file_path, startline, startcolumn, endline, endcolumn
    #         )
    #         return text


class ESHelper:
    def __init__(self, index_name, scheme="http", host="localhost", port=9200):
        self.es = Elasticsearch([f"{scheme}://{host}:{port}"])
        self.index_name = index_name
        self.create_index()

    def create_index(self):
        if not self.es.indices.exists(index=self.index_name):
            mappings = {
                "properties": {
                    "project_name": {"type": "keyword"},
                    "file_name": {"type": "keyword"},
                    "block_id": {"type": "keyword"},
                    "function_name": {"type": "keyword"},
                    "statement": {"type": "text"},
                    "code_context": {"type": "text"},
                    "involved_function_declaration": {"type": "object"},
                    "description": {"type": "text"},
                    "isSpec": {"type": "boolean"},
                }
            }
            self.es.indices.create(index=self.index_name, body={"mappings": mappings})

    def add(self, data):
        doc_id = f"{data['function_name']}@{data['file_name']}:{data['block_id']}"
        self.es.index(index=self.index_name, id=doc_id, body=data)

    def bulk_index(self, documents):
        actions = [
            {
                "_index": self.index_name,
                "_id": f"{doc['project_name']}@{doc['file_name']}:{doc['block_id']}",
                "_source": doc,
            }
            for doc in documents
        ]
        bulk(self.es, actions)

    def update(self, function_name, file_name, block_id, update_data):
        doc_id = f"{function_name}@{file_name}:{block_id}"
        self.es.update(index=self.index_name, id=doc_id, body={"doc": update_data})

    def delete(self, function_name, file_name, block_id):
        doc_id = f"{function_name}@{file_name}:{block_id}"
        self.es.delete(index=self.index_name, id=doc_id)

    def get(self, function_name, file_name, block_id):
        doc_id = f"{function_name}@{file_name}:{block_id}"
        try:
            result = self.es.get(index=self.index_name, id=doc_id)
            return result["_source"]
        except:
            return None

    def search(self, query):
        results = self.es.search(index=self.index_name, body=query)
        return {
            "took": results["took"],
            "timed_out": results["timed_out"],
            "hits": {
                "total": results["hits"]["total"],
                "max_score": results["hits"]["max_score"],
                "hits": [hit["_source"] for hit in results["hits"]["hits"]],
            },
        }
