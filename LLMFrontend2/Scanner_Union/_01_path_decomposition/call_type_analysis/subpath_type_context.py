from pydantic import BaseModel
from typing import List

class SubpathTypeFlowContext(BaseModel):
    fromCode: str
    fromLocation: str
    toCode: str
    toLocation: str
    relatedCode: str
    codeql_db_path: str = None  # Optional field for CodeQL database path
    toFunctionName: str = None  # Function name containing the calling line
    fromFunctionName: str = None  # Function name being called

class Call(BaseModel):
    to_call_from: bool