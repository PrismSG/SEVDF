import os
import sys
import logging
from colorama import Fore
# from flow_analysis.flow_context import execStep

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(current_dir, '../../AdvancedTools/CodeSearch'))
sys.path.append(parent_dir)

from AdvancedTools.CodeSearch.opengrok_search import CodeQueryManager  # Corrected import path

def query_symbol_definition(symbol, port=8080):
    """
    Query the definition of a symbol using CodeQueryManager.
    """
    os.environ['OPENGROK_STATUS'] = 'ready'
    query_manager = CodeQueryManager(port)
    results = query_manager.query_definition(symbol)
    return results
