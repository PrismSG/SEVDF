#!/usr/bin/env python3
"""
Scanner-Union Entry Point
Alternative scanner implementation with batch processing and Logic Unit management
"""
import sys
import os
import json
import logging
import argparse
from typing import List, Dict, Any, Optional
from datetime import datetime
import time

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))

# Import necessary types
from ._01_path_decomposition.path_decomposition_context import FlowStepDivide
from .analysis_context import AnalysisContext

# Import necessary components
# from BaseMachine.cwe_validator import CWEValidator  # Not needed

# Import unified coordinator
from ._00_unified_analysis_scheduling.unified_coordinator import UnifiedCoordinator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ScannerUnionAnalyzer:
    """
    Main analyzer class that coordinates batch analysis using Scanner-Union
    """
    
    def __init__(self, cwe_code: str, project_name: str, cwe_cot_config_file: str, model_name: str = "gpt-4", cwe_data=None, output_dir: str = None):
        self.cwe_code = cwe_code
        self.project_name = project_name
        self.model_name = model_name
        self.cwe_data = cwe_data  # Store the cwe_data object
        self.output_dir = output_dir  # Output directory for results
        
        # Load the configuration for per-unit reasoning.
        with open(cwe_cot_config_file, 'r', encoding='utf-8') as f:
            self.cwe_cot_config = json.load(f)
        
        # Create unified coordinator with cwe_data
        self.coordinator = UnifiedCoordinator(cwe_code, project_name, self.cwe_cot_config, model_name, cwe_data=cwe_data)
        
        # Pass output directory to coordinator if specified
        if output_dir:
            self.coordinator.output_dir = output_dir
        
        # Initialize validator
        # self.validator = CWEValidator()  # Not needed
    
    def analyze_paths(self, flow_steps: List[FlowStepDivide], total_paths: int = None) -> Dict[str, Any]:
        """
        Analyze all paths

        Args:
            flow_steps: List of flow step objects to analyze
            total_paths: Total number of paths (for statistics)
        """
        # Use unified coordinator for processing
        return self.coordinator.process_paths(flow_steps, total_paths=total_paths)


def load_path_info_list(path_info_file):
    """Load path info list from JSON file"""
    logger.info(f"Loading path info from {path_info_file}")
    
    with open(path_info_file, 'r') as f:
        path_info_list = json.load(f)
    
    if not isinstance(path_info_list, list):
        raise ValueError("Path info file must contain a JSON array")
    
    logger.info(f"Loaded {len(path_info_list)} path info items")
    
    # Convert to FlowStepDivide objects
    flow_steps = []
    for idx, path_info in enumerate(path_info_list):
        try:
            # Convert path_info dict/string to JSON string if needed
            if isinstance(path_info, dict):
                path_info_json = json.dumps(path_info)
            else:
                path_info_json = path_info
                
            # Parse JSON and convert to FlowStepDivide
            from ._01_path_decomposition.path_decomposition_tools import parse_json_to_flow_step_divide
            flow_step = parse_json_to_flow_step_divide(path_info_json)
            
            # Extract variable name from source or first step
            path_data = json.loads(path_info_json) if isinstance(path_info_json, str) else path_info
            variable_name = path_data.get('source', {}).get('variable', 'unknown')
            flow_step.variable_name = variable_name
            
            flow_steps.append(flow_step)
        except Exception as e:
            logger.warning(f"Failed to convert path info {idx} to FlowStepDivide: {e}")
            continue
    
    logger.info(f"Successfully converted {len(flow_steps)} flow paths")
    return flow_steps


def main():
    """Command-line interface"""
    parser = argparse.ArgumentParser(
        description="Scanner-Union: Batch processing scanner for SEVDF"
    )
    
    parser.add_argument('cwe_code', help='CWE identifier (e.g., 416-2)')
    parser.add_argument('project_name', help='Project name')
    parser.add_argument('path_info_file', help='Path to JSON file containing path info list')
    parser.add_argument('properties_file', help='Path to CWE COT config')
    
    parser.add_argument('--model', default='gpt-4', help='LLM model to use')
    parser.add_argument('--output', '-o', help='Output file for results')
    parser.add_argument('--visualize', '-v', action='store_true', 
                       help='Generate visualization data')
    parser.add_argument('--limit', '-l', type=int, help='Limit number of paths to analyze')
    
    args = parser.parse_args()
    
    # Load path info list and convert to FlowStepDivide
    flow_steps = load_path_info_list(args.path_info_file)
    
    # Apply limit if specified
    if args.limit and args.limit > 0:
        flow_steps = flow_steps[:args.limit]
        logger.info(f"Limited analysis to {len(flow_steps)} paths")
    
    if not flow_steps:
        logger.error("No valid flow paths found in path info file")
        return 1
    
    # Determine output directory from output file if specified
    output_dir = None
    if args.output:
        output_dir = os.path.dirname(args.output) or '.'
    
    # Create analyzer
    analyzer = ScannerUnionAnalyzer(
        args.cwe_code,
        args.project_name,
        args.properties_file,
        args.model,
        output_dir=output_dir
    )
    
    # Run analysis
    results = analyzer.analyze_paths(flow_steps)
    
    # Save results if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        logger.info(f"Results saved to {args.output}")
    
    # Generate visualization if requested
    if args.visualize:
        # TODO: Add visualization support
        logger.info("Visualization not yet implemented for Scanner-Union")
    
    # Print summary
    print(f"\n=== Analysis Complete ===")
    if 'summary' in results:
        print(f"Total paths: {results['summary'].get('total_paths_analyzed', 'N/A')}")
        print(f"Vulnerabilities found: {results['summary'].get('vulnerabilities_found', 'N/A')}")
        if 'cache_efficiency' in results['summary']:
            print(f"Cache hit rate: {results['summary']['cache_efficiency']['hit_rate']:.1%}")
    elif 'statistics' in results:
        # Handle Scanner-Union format
        stats = results['statistics']
        print(f"Total units: {stats.get('total_units', 'N/A')}")
        print(f"Cache hits: {stats.get('cache_hits', 0)}")
        print(f"Cache misses: {stats.get('cache_misses', 0)}")
        if stats.get('cache_hits', 0) + stats.get('cache_misses', 0) > 0:
            hit_rate = stats.get('cache_hit_rate', 0)
            print(f"Cache hit rate: {hit_rate:.1%}")
    if 'execution_time' in results:
        print(f"Execution time: {results['execution_time']:.2f} seconds")
    else:
        print(f"Analysis complete")
    
    return 0


if __name__ == '__main__':
    main()
