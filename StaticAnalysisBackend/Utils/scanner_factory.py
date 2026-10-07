"""
Scanner Factory - Build scanners from YAML configuration

This module provides a factory for creating CodeQL scanners from YAML configuration files.
Each CWE module has a scanner.yaml file that defines its configuration.

Benefits:
- Declarative configuration instead of imperative code
- Easy to add/modify scanners without touching Python code
- Consistent configuration format across all scanners
- Support for both simple and complex scanner architectures
- Built-in validation and error handling

Usage:
    from Utils.scanner_factory import ScannerFactory

    # Load scanner from module directory
    factory = ScannerFactory()
    scanner = factory.create_scanner("CWE-843", db_path="analysis.db")

    # Or load from specific config file
    scanner = factory.create_scanner_from_config(
        "/path/to/scanner.yaml",
        db_path="analysis.db",
        codeql_db_path="/path/to/codeql/db"
    )

    # Use the scanner
    results = scanner.get_analysis_results(...)
"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from .codeql_analysis_helper import CodeQLAnalysisHelper


class ScannerConfig:
    """
    Scanner configuration loaded from YAML file.

    Provides convenient access to configuration values with defaults.
    """

    def __init__(self, config_dict: Dict[str, Any], module_dir: str):
        """
        Initialize scanner configuration.

        Args:
            config_dict: Configuration dictionary loaded from YAML
            module_dir: Path to the scanner's module directory
        """
        self.raw_config = config_dict
        self.module_dir = module_dir

    @property
    def cwe_code(self) -> str:
        """Get CWE code from metadata."""
        return self.raw_config.get('metadata', {}).get('cwe_code', 'unknown')

    @property
    def cwe_name(self) -> str:
        """Get CWE name from metadata."""
        return self.raw_config.get('metadata', {}).get('cwe_name', '')

    @property
    def description(self) -> str:
        """Get description from metadata."""
        return self.raw_config.get('metadata', {}).get('description', '')

    @property
    def enabled(self) -> bool:
        """Check if scanner is enabled."""
        return self.raw_config.get('metadata', {}).get('enabled', True)

    @property
    def query_source(self) -> str:
        """Get query source (shared or local)."""
        return self.raw_config.get('query', {}).get('source', 'shared')

    @property
    def query_path(self) -> str:
        """Get query path."""
        path = self.raw_config.get('query', {}).get('path', '')

        # If local query, resolve relative to module directory
        if self.query_source == 'local' and not os.path.isabs(path):
            return os.path.join(self.module_dir, path)

        return path

    @property
    def search_path(self) -> Optional[str]:
        """Get CodeQL search path."""
        path = self.raw_config.get('query', {}).get('search_path')

        # If local search path, resolve relative to module directory
        if path and not os.path.isabs(path):
            return os.path.join(self.module_dir, path)

        return path

    @property
    def compression_level(self) -> int:
        """Path compression level (0=full, 1=unique threadFlow, 2=func-pair dedup, 3=file-pair dedup)."""
        analysis = self.raw_config.get('analysis', {})
        # Backward compat: if old extract_min exists, map it
        if 'compression_level' in analysis:
            return analysis['compression_level']
        if analysis.get('extract_min', False):
            return 2
        return 0

    @property
    def threads(self) -> int:
        """Number of threads for CodeQL analysis."""
        return self.raw_config.get('analysis', {}).get('threads', 10)

    @property
    def storage_format(self) -> str:
        """Get storage format (monolithic or itemized)."""
        return self.raw_config.get('storage', {}).get('format', 'monolithic')

    @property
    def database_file(self) -> str:
        """Get database file name."""
        return self.raw_config.get('storage', {}).get('database', 'codeql_analysis.db')

    @property
    def cleanup_sarif(self) -> bool:
        """Whether to cleanup SARIF file after analysis."""
        return self.raw_config.get('cache', {}).get('cleanup_sarif', True)

    @property
    def preserve_function_csv(self) -> bool:
        """Whether to preserve function CSV file."""
        return self.raw_config.get('cache', {}).get('preserve_function_csv', True)

    @property
    def evolution_enabled(self) -> bool:
        """Whether query evolution is enabled."""
        return self.raw_config.get('evolution', {}).get('enabled', False)

    @property
    def max_iterations(self) -> int:
        """Maximum evolution iterations."""
        return self.raw_config.get('evolution', {}).get('max_iterations', 10)

    @property
    def convergence_threshold(self) -> float:
        """Evolution convergence threshold."""
        return self.raw_config.get('evolution', {}).get('convergence_threshold', 0.95)

    def get_feature(self, feature_name: str, default: bool = False) -> bool:
        """
        Check if a feature is enabled.

        Args:
            feature_name: Name of the feature
            default: Default value if feature is not specified

        Returns:
            Whether the feature is enabled
        """
        return self.raw_config.get('features', {}).get(feature_name, default)


class ScannerFactory:
    """
    Factory for creating scanners from YAML configuration.

    This factory reads scanner.yaml files and creates CodeQLAnalysisHelper
    instances with the appropriate configuration.
    """

    def __init__(self, base_dir: str = None):
        """
        Initialize scanner factory.

        Args:
            base_dir: Base directory containing CWE modules
                     (defaults to StaticAnalysisBackend directory)
        """
        if base_dir is None:
            # Default to StaticAnalysisBackend directory
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        self.base_dir = base_dir

    def find_scanner_config(self, cwe_code: str) -> Optional[str]:
        """
        Find scanner.yaml file for a given CWE code.

        Args:
            cwe_code: CWE code (e.g., "843", "416-UseAfterFree")

        Returns:
            Path to scanner.yaml file, or None if not found
        """
        # Try CWE-{code} directory
        module_dir = os.path.join(self.base_dir, f"CWE-{cwe_code}")
        config_path = os.path.join(module_dir, "scanner.yaml")

        if os.path.exists(config_path):
            return config_path

        return None

    def load_config(self, config_path: str) -> ScannerConfig:
        """
        Load scanner configuration from YAML file.

        Args:
            config_path: Path to scanner.yaml file

        Returns:
            ScannerConfig object

        Raises:
            FileNotFoundError: If config file doesn't exist
            yaml.YAMLError: If config file is invalid YAML
        """
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Scanner config not found: {config_path}")

        with open(config_path, 'r') as f:
            config_dict = yaml.safe_load(f)

        module_dir = os.path.dirname(config_path)
        return ScannerConfig(config_dict, module_dir)

    def create_scanner(
        self,
        cwe_code: str,
        db_path: str = 'codeql_analysis.db',
        codeql_db_path: Optional[str] = None
    ) -> CodeQLAnalysisHelper:
        """
        Create a scanner for the given CWE code.

        Args:
            cwe_code: CWE code (e.g., "843", "416-UseAfterFree")
            db_path: Path to SQLite database for caching results
            codeql_db_path: Path to CodeQL database to analyze

        Returns:
            CodeQLAnalysisHelper instance configured for this CWE

        Raises:
            FileNotFoundError: If scanner config not found
            ValueError: If scanner is disabled

        Example:
            factory = ScannerFactory()
            scanner = factory.create_scanner(
                "843",
                db_path="/tmp/analysis.db",
                codeql_db_path="/path/to/codeql/db"
            )
            results = scanner.get_analysis_results(...)
        """
        # Find config file
        config_path = self.find_scanner_config(cwe_code)
        if not config_path:
            raise FileNotFoundError(
                f"Scanner config not found for CWE-{cwe_code}. "
                f"Expected: {self.base_dir}/CWE-{cwe_code}/scanner.yaml"
            )

        return self.create_scanner_from_config(config_path, db_path, codeql_db_path)

    def create_scanner_from_config(
        self,
        config_path: str,
        db_path: str = 'codeql_analysis.db',
        codeql_db_path: Optional[str] = None
    ) -> CodeQLAnalysisHelper:
        """
        Create a scanner from a specific config file.

        Args:
            config_path: Path to scanner.yaml file
            db_path: Path to SQLite database for caching results
            codeql_db_path: Path to CodeQL database to analyze

        Returns:
            CodeQLAnalysisHelper instance

        Raises:
            ValueError: If scanner is disabled
        """
        # Load configuration
        config = self.load_config(config_path)

        # Check if scanner is enabled
        if not config.enabled:
            raise ValueError(
                f"Scanner {config.cwe_code} is disabled in configuration. "
                f"Set metadata.enabled=true to enable it."
            )

        # Determine if we're using local query
        use_local_query = (config.query_source == 'local')

        # Determine if we're using itemized storage
        use_itemized_storage = (config.storage_format == 'itemized')

        # Create scanner
        return CodeQLAnalysisHelper(
            cwe_code=config.cwe_code,
            query_file_path=config.query_path,
            db_path=db_path,
            codeql_db_path=codeql_db_path,
            compression_level=config.compression_level,
            ql_search_path=config.search_path,
            use_local_query=use_local_query,
            use_itemized_storage=use_itemized_storage
        )

    def list_available_scanners(self) -> Dict[str, Dict[str, Any]]:
        """
        List all available scanners with their metadata.

        Returns:
            Dictionary mapping CWE codes to scanner metadata

        Example:
            factory = ScannerFactory()
            scanners = factory.list_available_scanners()
            for cwe_code, info in scanners.items():
                print(f"{cwe_code}: {info['name']} ({'enabled' if info['enabled'] else 'disabled'})")
        """
        scanners = {}

        # Scan all CWE-* directories
        for entry in os.listdir(self.base_dir):
            if not entry.startswith('CWE-'):
                continue

            module_dir = os.path.join(self.base_dir, entry)
            if not os.path.isdir(module_dir):
                continue

            config_path = os.path.join(module_dir, 'scanner.yaml')
            if not os.path.exists(config_path):
                continue

            try:
                config = self.load_config(config_path)
                scanners[config.cwe_code] = {
                    'name': config.cwe_name,
                    'description': config.description,
                    'enabled': config.enabled,
                    'query_source': config.query_source,
                    'storage_format': config.storage_format,
                    'evolution_enabled': config.evolution_enabled,
                    'config_path': config_path
                }
            except Exception as e:
                # Skip invalid configs
                print(f"Warning: Failed to load config for {entry}: {e}")
                continue

        return scanners
