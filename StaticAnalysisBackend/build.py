#!/usr/bin/env python3
"""
Scanner Builder CLI

Build CWE scanner modules from YAML configuration files.

Usage:
    # List available configs
    ./build.py list

    # Build a single scanner
    ./build.py build 416-UseAfterFree

    # Build all scanners
    ./build.py build-all

    # Force rebuild (overwrite existing files)
    ./build.py build 416-UseAfterFree --force

    # Verify a build
    ./build.py verify 416-UseAfterFree

    # Verify with test (runs CodeQL analysis)
    ./build.py verify 416-UseAfterFree --test-db /path/to/codeql/db

Directory Structure:
    StaticAnalysisBackend/
    ├── scanner_configs/           # YAML config files (input)
    │   ├── 416-UseAfterFree.yaml
    │   └── 843.yaml
    ├── builds/                    # Generated modules (output)
    │   ├── CWE-416-UseAfterFree/
    │   └── CWE-843/
    └── build.py                   # This script
"""

import sys
import os

# Add Utils to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from Utils.scanner_builder import ScannerBuilder, main

if __name__ == '__main__':
    main()
