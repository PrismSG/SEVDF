"""
Constants for CFG construction and analysis
"""

# Loop unrolling constants
LOOP_UNROLL_SUFFIX = "_iter"  # Suffix for unrolled loop iterations
DEFAULT_UNROLL_COUNT = 2      # Default number of loop unrolling iterations

# Loop unrolling limits
MAX_LOOP_BODY_SIZE = 50       # Don't unroll loops with more than 50 blocks
MAX_LOOP_NESTING_DEPTH = 3    # Don't unroll loops nested more than 3 levels deep
MAX_UNROLL_ITERATIONS = 2     # Maximum iterations to unroll

# Edge type constants
EDGE_TYPE_UNCONDITIONAL = "UNCONDITIONAL"
EDGE_TYPE_TRUE = "TRUE"
EDGE_TYPE_FALSE = "FALSE"
EDGE_TYPE_ITER2_START = "ITER2_START"
EDGE_TYPE_LOOP_EXIT = "LOOP_EXIT"