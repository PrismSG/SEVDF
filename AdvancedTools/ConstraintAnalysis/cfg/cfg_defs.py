from typing import List, Dict, Set
import dill
import os
from .utils import Logger

logger = Logger(log_level='log')
import sys


class PosPoint:
    def __init__(self, file_path: str, point_id: str):
        self.file_path = file_path
        self.point_id = point_id

    def get_pos(self):
        line, column = self.point_id.split(".")
        return int(line), int(column)

    def __repr__(self):
        return f"{self.file_path}:{self.point_id}"

    def __eq__(self, other):
        return self.file_path == other.file_path and self.point_id == other.point_id

    def __hash__(self) -> int:
        return hash((self.file_path, self.point_id))


class PosBlock:
    def __init__(self, file_path: str, block_id: str):
        self.file_path = file_path
        self.block_id = block_id

    def get_pos(self):
        startline, startcolumn = self.block_id.split("_")[0].split(".")
        endline, endcolumn = self.block_id.split("_")[1].split(".")
        return int(startline), int(startcolumn), int(endline), int(endcolumn)

    def get_id(self):
        return self.block_id

    def get_file_path(self):
        return self.file_path

    def is_within(self, outer):
        inner_start_line, inner_start_char, inner_end_line, inner_end_char = (
            self.get_pos()
        )
        outer_start_line, outer_start_char, outer_end_line, outer_end_char = (
            outer.get_pos()
        )

        return (
            outer_start_line < inner_start_line
            or (
                outer_start_line == inner_start_line
                and outer_start_char <= inner_start_char
            )
        ) and (
            outer_end_line > inner_end_line
            or (outer_end_line == inner_end_line and outer_end_char >= inner_end_char)
        )

    def __repr__(self):
        return f"{self.file_path}:{self.block_id}"

    def __eq__(self, other):
        # Handle cases where attributes might not be set during unpickling
        if not hasattr(self, 'file_path') or not hasattr(other, 'file_path'):
            return False
        if not hasattr(self, 'block_id') or not hasattr(other, 'block_id'):
            return False
        return self.file_path == other.file_path and self.block_id == other.block_id

    def __hash__(self) -> int:
        # Handle cases where attributes might not be set during unpickling
        file_path = getattr(self, 'file_path', '')
        block_id = getattr(self, 'block_id', '')
        return hash((file_path, block_id))


class Function(PosBlock):
    def __init__(
        self,
        file_path: str,
        block_id: str,
        qualified_name: str,
        opcode_name: str = None,
    ):
        super().__init__(file_path, block_id)
        self.qualified_name = qualified_name
        self.entry_block: BasicBlock = None
        self.basic_blocks: Set[BasicBlock] = set()
        self.opcode_name = opcode_name
        self.unrolled_loops = 0  # Track number of loops unrolled

    def get_basic_block(self, file_path: str, block_id: str):
        for bb in self.basic_blocks:
            if bb.file_path == file_path and bb.block_id == block_id:
                return bb
        return None

    def del_basic_block(self, bb):
        self.basic_blocks.remove(bb)

    def __eq__(self, other):
        return super().__eq__(other) and self.qualified_name == other.qualified_name

    def __hash__(self):
        return hash((super().__hash__(), self.qualified_name))

    def __repr__(self):
        loop_info = f" | {self.unrolled_loops} loops unrolled" if hasattr(self, 'unrolled_loops') and self.unrolled_loops > 0 else ""
        msg = f"Function {self.qualified_name}@{self.get_file_path()}:{self.get_id()} | totally {len(self.basic_blocks)} bb | entry block {self.entry_block.get_id()}{loop_info} \n"
        return msg


class FunctionCall(PosBlock):
    def __init__(self, file_path: str, block_id: str, function: Function):
        super().__init__(file_path, block_id)
        self.function = function

    def __eq__(self, other):
        return super().__eq__(other) and self.function == other.function

    def __hash__(self):
        return hash((super().__hash__(), self.function))

    def __repr__(self):
        pass


class BasicBlock(PosBlock):
    def __init__(self, file_path: str, block_id: str, function_name: str):
        super().__init__(file_path, block_id)
        self.called_functions: Set[FunctionCall] = set()
        self.successor_blocks: Dict[BasicBlock, str] = {}  # "TRUE" "FALSE" "NONE"
        self.predecessor_blocks: Set[BasicBlock] = set()
        self.function: Function = None
        self.function_name = function_name
        self.condition_statement = None
        self.isSpec = False
        self.has_condition = False  # Whether this block contains a conditional statement

    def add_successor(self, block, type: str = "NONE"):
        self.successor_blocks[block] = type
        block.predecessor_blocks.add(self)

    def del_successor_by_id(self, block_id):
        # Find the key to delete first (avoid modifying dict during iteration)
        key_to_delete = None
        for k, v in self.successor_blocks.items():
            if k.block_id == block_id:
                key_to_delete = k
                break
        
        if key_to_delete:
            del self.successor_blocks[key_to_delete]
            key_to_delete.predecessor_blocks.discard(self)  # Use discard to avoid KeyError
        

    def add_called_function(self, function_call):
        self.called_functions.add(function_call)

    def set_condition_statement(self, file_path: str, block_id: str):
        self.condition_statement = PosBlock(file_path, block_id)

    def is_check_node(self):
        # return self.condition_statement is not None
        # return( "TRUE" in bb.successor_blocks.values() ) and ("FALSE" in bb.successor_blocks.values()) and len(bb.successor_blocks) == 2
        if len(self.successor_blocks) == 2:
            return True
        # if len(self.successor_blocks) == 1:
        #     # return a==b 
        #     # get lots of false positive
        #     # get the only successor
        #     for k, v in self.successor_blocks.items():
        #         if len(k.successor_blocks) == 0:
        #             return True
        return False

    def is_spec_related_node(self):
        return self.isSpec


    @staticmethod
    def empty_block():
        return BasicBlock("<empty>", "0.0_0.0", "<empty>")

    def is_empty_block(self):
        return (
            self.file_path == "<empty>"
            and self.block_id == "0.0_0.0"
            and self.function_name == "<empty>"
        )

    def __eq__(self, other):
        return super().__eq__(other)

    def __hash__(self):
        return super().__hash__()

    def __repr__(self):
        msg = f"BB in {self.function_name} {self.file_path} {self.block_id}\n"
        if self.successor_blocks:
            for k, v in self.successor_blocks.items():
                msg += f"-->: {k.block_id} {v}\n"

        if self.called_functions:
            for _ in self.called_functions:
                msg += f"callee: {_.block_id} {_.function.qualified_name} \n"
        if self.condition_statement:
            msg += f"cond: {self.condition_statement}\n"
        if self.predecessor_blocks:
            msg += f"predecessors: {[_.block_id for _ in self.predecessor_blocks]}\n"
        return msg


class CFGCache:
    def __init__(self, cache_dir: str = "cache"):
        self.cache_dir = cache_dir
        self.functions = {}

    def _get_function_cache_path(self, qualified_name: str) -> str:
        """Get cache file path for a specific function"""
        # Clean special characters in function name for filename
        safe_name = qualified_name.replace("::", "_").replace("<", "_").replace(">", "_").replace("/", "_")
        return os.path.join(self.cache_dir, f"func_{safe_name}.pkl")

    def load_function(self, qualified_name: str) -> Function:
        """Load a specific function from cache"""
        cache_path = self._get_function_cache_path(qualified_name)
        try:
            with open(cache_path, "rb") as f:
                function = dill.load(f)
                
                # Validate the loaded function and fix any serialization issues
                self._validate_and_fix_function(function)
                
                logger.debug(f"Loaded function {qualified_name} from cache: {cache_path}")
                return function
        except FileNotFoundError:
            logger.debug(f"No cache file found for function {qualified_name}: {cache_path}")
            return None
        except Exception as e:
            logger.debug(f"Error loading function cache {cache_path}: {e}")
            # DO NOT remove cache files - leave them for debugging
            if os.path.exists(cache_path):
                file_size = os.path.getsize(cache_path)
                logger.warning(f"Cache file exists but corrupted. Size: {file_size} bytes. Keeping for debugging.")
            return None
    
    def _validate_and_fix_function(self, function: Function):
        """Validate and fix any serialization issues with loaded function"""
        # Ensure function has all required attributes
        if not hasattr(function, 'file_path'):
            raise AttributeError(f"Function missing file_path attribute")
        
        # Fix basic blocks that might have lost attributes during serialization
        for bb in function.basic_blocks:
            if not hasattr(bb, 'file_path'):
                # Try to recover from parent class or function
                bb.file_path = function.file_path
            if not hasattr(bb, 'block_id'):
                raise AttributeError(f"BasicBlock missing block_id attribute")
            if not hasattr(bb, 'function_name'):
                bb.function_name = function.qualified_name
            if not hasattr(bb, 'called_functions'):
                bb.called_functions = set()
            if not hasattr(bb, 'successor_blocks'):
                bb.successor_blocks = {}
            if not hasattr(bb, 'predecessor_blocks'):
                bb.predecessor_blocks = set()
            if not hasattr(bb, 'condition_statement'):
                bb.condition_statement = None
            if not hasattr(bb, 'isSpec'):
                bb.isSpec = False
            
            # Ensure bb.function points to the correct function
            bb.function = function

    def save_function(self, function: Function):
        """Save a specific function to cache"""
        cache_path = self._get_function_cache_path(function.qualified_name)
        try:
            os.makedirs(self.cache_dir, exist_ok=True)
            
            # Pre-validate function before saving
            self._prepare_function_for_cache(function)
            
            with open(cache_path, "wb") as f:
                dill.dump(function, f)
                logger.debug(f"Saved function {function.qualified_name} to cache: {cache_path}")
        except Exception as e:
            logger.debug(f"Error saving function cache {cache_path}: {e}")
    
    def _prepare_function_for_cache(self, function: Function):
        """Prepare function for caching by ensuring all attributes are properly set"""
        # Ensure all basic blocks have their function reference set
        for bb in function.basic_blocks:
            bb.function = function
            
            # Ensure all attributes are present
            if not hasattr(bb, 'called_functions'):
                bb.called_functions = set()
            if not hasattr(bb, 'successor_blocks'):
                bb.successor_blocks = {}
            if not hasattr(bb, 'predecessor_blocks'):
                bb.predecessor_blocks = set()
            if not hasattr(bb, 'condition_statement'):
                bb.condition_statement = None
            if not hasattr(bb, 'isSpec'):
                bb.isSpec = False

    def has_function(self, qualified_name: str) -> bool:
        """Check if function exists in cache"""
        cache_path = self._get_function_cache_path(qualified_name)
        return os.path.exists(cache_path)

    def clear_function(self, qualified_name: str):
        """Remove function from cache"""
        cache_path = self._get_function_cache_path(qualified_name)
        if os.path.exists(cache_path):
            os.remove(cache_path)
            logger.debug(f"Removed function cache: {cache_path}")

    def clear_all(self):
        """Remove all cached functions"""
        if os.path.exists(self.cache_dir):
            for filename in os.listdir(self.cache_dir):
                if filename.startswith("func_") and filename.endswith(".pkl"):
                    os.remove(os.path.join(self.cache_dir, filename))
            logger.debug(f"Cleared all function caches from {self.cache_dir}")

    # Legacy methods for backward compatibility
    def load(self):
        """Legacy method - does nothing in new implementation"""
        pass

    def save(self):
        """Legacy method - does nothing in new implementation"""
        pass
