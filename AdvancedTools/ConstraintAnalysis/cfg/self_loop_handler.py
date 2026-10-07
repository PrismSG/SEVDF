"""
Self-loop handling strategies for CFG optimization
"""

class SelfLoopHandler:
    """Handle self-loops in CFG to enable proper static analysis"""
    
    def handle_self_loops(self, function):
        """
        Process all self-loops in a function.
        Returns the number of self-loops handled.
        """
        self_loops_found = []
        
        for block in function.basic_blocks:
            if self._is_self_loop(block):
                self_loops_found.append(block)
        
        handled_count = 0
        for block in self_loops_found:
            if self._handle_single_self_loop(block):
                handled_count += 1
                
        return handled_count
    
    def _is_self_loop(self, block):
        """Check if a block has a self-loop"""
        return block in block.successor_blocks
    
    def _handle_single_self_loop(self, block):
        """
        Handle a single self-loop based on its type.
        
        Strategy:
        1. Conditional self-loops: Remove self-edge, keep exit edge
        2. Unconditional self-loops: Remove edge, mark as dead code
        3. Multi-edge self-loops: Keep non-self edges
        """
        if not self._is_self_loop(block):
            return False
            
        self_edge_type = block.successor_blocks[block]
        other_successors = [s for s in block.successor_blocks if s != block]
        
        # Case 1: Conditional self-loop (has other exits)
        if self_edge_type in ["TRUE", "FALSE"] and other_successors:
            # Remove only the self-edge
            block.del_successor_by_id(block.block_id)
            print(f"[Self-loop] Removed conditional self-loop at {block.block_id}")
            return True
            
        # Case 2: Unconditional self-loop with no exits
        elif self_edge_type == "UNCONDITIONAL" and not other_successors:
            # This is an infinite loop
            block.del_successor_by_id(block.block_id)
            # Mark block as having infinite loop
            block.has_infinite_loop = True
            print(f"[Self-loop] Removed unconditional self-loop at {block.block_id} (infinite loop)")
            return True
            
        # Case 3: Complex case with multiple edges
        else:
            # Remove self-edge but keep others
            block.del_successor_by_id(block.block_id)
            print(f"[Self-loop] Removed self-edge from {block.block_id}, kept {len(other_successors)} other edges")
            return True
    
    def create_bounded_version(self, block, max_iterations=2):
        """
        Alternative approach: Create a bounded version of the self-loop.
        This is useful when you need to analyze what happens in the loop.
        
        Instead of:
            A → A
        
        Create:
            A → A_bounded1 → A_bounded2 → Exit
        """
        if not self._is_self_loop(block):
            return None
            
        bounded_blocks = []
        prev_block = block
        
        # Remove original self-edge
        self_edge_type = block.successor_blocks.get(block)
        block.del_successor_by_id(block.block_id)
        
        # Create bounded iterations
        for i in range(1, max_iterations + 1):
            # Clone the block
            bounded_block = block.clone(suffix=f"_bounded{i}")
            bounded_blocks.append(bounded_block)
            
            # Connect previous to this
            prev_block.add_successor(bounded_block, self_edge_type)
            prev_block = bounded_block
        
        # Last iteration exits (no self-loop)
        # Connect to original successors
        for succ, edge_type in block.successor_blocks.items():
            if succ != block:  # Skip self-edge
                bounded_blocks[-1].add_successor(succ, edge_type)
        
        return bounded_blocks

# Example usage in cfg_builder.py:
def _handle_self_loops(self, f):
    """
    Handle self-loops before main loop unrolling.
    Self-loops need special treatment as they can't be unrolled normally.
    """
    handler = SelfLoopHandler()
    handled = handler.handle_self_loops(f)
    
    # Optionally create bounded versions for analysis
    # This depends on whether you want to analyze loop body
    # or just remove the cycle
    
    return handled