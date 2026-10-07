"""
Suggested improvements for loop unrolling algorithm
"""

def handle_self_loops(self, f: Function):
    """
    Special handling for self-loops (blocks that jump to themselves).
    These are often created by goto statements or special control flow.
    """
    self_loops_found = []
    
    for bb in f.basic_blocks:
        # Check if block has a self-edge
        if bb in bb.successor_blocks:
            self_loops_found.append(bb)
            
            # Remove the self-edge
            edge_type = bb.successor_blocks[bb]
            bb.del_successor_by_id(bb.block_id)
            
            # For conditional self-loops, preserve the exit condition
            if edge_type in ["TRUE", "FALSE"]:
                # Find the other branch (exit condition)
                other_successors = [s for s in bb.successor_blocks.keys() if s != bb]
                if other_successors:
                    # The self-loop is removed, control flows to exit
                    cfg_print(f"Removed conditional self-loop at {bb.block_id}")
            else:
                # Unconditional self-loop - this is problematic
                # Add a synthetic exit to prevent infinite loop
                cfg_print(f"WARNING: Unconditional self-loop at {bb.block_id}")
    
    return self_loops_found

def improve_loop_detection(self, f: Function):
    """
    Enhanced loop detection that doesn't rely solely on database queries.
    """
    # 1. Detect self-loops
    self_loops = self.handle_self_loops(f)
    
    # 2. Use Tarjan's algorithm for strongly connected components
    sccs = self.find_strongly_connected_components(f)
    
    # 3. Each non-trivial SCC is a potential loop
    loops = []
    for scc in sccs:
        if len(scc) > 1:  # Non-trivial SCC
            # Find loop header (entry point from outside)
            header = self.find_loop_header(scc, f)
            # Find back edges
            back_edges = self.find_back_edges_in_scc(scc, header)
            for back_edge_source in back_edges:
                loops.append((header, None, back_edge_source))
    
    return loops

def find_strongly_connected_components(self, f: Function):
    """
    Tarjan's algorithm for finding SCCs.
    """
    index_counter = [0]
    stack = []
    lowlinks = {}
    index = {}
    on_stack = {}
    sccs = []
    
    def strongconnect(v):
        index[v] = index_counter[0]
        lowlinks[v] = index_counter[0]
        index_counter[0] += 1
        stack.append(v)
        on_stack[v] = True
        
        for w in v.successor_blocks:
            if w not in index:
                strongconnect(w)
                lowlinks[v] = min(lowlinks[v], lowlinks[w])
            elif on_stack.get(w, False):
                lowlinks[v] = min(lowlinks[v], index[w])
        
        if lowlinks[v] == index[v]:
            scc = []
            while True:
                w = stack.pop()
                on_stack[w] = False
                scc.append(w)
                if w == v:
                    break
            sccs.append(scc)
    
    for bb in f.basic_blocks:
        if bb not in index:
            strongconnect(bb)
    
    return sccs

def add_unrolling_limit_check(self, loop_body_blocks):
    """
    Add limits to prevent excessive unrolling of very large loops.
    """
    MAX_LOOP_BODY_SIZE = 50  # Don't unroll loops with more than 50 blocks
    MAX_NESTED_DEPTH = 3     # Don't unroll loops nested more than 3 deep
    
    if len(loop_body_blocks) > MAX_LOOP_BODY_SIZE:
        cfg_print(f"Skipping unrolling: loop too large ({len(loop_body_blocks)} blocks)")
        return False
    
    # Check nesting depth
    nesting_depth = max(bb.block_id.count('_L') for bb in loop_body_blocks)
    if nesting_depth >= MAX_NESTED_DEPTH:
        cfg_print(f"Skipping unrolling: too deeply nested (depth {nesting_depth})")
        return False
    
    return True

def handle_goto_loops(self, f: Function):
    """
    Special handling for loops created by goto statements.
    These often create complex control flow that standard loop detection misses.
    """
    # Detect potential goto patterns
    goto_patterns = []
    
    for bb in f.basic_blocks:
        # Look for unconditional jumps backward (typical goto pattern)
        if len(bb.successor_blocks) == 1:
            successor = list(bb.successor_blocks.keys())[0]
            try:
                bb_line = int(bb.block_id.split('.')[0])
                succ_line = int(successor.block_id.split('.')[0])
                if succ_line < bb_line:
                    # This is a backward goto
                    goto_patterns.append((bb, successor))
            except:
                pass
    
    # Convert goto patterns to loop structures
    for source, target in goto_patterns:
        # Find all blocks between target and source
        loop_body = self.find_blocks_between(target, source, f)
        if loop_body:
            cfg_print(f"Detected goto loop: {source.block_id} -> {target.block_id}")
            # Process as a special loop type
            self.unroll_goto_loop(f, target, source, loop_body)