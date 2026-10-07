#!/usr/bin/env python3
"""
Dominator tree computation for CFG
"""

class DominatorTree:
    """
    Compute dominator relationships for a CFG.
    A node X dominates node Y if every path from entry to Y must pass through X.
    """
    
    def __init__(self, entry_block, all_blocks):
        self.entry = entry_block
        self.blocks = list(all_blocks)
        self.dominators = {}
        self.immediate_dominators = {}
        
        # Build predecessor map
        self.predecessors = {}
        for block in self.blocks:
            self.predecessors[block] = []
        
        for block in self.blocks:
            for succ in block.successor_blocks.keys():
                if succ in self.blocks:
                    self.predecessors[succ].append(block)
        
        # Compute dominators
        self._compute_dominators()
    
    def _compute_dominators(self):
        """
        Compute dominators using the standard iterative algorithm.
        """
        # Initialize
        for block in self.blocks:
            if block == self.entry:
                self.dominators[block] = {block}
            else:
                self.dominators[block] = set(self.blocks)
        
        # Iterate until fixed point
        changed = True
        while changed:
            changed = False
            
            for block in self.blocks:
                if block == self.entry:
                    continue
                
                # Dom(n) = {n} ∪ (∩ Dom(p) for all predecessors p)
                new_dom = set(self.blocks)
                
                # Intersect dominators of all predecessors
                preds = self.predecessors.get(block, [])
                if preds:
                    for pred in preds:
                        if pred in self.dominators:
                            new_dom &= self.dominators[pred]
                
                # Add self
                new_dom.add(block)
                
                # Check if changed
                if new_dom != self.dominators[block]:
                    self.dominators[block] = new_dom
                    changed = True
        
        # Compute immediate dominators
        self._compute_immediate_dominators()
    
    def _compute_immediate_dominators(self):
        """
        Compute immediate dominators from dominators.
        idom(n) is the unique node that dominates n but doesn't dominate any other dominator of n.
        """
        for block in self.blocks:
            if block == self.entry:
                self.immediate_dominators[block] = None
                continue
            
            # Get all dominators except self
            doms = self.dominators[block] - {block}
            
            if not doms:
                self.immediate_dominators[block] = None
                continue
            
            # Find the dominator that doesn't dominate any other dominator
            idom = None
            for d in doms:
                # Check if d dominates any other dominator
                dominates_other = False
                for other in doms:
                    if d != other and other in self.dominators[d]:
                        dominates_other = True
                        break
                
                if not dominates_other:
                    idom = d
                    break
            
            self.immediate_dominators[block] = idom
    
    def dominates(self, dominator, block):
        """
        Check if dominator dominates block.
        """
        return dominator in self.dominators.get(block, set())
    
    def get_dominators(self, block):
        """
        Get all dominators of a block.
        """
        return self.dominators.get(block, set())
    
    def get_immediate_dominator(self, block):
        """
        Get the immediate dominator of a block.
        """
        return self.immediate_dominators.get(block)