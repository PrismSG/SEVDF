"""
Logic Unit Connection Manager
Manages the relationships between Logic Units, especially for intermediate units
"""
from typing import Dict, List, Tuple, Optional, Set
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)


def get_unit_intermediate_contexts(unit, connections):
    """Resolve the full B/F keys for the paths assigned to this unit."""
    original_key = unit.cache_key.split('__ctx_')[0]
    contexts = []
    for path_id in unit.paths_using:
        connection = getattr(connections, 'path_connections', {}).get(path_id)
        if connection and connection[1] == original_key:
            context = (connection[0], connection[2])
            if context not in contexts:
                contexts.append(context)
    if not contexts:
        contexts = connections.get_intermediate_contexts(original_key)
    return [(None if backward == 'none' else backward,
             None if forward == 'none' else forward)
            for backward, forward in contexts]


class LogicUnitConnections:
    """
    Manages connections and relationships between Logic Units
    """
    
    def __init__(self):
        # Forward connections: unit_key -> List[next_unit_keys]
        self.forward_connections: Dict[str, Set[str]] = defaultdict(set)
        
        # Backward connections: unit_key -> List[prev_unit_keys]
        self.backward_connections: Dict[str, Set[str]] = defaultdict(set)
        
        # Intermediate context: intermediate_key -> Set[(backward_key, forward_key)]
        # This is crucial for intermediate analysis
        self.intermediate_contexts: Dict[str, Set[Tuple[str, str]]] = defaultdict(set)
        
        # Path-based connections: path_id -> (backward_key, intermediate_key, forward_key)
        self.path_connections: Dict[str, Tuple[Optional[str], Optional[str], Optional[str]]] = {}
        
        # Statistics
        self.stats = {
            'total_connections': 0,
            'unique_intermediate_contexts': 0,
            'max_context_variations': 0
        }
    
    def add_path_connection(self, 
                          path_id: str,
                          backward_key: Optional[str],
                          intermediate_key: Optional[str],
                          forward_key: Optional[str]):
        """
        Add connections for a complete path
        
        Args:
            path_id: Unique path identifier
            backward_key: Cache key for backward segment (can be None)
            intermediate_key: Cache key for intermediate segment (can be None)
            forward_key: Cache key for forward segment (can be None)
        """
        # Store path connection
        self.path_connections[path_id] = (backward_key, intermediate_key, forward_key)
        
        # Build connection graph
        if backward_key and intermediate_key:
            self.forward_connections[backward_key].add(intermediate_key)
            self.backward_connections[intermediate_key].add(backward_key)
            self.stats['total_connections'] += 1
        
        if intermediate_key and forward_key:
            self.forward_connections[intermediate_key].add(forward_key)
            self.backward_connections[forward_key].add(intermediate_key)
            self.stats['total_connections'] += 1
        
        # Direct backward->forward connection when intermediate is missing
        if backward_key and forward_key and not intermediate_key:
            self.forward_connections[backward_key].add(forward_key)
            self.backward_connections[forward_key].add(backward_key)
            self.stats['total_connections'] += 1
            logger.debug(f"Direct connection: {backward_key[:8]}... -> {forward_key[:8]}... (no intermediate)")
        
        # Special handling for intermediate contexts
        if intermediate_key:
            # Track contexts even with partial paths
            if backward_key or forward_key:
                context = (backward_key or "none", forward_key or "none")
                self.intermediate_contexts[intermediate_key].add(context)
                
                # Update statistics
                self.stats['unique_intermediate_contexts'] = len(self.intermediate_contexts)
                if self.intermediate_contexts:
                    max_contexts = max(len(contexts) for contexts in self.intermediate_contexts.values())
                    self.stats['max_context_variations'] = max_contexts
                
                # Log if we have multiple contexts for same intermediate
                if len(self.intermediate_contexts[intermediate_key]) > 1:
                    logger.debug(f"Intermediate unit {intermediate_key[:8]}... has "
                               f"{len(self.intermediate_contexts[intermediate_key])} different contexts")
    
    def get_intermediate_contexts(self, intermediate_key: str) -> List[Tuple[str, str]]:
        """
        Get all possible (backward, forward) contexts for an intermediate unit
        
        Returns:
            List of (backward_key, forward_key) tuples
        """
        return list(self.intermediate_contexts.get(intermediate_key, set()))
    
    def get_most_common_context(self, intermediate_key: str) -> Optional[Tuple[str, str]]:
        """
        Get the most common context for an intermediate unit
        For now, returns the first context (can be enhanced with frequency tracking)
        
        Returns:
            (backward_key, forward_key) or None
        """
        contexts = self.get_intermediate_contexts(intermediate_key)
        return contexts[0] if contexts else None
    
    def get_connected_units(self, unit_key: str) -> Dict[str, Set[str]]:
        """
        Get all units connected to a given unit
        
        Returns:
            Dict with 'forward' and 'backward' connections
        """
        return {
            'forward': self.forward_connections.get(unit_key, set()),
            'backward': self.backward_connections.get(unit_key, set())
        }
    
    def get_path_flow(self, path_id: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Get the complete flow for a specific path
        
        Returns:
            (backward_key, intermediate_key, forward_key)
        """
        return self.path_connections.get(path_id, (None, None, None))
    
    def get_connection_statistics(self) -> Dict[str, any]:
        """
        Get detailed statistics about connections
        """
        # Calculate additional statistics
        units_with_multiple_prev = sum(1 for conns in self.backward_connections.values() 
                                      if len(conns) > 1)
        units_with_multiple_next = sum(1 for conns in self.forward_connections.values() 
                                      if len(conns) > 1)
        
        # Analyze path completeness
        complete_paths = 0
        partial_paths = 0
        path_patterns = {'B-I-F': 0, 'B-I': 0, 'I-F': 0, 'B-F': 0, 'B': 0, 'I': 0, 'F': 0}
        
        for path_id, (b, i, f) in self.path_connections.items():
            if b and i and f:
                complete_paths += 1
                path_patterns['B-I-F'] += 1
            else:
                partial_paths += 1
                if b and i and not f:
                    path_patterns['B-I'] += 1
                elif not b and i and f:
                    path_patterns['I-F'] += 1
                elif b and not i and f:
                    path_patterns['B-F'] += 1
                elif b and not i and not f:
                    path_patterns['B'] += 1
                elif not b and i and not f:
                    path_patterns['I'] += 1
                elif not b and not i and f:
                    path_patterns['F'] += 1
        
        # Intermediate context diversity
        context_distribution = {}
        for intermediate_key, contexts in self.intermediate_contexts.items():
            count = len(contexts)
            context_distribution[count] = context_distribution.get(count, 0) + 1
        
        return {
            **self.stats,
            'total_paths': len(self.path_connections),
            'complete_paths': complete_paths,
            'partial_paths': partial_paths,
            'path_patterns': path_patterns,
            'units_with_multiple_predecessors': units_with_multiple_prev,
            'units_with_multiple_successors': units_with_multiple_next,
            'intermediate_context_distribution': context_distribution,
            'average_contexts_per_intermediate': (
                sum(len(contexts) for contexts in self.intermediate_contexts.values()) / 
                max(len(self.intermediate_contexts), 1)
            )
        }
    
    def visualize_connections(self) -> str:
        """
        Generate a text visualization of connection patterns
        """
        lines = ["=== Logic Unit Connection Patterns ==="]
        
        # Show intermediate units with multiple contexts
        multi_context_intermediates = [
            (key, len(contexts)) 
            for key, contexts in self.intermediate_contexts.items() 
            if len(contexts) > 1
        ]
        
        if multi_context_intermediates:
            lines.append("\nIntermediate Units with Multiple Contexts:")
            for key, count in sorted(multi_context_intermediates, 
                                   key=lambda x: x[1], reverse=True)[:5]:
                lines.append(f"  {key[:16]}... : {count} contexts")
        
        # Show units with high connectivity
        high_connectivity_units = []
        for unit_key in set(self.forward_connections.keys()) | set(self.backward_connections.keys()):
            in_degree = len(self.backward_connections.get(unit_key, set()))
            out_degree = len(self.forward_connections.get(unit_key, set()))
            total_degree = in_degree + out_degree
            if total_degree > 2:
                high_connectivity_units.append((unit_key, in_degree, out_degree))
        
        if high_connectivity_units:
            lines.append("\nHighly Connected Units (in/out degree > 2):")
            for key, in_deg, out_deg in sorted(high_connectivity_units, 
                                              key=lambda x: x[1] + x[2], reverse=True)[:5]:
                lines.append(f"  {key[:16]}... : {in_deg} in, {out_deg} out")
        
        # Show statistics
        stats = self.get_connection_statistics()
        lines.append("\nConnection Statistics:")
        lines.append(f"  Total paths: {stats['total_paths']}")
        lines.append(f"  Total connections: {stats['total_connections']}")
        lines.append(f"  Unique intermediate contexts: {stats['unique_intermediate_contexts']}")
        lines.append(f"  Max context variations: {stats['max_context_variations']}")
        
        return "\n".join(lines)
