"""
Connection Analysis Context
"""
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass, field


@dataclass
class IntermediateContext:
    """Context for an intermediate Logic Unit"""
    intermediate_key: str
    contexts: Set[Tuple[str, str]] = field(default_factory=set)  # Set of (backward_key, forward_key)
    
    def add_context(self, backward_key: str, forward_key: str):
        self.contexts.add((backward_key, forward_key))
    
    def get_primary_context(self) -> Optional[Tuple[str, str]]:
        """Get the primary context (first one for now)"""
        return list(self.contexts)[0] if self.contexts else None
    
    def has_multiple_contexts(self) -> bool:
        return len(self.contexts) > 1


@dataclass
class ConnectionGraph:
    """Graph of connections between Logic Units"""
    forward_edges: Dict[str, Set[str]] = field(default_factory=dict)
    backward_edges: Dict[str, Set[str]] = field(default_factory=dict)
    intermediate_contexts: Dict[str, IntermediateContext] = field(default_factory=dict)