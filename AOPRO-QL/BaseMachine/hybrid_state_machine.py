# hybrid_state_machine.py

import os
import sys
from typing import Any, Callable, Dict, Tuple, Optional
import logging

from BaseMachine.state_machine import StateMachine, BaseState, ExitState
from BaseMachine.action_utils import create_chat_action, create_new_chat_action
from BaseMachine.agent_action_utils import create_agent_action, create_hybrid_action

logger = logging.getLogger(__name__)


class HybridStateMachine(StateMachine):
    """
    A state machine that supports both chat and agent action modes.
    Can dynamically switch between modes based on task requirements.
    """
    
    def __init__(
        self,
        context,
        state_definitions: Dict[str, Dict],
        initial_state: str,
        config_path='',
        unified_config=None,
        mode='hybrid',
        default_mode='chat',
        mode_selector: Optional[Callable[[str, Dict[str, Any]], str]] = None,
        require_models=True
    ):
        """
        Initialize the hybrid state machine.
        
        Args:
            context: The context object
            state_definitions: State definitions
            initial_state: Initial state name
            config_path: Path to config file
            unified_config: Unified configuration
            mode: Operating mode ('chat', 'agent', 'hybrid', or 'action')
            default_mode: Default mode for hybrid operation
            mode_selector: Function to select mode based on state and context
            require_models: Whether to initialize model managers
        """
        super().__init__(context, state_definitions, initial_state, config_path, unified_config, mode, require_models)
        
        self.default_mode = default_mode
        self.mode_selector = mode_selector or self._default_mode_selector
        self.mode_stats = {'chat': 0, 'agent': 0}  # Track usage statistics
        
    def _default_mode_selector(self, state_name: str, context: Dict[str, Any]) -> str:
        """
        Default mode selector based on state name and context.
        
        Args:
            state_name: Current state name
            context: Current context
            
        Returns:
            'chat' or 'agent'
        """
        # Use agent mode for code-related tasks
        agent_keywords = ['code', 'file', 'implement', 'refactor', 'debug', 'analyze_code']
        if any(keyword in state_name.lower() for keyword in agent_keywords):
            return 'agent'
        
        # Use agent mode if context indicates file operations
        if context.get('requires_file_access', False):
            return 'agent'
        
        # Use agent mode if tools are specified
        if context.get('tools_required', []):
            return 'agent'
        
        # Default to chat mode
        return 'chat'
    
    def _create_states(self, state_definitions):
        """
        Create state instances with hybrid support.
        """
        states = {}
        for name, config in state_definitions.items():
            if name == "Exit":
                states[name] = ExitState()
            else:
                # Check if this state has mode-specific actions
                if 'hybrid_action' in config:
                    # State explicitly defines hybrid behavior
                    states[name] = BaseState(
                        name=name,
                        action=config['hybrid_action'],
                        next_state_func=config.get("next_state_func", None),
                    )
                elif 'chat_action' in config and 'agent_action' in config:
                    # State has both chat and agent actions
                    hybrid_action = create_hybrid_action(
                        chat_action=config['chat_action'],
                        agent_action=config['agent_action'],
                        mode='auto',
                        decision_func=lambda ctx: self.mode_selector(name, ctx)
                    )
                    states[name] = BaseState(
                        name=name,
                        action=hybrid_action,
                        next_state_func=config.get("next_state_func", None),
                    )
                else:
                    # Regular state with single action
                    states[name] = BaseState(
                        name=name,
                        action=config['action'],
                        next_state_func=config.get("next_state_func", None),
                    )
        return states
    
    def process(self):
        """
        Process states with mode tracking.
        """
        previous_result = None
        extra_args = {}
        
        while True:
            try:
                if isinstance(self.state, ExitState) or self.state is None:
                    # Log mode usage statistics
                    logger.info(f"Mode usage - Chat: {self.mode_stats['chat']}, Agent: {self.mode_stats['agent']}")
                    return previous_result
                else:
                    # Determine current mode
                    current_mode = self.mode
                    if self.mode == 'hybrid':
                        current_mode = self.mode_selector(self.state.name, self.context.__dict__)
                    
                    # Track mode usage
                    if current_mode in self.mode_stats:
                        self.mode_stats[current_mode] += 1
                    
                    # Log current mode
                    logger.debug(f"Processing state '{self.state.name}' in {current_mode} mode")
                    
                    # Execute state action
                    action_func = self.state.action
                    args_spec = action_func.__code__.co_varnames
                    
                    if len(args_spec) > 1:
                        kwargs = extra_args if extra_args else {}
                        result = action_func(self, **kwargs)
                        extra_args = {}
                    else:
                        result = action_func(self)
                    
                    # Get next state
                    next_state_info = self.state.next_state_func(result, self)
                    if isinstance(next_state_info, tuple):
                        next_state_name = next_state_info[0]
                        extra_args = next_state_info[1] if len(next_state_info) > 1 else {}
                        self.state = self.states.get(next_state_name, ExitState())
                    elif isinstance(next_state_info, str):
                        next_state_name = next_state_info
                        self.state = self.states.get(next_state_name, ExitState())
                        extra_args = {}
                    else:
                        raise ValueError("next_state_func must return a string or a tuple (state_name, args_dict)")
                    
                    previous_result = result
                    
            except Exception as e:
                logging.error(f"\033[91mError in state '{self.state.name}': {e}\033[0m")
                import traceback
                tb_str = ''.join(traceback.format_exception(None, e, e.__traceback__))
                logging.error(f"\033[90m{tb_str}\033[0m")
                break
    
    def get_agent_results(self):
        """Get results from agent actions."""
        return self.agent_results
    
    def get_hybrid_history(self):
        """Get history of hybrid mode decisions."""
        return self.hybrid_history
    
    def get_mode_statistics(self):
        """Get statistics on mode usage."""
        return self.mode_stats


def create_hybrid_state_definitions(
    chat_definitions: Dict[str, Dict],
    agent_definitions: Dict[str, Dict],
    mode_overrides: Optional[Dict[str, str]] = None
) -> Dict[str, Dict]:
    """
    Merge chat and agent state definitions for hybrid operation.
    
    Args:
        chat_definitions: State definitions for chat mode
        agent_definitions: State definitions for agent mode
        mode_overrides: Override mode for specific states
        
    Returns:
        Merged state definitions for hybrid operation
    """
    hybrid_definitions = {}
    mode_overrides = mode_overrides or {}
    
    # Get all unique state names
    all_states = set(chat_definitions.keys()) | set(agent_definitions.keys())
    
    for state_name in all_states:
        if state_name == "Exit":
            hybrid_definitions[state_name] = {"action": lambda m: None}
            continue
        
        # Check for mode override
        if state_name in mode_overrides:
            override_mode = mode_overrides[state_name]
            if override_mode == 'chat' and state_name in chat_definitions:
                hybrid_definitions[state_name] = chat_definitions[state_name]
            elif override_mode == 'agent' and state_name in agent_definitions:
                hybrid_definitions[state_name] = agent_definitions[state_name]
            continue
        
        # Create hybrid definition
        hybrid_def = {}
        
        # Handle action
        if state_name in chat_definitions and state_name in agent_definitions:
            # Both modes available
            hybrid_def['chat_action'] = chat_definitions[state_name]['action']
            hybrid_def['agent_action'] = agent_definitions[state_name]['action']
        elif state_name in chat_definitions:
            # Only chat mode available
            hybrid_def['action'] = chat_definitions[state_name]['action']
        else:
            # Only agent mode available
            hybrid_def['action'] = agent_definitions[state_name]['action']
        
        # Handle next_state_func (prefer chat definition if both exist)
        if state_name in chat_definitions and 'next_state_func' in chat_definitions[state_name]:
            hybrid_def['next_state_func'] = chat_definitions[state_name]['next_state_func']
        elif state_name in agent_definitions and 'next_state_func' in agent_definitions[state_name]:
            hybrid_def['next_state_func'] = agent_definitions[state_name]['next_state_func']
        
        hybrid_definitions[state_name] = hybrid_def
    
    return hybrid_definitions