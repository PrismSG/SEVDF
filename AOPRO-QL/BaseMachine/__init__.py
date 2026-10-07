"""
BaseMachine package for LLMFrontend2
This package contains the core functionality for model management and state machine implementation.
"""

# Core components
from .state_machine import StateMachine, BaseState, ExitState
from .hybrid_state_machine import HybridStateMachine, create_hybrid_state_definitions
from .model_manager import ModelManager
from .config_loader import load_config

# Action utilities
from .action_utils import (
    create_chat_action,
    create_new_chat_action,
    create_context_filling_new_chat_action,
    create_context_filling_new_chat_json_action,
    call_sub_state_machine_action
)

# Agent action utilities
from .agent_action_utils import (
    create_agent_action,
    create_agent_code_action,
    create_agent_analysis_action,
    create_hybrid_action
)

__all__ = [
    # Core
    'StateMachine',
    'BaseState',
    'ExitState',
    'HybridStateMachine',
    'create_hybrid_state_definitions',
    'ModelManager',
    'load_config',
    # Chat actions
    'create_chat_action',
    'create_new_chat_action',
    'create_context_filling_new_chat_action',
    'create_context_filling_new_chat_json_action',
    'call_sub_state_machine_action',
    # Agent actions
    'create_agent_action',
    'create_agent_code_action',
    'create_agent_analysis_action',
    'create_hybrid_action',
]
