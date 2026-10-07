# statemachine.py

import os
import sys
from typing import Any, Callable, Dict, Tuple
import logging

# Import configuration loading function
from BaseMachine.config_loader import load_config
from BaseMachine.model_manager import ModelManager

from openai import OpenAI
from openai import AzureOpenAI

# Suppress httpx INFO logs (HTTP Request logs)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("openai").setLevel(logging.WARNING)

# Add utils directory to system path (if needed)
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))

class BaseState:
    def __init__(
        self,
        name: str,
        action: Callable[..., Any],
        next_state_func: Callable[[Any, 'StateMachine'], Tuple[str, Dict[str, Any]]] = None,
    ):
        self.name = name
        self.action = action
        self.next_state_func = next_state_func

    def process(self, machine: 'StateMachine', **kwargs):
        # Execute the action, passing in the machine and optional parameters to get the result
        result = self.action(machine, **kwargs)
        # Call next_state_func, which may return the next state name or (state name, parameters)
        next_state_info = self.next_state_func(result, machine)
        return next_state_info, result  # Return the next state information and result

class ExitState(BaseState):
    def __init__(self):
        super().__init__(name="Exit", action=lambda machine: None)

    def process(self, machine, **kwargs):
        pass  # Exit state, no need to process

class StateMachine:
    def __init__(self, context, state_definitions: Dict[str, Dict], initial_state: str, config_path='', cwe_cot_config=None):
        self.state = None
        self.context = context
        self.cwe_cot_config = cwe_cot_config
        
        # Static states must run without model configuration or credentials.
        # Load model resources only when an action first needs them.
        self.config_path = config_path
        self._model_manager = None
        self._config = None
        self._clients = None

        self.analysis_result = []
        self.messages = getattr(self.context, 'messages', [])
        self.complete_conversation_history = []  # New: Store complete conversation across all phases
        self.total_input_tokens = 0
        self.total_output_tokens = 0

        # Note: Client selection is handled by create_chat_action, not here.

        # Create state instances
        self.states = self._create_states(state_definitions)
        self.state = self.states.get(initial_state, None)
        if self.state is None:
            raise ValueError(f"Initial state '{initial_state}' is not defined in state_definitions.")

    @property
    def model_manager(self):
        if self._model_manager is None:
            config_dir = os.path.dirname(self.config_path) if self.config_path else os.path.join(os.path.dirname(__file__), '../.config')
            self._model_manager = ModelManager(config_dir)
        return self._model_manager

    @property
    def config(self):
        if self._config is None:
            self._config = self._load_config(self.config_path)
        return self._config

    @property
    def clients(self):
        if self._clients is None:
            self._clients = self.model_manager.initialize_client()
        return self._clients
        
    def _load_config(self, config_path):
        if not config_path:
            default_config_path = '../.config/config.json'
            config_path = os.path.join(os.path.dirname(__file__), default_config_path)
        config = load_config(config_path)
        config.config_path = config_path  # Set the config_path attribute
        return config

    def _create_states(self, state_definitions):
        states = {}
        for name, config in state_definitions.items():
            if name == "Exit":
                states[name] = ExitState()
            else:
                states[name] = BaseState(
                    name=name,
                    action=config['action'],
                    next_state_func=config.get("next_state_func", None),
                )
        return states

    def process(self):
        previous_result = None  # Save the result of the previous action
        extra_args = {}  # Store the parameters that need to be passed to the next action
        while True:
            try:
                if isinstance(self.state, ExitState) or self.state is None:
                    return previous_result  # or self.analysis_result
                else:
                    # Call the action function, passing in the machine and optional parameters
                    action_func = self.state.action

                    # Get the parameter list of action_func
                    args_spec = action_func.__code__.co_varnames
                    if len(args_spec) > 1:
                        # There are other parameters besides 'machine'
                        # Prepare parameters
                        kwargs = extra_args if extra_args else {}
                        result = action_func(self, **kwargs)
                        extra_args = {}  # Clear extra_args
                    else:
                        result = action_func(self)

                    # Call next_state_func, which may return the next state name or (state name, parameter dictionary)
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
                    previous_result = result  # Update previous_result
            except Exception as e:
                logging.error(f"\033[91mError in state '{self.state.name}': {e}\033[0m")
                import traceback
                tb_str = ''.join(traceback.format_exception(None, e, e.__traceback__))
                logging.error(f"\033[90m{tb_str}\033[0m")
                break

    def results(self):
        return self.analysis_result

    def get_completion_kwargs(self):
        """Get the kwargs for completion API call"""
        return self.model_manager.get_completion_kwargs()
