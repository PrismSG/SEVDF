"""
LLM Action Functions Module
Contains various action functions for interacting with LLMs
"""

from typing import Any, List
from pydantic import BaseModel, Field
import logging
from colorama import Fore
import json
import requests
# Fix import errors by adapting to different OpenAI library versions
try:
    # Try importing from newer version
    from openai.types.chat import ChatCompletion, ChatCompletionMessage
    from openai.types.chat.chat_completion import Choice
except ImportError:
    try:
        # Try importing from another possible location
        from openai.types.chat import ChatCompletion, ChatCompletionMessage
        from openai.types import Choice
    except ImportError:
        # If both fail, create a simple implementation
        class ChatCompletion:
            def __init__(self, id, choices, created, model, object, system_fingerprint, usage):
                self.id = id
                self.choices = choices
                self.created = created
                self.model = model
                self.object = object
                self.system_fingerprint = system_fingerprint
                self.usage = usage
                
        class ChatCompletionMessage:
            def __init__(self, content, role, function_call=None, tool_calls=None):
                self.content = content
                self.role = role
                self.function_call = function_call
                self.tool_calls = tool_calls
                
        class Choice:
            def __init__(self, finish_reason, index, message, logprobs=None):
                self.finish_reason = finish_reason
                self.index = index
                self.message = message
                self.logprobs = logprobs


class ContextCode(BaseModel):
    name: str = Field(description="Function or Class name")
    reason: str = Field(description="Brief reason why this function's code is needed for analysis")
    code_line: str = Field(description="The single line of code where where this context object is referenced.")
    file_path: str = Field(description="The file path of the code line.")

class Response(BaseModel):
    analysis: str = Field(description="The analysis result of the question.")
    context_code: List[str] = Field(description="If you need additional context code to analyze the question, please provide the context code's names you need additionally to analyze the question.")

# Import helper functions
from BaseMachine.llm_helpers import (
    reliable_parse, 
    safe_format, 
    extract_code_snippets, 
    parse_and_validate_json_response
)

def create_chat_action(prompt_template, response_parser=None, save_option='both', model_name='azure-gpt4o', debug=False):
    """
    Create a chat action function for sending prompts and handling responses.
    Maintains the complete chat history.
    
    :param prompt_template: The prompt template
    :param response_parser: Optional response parser
    :param save_option: Save option, can be 'both', 'prompt', 'result', or 'none'
    :param model_name: The model name to use
    :param debug: Whether to enable debugging
    :return: The action function
    """
    def chat_action(machine, **kwargs):
        from BaseMachine.state_machine import StateMachine  # Move import here
        prompt = prompt_template.format(**kwargs)

        if debug:
            logging.info(Fore.BLUE + f'Chat Action Prompt: {prompt}')

        machine.messages.append({"role": "user", "content": prompt})

        # Select the appropriate client based on model_name
        client_to_use, info = next(((client, info) for client, info in machine.clients if info['name'] == model_name), (None, None))
        if client_to_use is None:
            raise ValueError(f"Model '{model_name}' not found in initialized clients.")

        # Ensure info is a dictionary
        if isinstance(info, tuple):
            info = dict(info)

        # Build request parameters based on whether response_parser is None or not
        request_params = {
            'model': info['model_name'],
            'messages': machine.messages,
            **(
                {"temperature": 0.01, "top_p": machine.config.top_p}
                if info['model_name'] not in ["o1-mini", "o1-preview"]
                else {}
            ),
        }
        if response_parser is not None:
            request_params['response_format'] = response_parser

        # Change to use the reliable_parse function to make the request
        # Use the selected client to make the request
        logging.info(Fore.YELLOW + f'Waiting for the model {info["model_name"]} to process the request...')
        response = reliable_parse(client_to_use, request_params, max_retries=3, debug=debug, model_info=info)
        logging.info(Fore.GREEN + f'Model {info["model_name"]} processed the request successfully.')
        # machine.total_input_tokens += response.usage.prompt_tokens
        # machine.total_output_tokens += response.usage.completion_tokens

        # Add the assistant's reply to the message list
        machine.messages.append(
            {"role": "assistant", "content": response.choices[0].message.content}
        )

        # Parse the assistant's reply
        message = response.choices[0].message
        # parsed_result = getattr(message, "parsed", message.content)
        parsed_result = message.content if getattr(message, "parsed", None) is None else message.parsed

        # Save content based on the save_option parameter
        if save_option == 'prompt':
            machine.analysis_result.append(prompt)
        elif save_option == 'result':
            machine.analysis_result.append(parsed_result)
        elif save_option == 'both':
            machine.analysis_result.append({'prompt': prompt, 'result': parsed_result})
        elif save_option == 'none':
            pass
        else:
            # If an invalid save_option is provided, throw an exception or perform default handling
            raise ValueError("Invalid save_option value. Choose from 'prompt', 'result', or 'both'.")

        return parsed_result

    return chat_action


def create_new_chat_action(prompt_template, response_parser=None, save_option='both', model_name='azure-gpt4o', debug=False):
    """
    Create a new chat action function that ignores previous messages but updates the machine's message history.
    
    :param prompt_template: The prompt template
    :param response_parser: Optional response parser
    :param save_option: Save option, can be 'both', 'prompt', 'result', or 'none'
    :param model_name: The model name to use
    :param debug: Whether to enable debugging
    :return: The action function
    """
    def chat_action(machine, **kwargs):
        from BaseMachine.state_machine import StateMachine  # Move import here
        prompt = prompt_template.format(**kwargs)

        if debug:
            logging.info(Fore.BLUE + f'Chat Action Prompt: {prompt}')

        machine.messages.append({"role": "user", "content": prompt})

        # Select the appropriate client based on model_name
        client_to_use, info = next(((client, info) for client, info in machine.clients if info['name'] == model_name), (None, None))
        if client_to_use is None:
            raise ValueError(f"Model '{model_name}' not found in initialized clients.")

        # Ensure info is a dictionary
        if isinstance(info, tuple):
            info = dict(info)

        # Build request parameters based on whether response_parser is None or not
        request_params = {
            'model': info['model_name'],
            'messages': machine.messages[-1:],
            **(
                {"temperature": 0.01, "top_p": machine.config.top_p}
                if info['model_name'] not in ["o1-mini", "o1-preview"]
                else {}
            ),
        }
        if response_parser is not None:
            request_params['response_format'] = response_parser

        # Use the selected client to make the request
        logging.info(Fore.YELLOW + f'Waiting for the model {info["model_name"]} to process the request...')
        response = reliable_parse(client_to_use, request_params, max_retries=3, debug=debug, model_info=info)
        logging.info(Fore.GREEN + f'Model {info["model_name"]} processed the request successfully.')

        # Add the assistant's reply to the message list
        machine.messages.append(
            {"role": "assistant", "content": response.choices[0].message.content}
        )

        # Parse the assistant's reply
        message = response.choices[0].message
        # parsed_result = getattr(message, "parsed", message.content)
        parsed_result = message.content if getattr(message, "parsed", None) is None else message.parsed

        # Save content based on the save_option parameter
        if save_option == 'prompt':
            machine.analysis_result.append(prompt)
        elif save_option == 'result':
            machine.analysis_result.append(parsed_result)
        elif save_option == 'both':
            machine.analysis_result.append({'prompt': prompt, 'result': parsed_result})
        elif save_option == 'none':
            pass
        else:
            # If an invalid save_option is provided, throw an exception or perform default handling
            raise ValueError("Invalid save_option value. Choose from 'prompt', 'result', or 'both'.")

        return parsed_result

    return chat_action


def create_context_filling_new_chat_action(prompt_template, response_parser=None, save_option='both', model_name='azure-gpt4o'):
    """
    Create a context-filling chat action function.
    The first response includes a general chat result and a context filling field.
    Then, include the filled context code at the end of the prompt and re-ask.
    
    :param prompt_template: The prompt template
    :param response_parser: Optional response parser
    :param save_option: Save option, can be 'both', 'prompt', 'result', or 'none'
    :param model_name: The model name to use
    :return: The action function
    """
    def chat_action(machine, **kwargs):
        from BaseMachine.code_filling.code_filling_context import CFContext  # Move import here
        from BaseMachine.state_machine import StateMachine  # Move import here
        from BaseMachine.code_filling.code_filling_config import state_definitions  # Move import here

        # Log existing definitions
        existing_definitions = list(state_definitions.keys())
        logging.info(Fore.GREEN + f'Existing Definitions: {existing_definitions}')

        base_prompt = prompt_template.format(**kwargs)
        output_requirements = '''
        ---------------
        <!!! VERY IMPORTANT OUTPUT format Requirements>:
        I have a function code search tools prepared for you to analysis this questions. The code search tools can provide you with the code snippets of the FUNCTIONS names you need to analyze the question.
        If you CANNOT provide a VERY reliable analysis and NEED More definitions of specific symbols to answer the question, you MUST Point out the symbol name and provide the relevant code lines and file path to tell me you need more context.
        '''
        output_requirements2 = '''
        ---------------
        <!!! VERY IMPORTANT OUTPUT format Requirements>:
        I have ALREADY provided you with the code snippets and FULL implementation of {context_code_names_str} shown ABOVE.
        I have a function code search tools prepared for you to analysis this questions. The code search tools can provide you with the FULL implementation code of the FUNCTIONS you need to analyze the question.
        If you CANNOT provide a VERY reliable analysis base on code snippets and FULL implementation of function(s):{context_code_names_str}, and NEED More functions full definitions (EXCEPT for the {context_code_names_str}) of specific symbols to answer the question, you MUST Point out the function name and provide the relevant code lines and file path(s) to tell me you need more function definition(s).
        '''
        prompt = base_prompt + output_requirements
        
        accumulated_context_code = ""
        context_code_names = set()

        iteration_count = 0
        while iteration_count < 20:
            temp_messages = [{"role": "user", "content": prompt}]
            request_params = {
                'model': machine.config.model,
                'messages': temp_messages[-1:],
                **(
                    {"temperature": 0.01, "top_p": machine.config.top_p}
                    if machine.config.model not in ["o1-mini", "o1-preview"]
                    else {}
                ),
            }
            assert response_parser is None, "response_parser should be None for context filling chat action"

            request_params['response_format'] = Response                                                           

            # Select the appropriate client based on model_name
            client_to_use, info = next(((client, info) for client, info in machine.clients if info['name'] == model_name), (None, None))
            if client_to_use is None:
                raise ValueError(f"Model '{model_name}' not found in initialized clients.")

            # Use the selected client to make the request
            logging.info(Fore.YELLOW + f'Waiting for the model {model_name} to process the request...')
            response = reliable_parse(client_to_use, request_params, max_retries=3, model_info=info)
            logging.info(Fore.GREEN + f'Model {model_name} processed the request successfully.')

            temp_messages.append({"role": "assistant", "content": response.choices[0].message.content})

            message = response.choices[0].message
            response_obj = message.content if getattr(message, "parsed", None) is None else message.parsed

            if not response_obj.context_code:
                break

            for code in response_obj.context_code:
                if code.name in context_code_names:
                    continue
                # Directly call the sub state machine to fill the context
                sub_context = CFContext(name=code.name, reason=code.reason, code_line=code.code_line, file_path=code.file_path)
                sub_machine = StateMachine(
                    context=sub_context,
                    state_definitions=state_definitions,  # Use the state definitions from code_filling_config
                    initial_state='InitializeSystemPrompt',  # Define your initial state here
                    config_path=machine.config.config_path
                )
                sub_result = sub_machine.process()
                context_code_str = sub_machine.definition
                accumulated_context_code += f"\nAccumulated FULL IMPLEMENT Context Code for {code.name}:\n{context_code_str}\n"
                context_code_names.add(code.name)
                # machine.total_input_tokens += sub_machine.total_input_tokens
                # machine.total_output_tokens += sub_machine.total_output_tokens
                # machine.messages.extend(sub_machine.messages)

                # print("Context Code:", sub_machine.definition)

            context_code_names_str = ", ".join(context_code_names)
            prompt = base_prompt + f"\n\n --------------- <!!! IMPORTANT ADDITIONAL CONTEXT CODE PROVIDED !!!> \n Here are some FULL implementations for Accumulated Context Code Names to increase the reliability of the analysis: {context_code_names_str}\n: {accumulated_context_code}\n" + safe_format(output_requirements2, context_code_names_str=context_code_names_str)
            # temp_messages.append({"role": "user", "content": prompt})
            iteration_count += 1

        machine.messages.extend(temp_messages[-2:])
        return response_obj.analysis

    return chat_action


def create_context_filling_new_chat_json_action(prompt_template, response_parser=None, save_option='both', model_name='azure-gpt4o', debug=False, use_hardcoded_json=False, accelerated_mode=True):
    """
    Create a context-filling chat action function with JSON response format.
    Provides accelerated mode and debugging features.
    
    :param prompt_template: The prompt template
    :param response_parser: Optional response parser
    :param save_option: Save option, can be 'both', 'prompt', 'result', or 'none'
    :param model_name: The model name to use
    :param debug: Whether to enable debugging
    :param use_hardcoded_json: Whether to use hardcoded JSON (for debugging)
    :param accelerated_mode: Whether to enable accelerated mode
    :return: The action function
    """
    def chat_action(machine, **kwargs):
        from BaseMachine.code_filling.code_filling_context import CFContext  # Move import here
        from BaseMachine.state_machine import StateMachine  # Move import here
        from BaseMachine.code_filling.code_filling_config import state_definitions  # Move import here

        # Modify client selection logic
        if accelerated_mode:
            # Get accelerated model and main model clients
            client_to_use, info = next(((client, info) for client, info in machine.clients if info['name'] == 'azure-gpt4o'), (None, None))
            fallback_client, fallback_info = next(((client, info) for client, info in machine.clients if info['name'] == model_name), (None, None))
        else:
            client_to_use, info = next(((client, info) for client, info in machine.clients if info['name'] == model_name), (None, None))
            fallback_client = None

        # Use safe_format instead of direct format
        base_prompt = safe_format(prompt_template, **kwargs)
        output_requirements = '''
        ---------------
        <!!! VERY IMPORTANT OUTPUT format Requirements>:

        - TOOL Description: 
            You are given access to a function definition search tool. Your could call this tool to help you to analysis the Above Task. 
        - WHEN to USE the TOOL: 
            If you CANNOT provide a VERY reliable analysis on the above question and NEED More definitions of specific symbols to answer the question, you MUST use the tool.
        
        - TOOLS Usage: 
            The function definition search tool accepts a function name list and returns the full implementation code of the function(s) you need to analyze the above question.
            Please verify whether the **function names** you want to feed into the function definition search tool conform to the following constraint:
            > Function names must consist only of letters, digits, and underscores. They **must not** include any special characters, including but not limited to `!`, `@`, `*`, `<`, `>`, `-`, or other symbols.  
            > This rule is necessary because our code search tool (OpenGrok) **cannot reliably search function names that include symbols such as `<` or `>`**, even if they are valid in C++ syntax (e.g., in templates).  
            > If a function is a template, you must **ignore the `template<>` part entirely** and analyze only the actual function name that follows it.

            You MUST perform this check across all function definitions provided.

        
        The output MUST be a JSON object with the following fields:

        - **analysis**: The analysis result of the question.
        - **context_code**: An input array to the function definition search tool IF you need to use the tool, otherwise it should be an empty array.

        EXAMPLE JSON OUTPUT:
        ```json
        {
            "analysis": "The function `parse<Request>` is invalid due to the inclusion of angle brackets, which OpenGrok cannot handle. Function `gen_func` might be macro-generated and needs further inspection.",
            "context_code": ["gen_func"]
        }

        ```
        '''
        output_requirements2 = '''
        ---------------
        <!!! VERY IMPORTANT OUTPUT format Requirements>:
        I have ALREADY provided you with the function definition of {context_code_names_str} shown ABOVE.
        
        - TOOL Description: 
            You are given access to a function definition search tool. Your could call this tool to help you to analysis the Above Task. 
        - WHEN to USE the TOOL: 
            If you CANNOT provide a VERY reliable analysis on the above question and NEED More definitions of specific symbols to answer the question, you MUST use the tool.
        
        - TOOLS Usage: 
            The function definition search tool accepts a function name list and returns the full implementation code of the function(s) you need to analyze the above question.
            Please verify whether the **function names** you want to feed into the function definition search tool conform to the following constraint:
            > Function names must consist only of letters, digits, and underscores. They **must not** include any special characters, including but not limited to `!`, `@`, `*`, `<`, `>`, `-`, or other symbols.  
            > This rule is necessary because our code search tool (OpenGrok) **cannot reliably search function names that include symbols such as `<` or `>`**, even if they are valid in C++ syntax (e.g., in templates).  
            > If a function is a template, you must **ignore the `template<>` part entirely** and analyze only the actual function name that follows it.

            You MUST perform this check across all function definitions provided.

        
        The output MUST be a JSON object with the following fields:

        - **analysis**: The analysis result of the question.
        - **context_code**: An input array to the function definition search tool IF you need to use the tool, otherwise it should be an empty array.

        EXAMPLE JSON OUTPUT:
        ```json
        {
            "analysis": "The function `parse<Request>` is invalid due to the inclusion of angle brackets, which OpenGrok cannot handle. Function `gen_func` might be macro-generated and needs further inspection.",
            "context_code": ["gen_func"]
        }
        '''
        prompt = base_prompt + output_requirements

        accumulated_context_code = ""
        context_code_names = set()
        provided_context_codes = set()

        iteration_count = 0
        current_client, current_info = (client_to_use, info)  # Currently used client
        fallback_triggered = False  # Flag whether fallback has been triggered
        
        while iteration_count < 20:
            if debug:
                logging.info(Fore.BLUE + f'Chat Action Prompt: {prompt}')
            temp_messages = [{"role": "user", "content": prompt}]
            request_params = {
                'model': current_info['model_name'],  # Fix to use the correct field
                'messages': temp_messages[-1:],
                **(
                    {"temperature": 0.01, "top_p": machine.config.top_p}
                    if current_info['model_name'] not in ["o1-mini", "o1-preview"]  # Synchronize fixed condition
                    else {}
                ),
            }
            assert response_parser is None, "response_parser should be None for context filling chat action"

            if use_hardcoded_json:
                # Use a hardcoded JSON string for debugging
                hardcoded_json = '''
                {
                    "analysis": "The call chain leading to RTMemFree is not possible in the given scenario. In CFGMR3InsertSubTree, the code checks that pSubTree->pVM matches pNode->pVM (non-NULL). Thus, in cfgmR3FreeNodeOnly, pNode->pVM is non-NULL, leading to MMR3HeapFree(pNode) instead of RTMemFree(pNode). The call to RTMemFree would only occur if pSubTree->pVM is NULL, which is prevented by the earlier validation in CFGMR3InsertSubTree. Therefore, the free_behavior call chain involving RTMemFree is not feasible here.",
                    "context_code": ["CFGMR3DuplicateSubTree"]
                }
                '''
                if debug:
                    logging.info(Fore.YELLOW + f'Raw JSON Response: {hardcoded_json}')
                
                response_obj = json.loads(hardcoded_json)  # Parse JSON response
            else:
                # Use reliable parse function to make request
                logging.info(Fore.YELLOW + f'Waiting for the model {current_info["name"]} to process the request...')
                response = reliable_parse(current_client, request_params, max_retries=5, debug=debug, model_info=current_info)

                # Ensure the content is a single JSON object
                try:
                    response_obj = parse_and_validate_json_response(
                        message=response.choices[0].message,
                        machine=machine,
                        debug=debug
                    )
                except Exception as e:
                    logging.error(Fore.RED + f"JSON parsing failed: {str(e)}")
                    return None

            if not response_obj['context_code']:
                if accelerated_mode and not fallback_triggered and fallback_client:
                    # Switch to main model for verification
                    current_client, current_info = fallback_client, fallback_info
                    fallback_triggered = True
                    logging.info(Fore.CYAN + "Switching to main model for final verification...")
                    continue  # Re-process current prompt
                else:
                    # Both models confirm no more context needed
                    break
            else:
                if fallback_triggered:
                    # Fallback model requested new context, switch back to accelerated model to continue
                    current_client, current_info = client_to_use, info
                    fallback_triggered = False
                    logging.info(Fore.CYAN + "Reverting to accelerated model...")

            current_context_codes = set(response_obj['context_code'])
            if current_context_codes.issubset(provided_context_codes):
                logging.info("All requested context codes have already been provided. Exiting loop to prevent hallucination.")
                break

            # Extract all the code snippets from the prompt
            code_snippets = extract_code_snippets(prompt)

            for code_name in current_context_codes:
                if code_name in context_code_names:
                    continue
                # Directly call the sub state machine to fill the context
                sub_context = CFContext(name=code_name, context_code=code_snippets)
                sub_machine = StateMachine(
                    context=sub_context,
                    state_definitions=state_definitions,  # Use the state definitions from code_filling_config
                    initial_state='InitializeSystemPrompt',  # Define your initial state here
                    config_path=machine.config.config_path
                )
                sub_result = sub_machine.process()
                context_code_str = sub_machine.definition
                accumulated_context_code += f"\nAccumulated FULL IMPLEMENT Context Code for {code_name}:\n{context_code_str}\n"
                context_code_names.add(code_name)
                provided_context_codes.add(code_name)

            context_code_names_str = ", ".join(context_code_names)
            prompt = base_prompt + f"\n\n --------------- <!!! IMPORTANT ADDITIONAL CONTEXT CODE PROVIDED !!!> \n Here are some FULL implementations for Accumulated Context Code Names to increase the reliability of the analysis: {context_code_names_str}\n: {accumulated_context_code}\n" + safe_format(output_requirements2, context_code_names_str=context_code_names_str)
            iteration_count += 1

        machine.messages.extend(temp_messages[-2:])
        return response_obj['analysis']

    return chat_action


def call_sub_state_machine_action(sub_state_definitions, sub_initial_state, sub_context_cls, save_option='both'):
    """
    Create an action function that calls a sub-state machine
    
    :param sub_state_definitions: The sub-state machine's state definitions
    :param sub_initial_state: The sub-state machine's initial state
    :param sub_context_cls: The sub-state machine's context class
    :param save_option: Save option, can be 'both', 'prompt', 'result', or 'none'
    :return: The action function
    """
    def sub_state_machine_action(machine, **kwargs):
        from BaseMachine.state_machine import StateMachine  # Move import here
        # Create the sub-state machine's context
        sub_context = sub_context_cls(**kwargs)
        
        # Create and run the sub-state machine
        sub_machine = StateMachine(
            context=sub_context,
            state_definitions=sub_state_definitions,
            initial_state=sub_initial_state,
            config_path=machine.config.config_path
        )
        sub_result = sub_machine.process()
        
        # Merge the sub-state machine's results and resource consumption
        machine.total_input_tokens += sub_machine.total_input_tokens
        machine.total_output_tokens += sub_machine.total_output_tokens
        machine.messages.extend(sub_machine.messages)
        
        # Save content based on the save_option parameter
        if save_option == 'prompt':
            machine.analysis_result.append(sub_context)
        elif save_option == 'result':
            machine.analysis_result.append(sub_result)
        elif save_option == 'both':
            machine.analysis_result.append({'context': sub_context, 'result': sub_result})
        else:
            # If an invalid save_option is provided, throw an exception or perform default handling
            raise ValueError("Invalid save_option value. Choose from 'prompt', 'result', or 'both'.")
        
        return sub_result
    return sub_state_machine_action
