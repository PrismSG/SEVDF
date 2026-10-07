import os
import re
import json
import logging
import importlib.util
from datetime import datetime
from colorama import Fore
from typing import Any, List
from pydantic import BaseModel, Field

# Check if json_repair is available (optional dependency for JSON recovery)
JSON_REPAIR_AVAILABLE = importlib.util.find_spec("json_repair") is not None
if JSON_REPAIR_AVAILABLE:
    import json_repair
    from json_repair import repair_json

# Define response model
class Response(BaseModel):
    analysis: str = Field(description="The analysis result of the question.")
    needed_functions_not_provided: List[str] = Field(description="If you need additional context code to analyze the question, please provide the function names you need additionally to analyze the question.")

# Import helper functions
from BaseMachine.llm_helpers import (
    reliable_parse,
    validate_json_schema,
    safe_format,
    extract_code_snippets as llm_extract_code_snippets
)


# Note: parse_and_validate_json_response() function has been removed as it was not being used.
# Use validate_json_schema() from llm_helpers instead for JSON validation.


# ---------------------------------------------------------------------------
# Prompt Dump Infrastructure
# ---------------------------------------------------------------------------
_prompt_dump_counter = 0
_ENABLE_RAW_PROMPT_DUMP = os.environ.get('ENABLE_RAW_PROMPT_DUMP', '0') == '1'

def _dump_prompt(messages, phase, context_label=None, tools=None, response_format=None):
    """
    Dump the full messages list to a JSON file under AI_ANALYSIS_DIR/prompt_dumps/.

    Each file captures one API call: the complete messages array, tool definitions,
    response_format, and metadata (timestamp, phase, context_label).

    Gated behind ENABLE_RAW_PROMPT_DUMP=1 env var. Use ReasoningDumpStorage for
    structured reasoning persistence instead.
    """
    if not _ENABLE_RAW_PROMPT_DUMP:
        return

    global _prompt_dump_counter
    ai_dir = os.environ.get('AI_ANALYSIS_DIR')
    if not ai_dir:
        return

    dump_dir = os.path.join(ai_dir, 'prompt_dumps')
    os.makedirs(dump_dir, exist_ok=True)

    _prompt_dump_counter += 1
    label = context_label or 'unknown'
    filename = f"{_prompt_dump_counter:04d}_{label}_{phase}.json"

    dump = {
        'seq': _prompt_dump_counter,
        'timestamp': datetime.now().isoformat(),
        'context_label': context_label,
        'phase': phase,
        'num_messages': len(messages),
        'messages': messages,
    }
    if tools:
        dump['tools'] = tools
    if response_format:
        dump['response_format'] = response_format

    filepath = os.path.join(dump_dir, filename)
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(dump, f, indent=2, ensure_ascii=False, default=str)
        logging.info(f'[PromptDump] Saved {filepath} ({len(messages)} messages)')
    except Exception as e:
        logging.warning(f'[PromptDump] Failed to save {filepath}: {e}')


def extract_needed_functions_from_json(content):
    """Extract needed functions from JSON content, handling various formats."""
    # Try direct JSON parse first
    try:
        obj = json.loads(content)
        if 'needed_functions_not_provided' in obj:
            return set(obj['needed_functions_not_provided'])
    except:
        pass
    
    # Try regex extraction
    import re
    # Pattern 1: Standard JSON array
    pattern1 = r'"needed_functions_not_provided"\s*:\s*\[(.*?)\]'
    match = re.search(pattern1, content, re.DOTALL)
    if match:
        funcs_str = match.group(1)
        # Extract function names from the array
        func_pattern = r'"([^"]+)"'
        func_names = re.findall(func_pattern, funcs_str)
        if func_names:
            return set(func_names)
    
    # Pattern 2: With possible extra fields
    pattern2 = r'"needed_functions_not_provided"\s*:\s*\[((?:[^[\]]*|\[.*?\])*)\]'
    match = re.search(pattern2, content, re.DOTALL)
    if match:
        funcs_str = match.group(1)
        func_names = re.findall(r'"([^"]+)"', funcs_str)
        if func_names:
            return set(func_names)
    
    return None


# Use the imported extract_code_snippets from llm_helpers
extract_code_snippets = llm_extract_code_snippets


# ============================================================
# Basic Chat Actions
# ============================================================

def create_chat_action(prompt_template, response_parser=None, save_option='both', model_name='gpt-oss-120b', debug=False):
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
            logging.debug(Fore.BLUE + f'Chat Action Prompt: {prompt}')

        machine.messages.append({"role": "user", "content": prompt})
        # Also save to complete conversation history
        if hasattr(machine, 'complete_conversation_history'):
            machine.complete_conversation_history.append({"role": "user", "content": prompt})
            logging.debug(Fore.CYAN + f'DEBUG: Added user message to conversation history. Total messages: {len(machine.complete_conversation_history)}')
        else:
            logging.warning(Fore.YELLOW + 'DEBUG: Machine does not have complete_conversation_history attribute')

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
        response, _ = reliable_parse(client_to_use, request_params, max_retries=3, debug=debug, model_info=info)
        logging.info(Fore.GREEN + f'Model {info["model_name"]} processed the request successfully.')
        # machine.total_input_tokens += response.usage.prompt_tokens
        # machine.total_output_tokens += response.usage.completion_tokens

        # Parse the assistant's reply first
        message = response.choices[0].message
        parsed_result = message.content if getattr(message, "parsed", None) is None else message.parsed
        
        # For structured outputs, convert parsed object to string for conversation history
        content_for_history = str(parsed_result) if response_parser and hasattr(parsed_result, '__dict__') else (message.content or str(parsed_result))
        
        # Add the assistant's reply to the message list
        assistant_message = {"role": "assistant", "content": content_for_history}
        machine.messages.append(assistant_message)
        # Also save to complete conversation history
        if hasattr(machine, 'complete_conversation_history'):
            machine.complete_conversation_history.append(assistant_message)
            logging.debug(Fore.CYAN + f'DEBUG: Added assistant message to conversation history. Total messages: {len(machine.complete_conversation_history)}')
        else:
            logging.warning(Fore.YELLOW + 'DEBUG: Machine does not have complete_conversation_history attribute for assistant message')

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


def create_new_chat_action(prompt_template, response_parser=None, save_option='both', model_name='gpt-oss-120b', debug=False):
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
            logging.debug(Fore.BLUE + f'Chat Action Prompt: {prompt}')

        machine.messages.append({"role": "user", "content": prompt})
        # Also save to complete conversation history
        if hasattr(machine, 'complete_conversation_history'):
            machine.complete_conversation_history.append({"role": "user", "content": prompt})
            logging.debug(Fore.CYAN + f'DEBUG: Added user message to conversation history. Total messages: {len(machine.complete_conversation_history)}')
        else:
            logging.warning(Fore.YELLOW + 'DEBUG: Machine does not have complete_conversation_history attribute')

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
        response, _ = reliable_parse(client_to_use, request_params, max_retries=3, debug=debug, model_info=info)
        logging.info(Fore.GREEN + f'Model {info["model_name"]} processed the request successfully.')

        # Parse the assistant's reply first
        message = response.choices[0].message
        parsed_result = message.content if getattr(message, "parsed", None) is None else message.parsed
        
        # For structured outputs, convert parsed object to string for conversation history
        content_for_history = str(parsed_result) if response_parser and hasattr(parsed_result, '__dict__') else (message.content or str(parsed_result))
        
        # Add the assistant's reply to the message list
        assistant_message = {"role": "assistant", "content": content_for_history}
        machine.messages.append(assistant_message)
        # Also save to complete conversation history
        if hasattr(machine, 'complete_conversation_history'):
            machine.complete_conversation_history.append(assistant_message)
            logging.debug(Fore.CYAN + f'DEBUG: Added assistant message to conversation history. Total messages: {len(machine.complete_conversation_history)}')
        else:
            logging.warning(Fore.YELLOW + 'DEBUG: Machine does not have complete_conversation_history attribute for assistant message')

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


# ============================================================
# Chat Actions with Tools / Code Filling
# ============================================================

def create_chat_action_with_tools(prompt_template, response_parser=None, save_option='both',
                                       model_name='gpt-oss-120b', debug=False, message_key='message',
                                       expected_fields=None, purpose_rules=None, transition_rules=None,
                                       max_tool_iterations=10, context_label=None):
    """
    Create a chat action that supports OpenAI function calling (tools) with actual tool execution.

    Built-in tools:
    - get_function_definition: Search for function implementations via OpenGrok

    :param prompt_template: The prompt template
    :param response_parser: Optional response parser
    :param save_option: Save option, can be 'both', 'prompt', 'result', or 'none'
    :param model_name: The model name
    :param debug: Whether to enable debugging
    :param message_key: The message key for the response
    :param expected_fields: List of expected fields in the final JSON response
    :param purpose_rules: List of purpose rules for rule_checks examples
    :param transition_rules: List of transition rules for transition_checks examples
    :param max_tool_iterations: Maximum number of tool call iterations (default: 10)
    :param context_label: Optional label to identify this analysis phase (e.g., 'SourceBackward', 'Intermediate')
    :return: The action function
    """
    # Import built-in tools
    from BaseMachine.code_filling.code_filling_tools import (
        ALL_SYMBOL_TOOLS,
        ALL_SYMBOL_EXECUTORS
    )

    # Built-in tool definitions and executors (function, macro, global_var, class)
    tool_definitions = ALL_SYMBOL_TOOLS
    tool_executors = ALL_SYMBOL_EXECUTORS

    def chat_action(machine, **kwargs):
        # Get model info to check tool call format
        client, info = next(((client, info) for client, info in machine.clients
                            if info['name'] == model_name), (None, None))

        # Check if model requires XML format (automatic routing)
        tool_format = info.get('tool_call_format', 'openai_native') if info else 'openai_native'

        if tool_format == 'xml_tags':
            # Route to XML-based fallback for models that don't support OpenAI native tools
            logging.info(f"[ToolRouter] Model {model_name} requires XML format, routing to fallback")
            return create_chat_action_with_tools_fallback(
                prompt_template, response_parser, save_option, model_name, debug,
                expected_fields, purpose_rules, transition_rules, context_label=context_label
            )(machine, **kwargs)

        # Continue with OpenAI native format
        from BaseMachine.code_filling.code_filling_context import CFContext
        from BaseMachine.state_machine import StateMachine
        from BaseMachine.code_filling.code_filling_config import state_definitions

        # Build base prompt
        base_prompt = safe_format(prompt_template, **kwargs)

        # Build output format requirements if expected_fields provided
        if expected_fields:
            analysis_template = _build_analysis_template(expected_fields, purpose_rules, transition_rules)
            output_requirements = f'''
---------------
<!!! OUTPUT FORMAT Requirements>:

**IMPORTANT - Two-Phase Process:**
1. **Phase 1 - Tool Calling (if needed)**: If you need additional information (e.g., function definitions, macro definitions), use the available tools to gather evidence FIRST. You can call tools multiple times until you have sufficient information.

2. **Phase 2 - JSON Output**: After you have gathered all necessary information (or if no tools are needed), provide your final analysis as a JSON object.

**Required JSON Format:**
{analysis_template['example']}

Required fields:
{analysis_template['field_descriptions']}

**Critical Instructions - Tool Calling Priority:**
- **ALWAYS prefer using tools to eliminate uncertainty and increase credibility**
- Use tools to verify ANY information you're unsure about (function definitions, behavior, data flow, etc.)
- Calling tools provides concrete evidence and significantly increases the trustworthiness of your analysis
- You can call tools multiple times - use them liberally to resolve every point of doubt
- Examples of when to use tools:
  * You see a function call but don't know its implementation → call get_function_definition
  * You're unsure about what a function does → call get_function_definition to verify
  * You need to understand data flow through a function → call get_function_definition
  * Any uncertainty about code behavior → resolve it with tools FIRST

**When to skip tools (rare cases):**
- ONLY skip tools if the prompt already provides ALL necessary code context
- If you have any doubt, USE TOOLS - it's better to over-verify than to make assumptions

**Response Format Rules:**
- Phase 1 (Tool Calling): Use the tool_calls API structure. Call tools to gather evidence.
- Phase 2 (JSON Output): After gathering sufficient evidence, provide your analysis as JSON.
- Do NOT output JSON until you have eliminated all uncertainties through tool calls
- During tool calling phase: Do NOT put tool names or JSON in the message content field.
- When providing JSON output: Respond with ONLY the JSON object, no additional text.
'''
            prompt = base_prompt + output_requirements
        else:
            prompt = base_prompt

        if debug:
            logging.debug(Fore.BLUE + f'Chat Action Prompt: {prompt}')

        temp_messages = [{"role": "user", "content": prompt}]

        # Track conversation history
        if hasattr(machine, 'complete_conversation_history'):
            machine.complete_conversation_history.append({"role": "user", "content": prompt})

        # Find the client
        client_to_use, info = next(((client, info) for client, info in machine.clients if info['name'] == model_name), (None, None))
        if not client_to_use:
            raise ValueError(f"No client found with model name: {model_name}")

        # Build request with tools
        request_params = {
            'model': info['model_name'],
            'messages': temp_messages,
            'temperature': 0.01,
            'top_p': machine.config.top_p if hasattr(machine.config, 'top_p') else 0.95
        }

        # Add tools
        if tool_definitions:
            request_params['tools'] = tool_definitions
            request_params['tool_choice'] = "auto"

        # Do NOT add response_format during tool calling phase
        # This prevents model confusion between calling tools and outputting JSON

        # Tool execution loop
        iteration = 0
        provided_symbol_names = set()  # Track all provided symbols (functions, macros, vars, classes)

        while iteration < max_tool_iterations:
            # Build context info for logging
            state_name = machine.state.name if hasattr(machine, 'state') and machine.state else 'Unknown'
            context_info = f"[{context_label}] " if context_label else ""

            logging.info(Fore.YELLOW + f'[State:{state_name}|Phase:ToolCalling|Iter:{iteration + 1}|Symbols:{len(provided_symbol_names)}] {context_info}Waiting for {model_name} to process request...')

            # Dump prompt before API call
            _dump_prompt(
                request_params['messages'],
                phase=f'tool_calling_iter{iteration + 1}',
                context_label=context_label,
                tools=request_params.get('tools'),
            )

            response, _ = reliable_parse(client_to_use, request_params, max_retries=5, debug=debug, model_info=info)

            message = response.choices[0].message

            # DEBUG: Print full response details
            logging.info(Fore.MAGENTA + f'[DEBUG] Tool calling iteration {iteration + 1} response:')
            logging.info(Fore.MAGENTA + f'  message.content: {repr(message.content)}')
            logging.info(Fore.MAGENTA + f'  message.tool_calls: {message.tool_calls is not None and len(message.tool_calls) if message.tool_calls else None}')
            if hasattr(message, 'reasoning'):
                logging.info(Fore.MAGENTA + f'  message.reasoning: {repr(message.reasoning)}')

            # Check if model wants to use tools
            if hasattr(message, 'tool_calls') and message.tool_calls:
                logging.info(Fore.CYAN + f'Model requested {len(message.tool_calls)} tool call(s)')

                # Debug: Log raw tool calls from API
                if debug:
                    logging.info(f'[DEBUG] Raw API tool_calls ({len(message.tool_calls)}):')
                    for i, tc in enumerate(message.tool_calls):
                        logging.info(f'  [{i}] id={tc.id}')
                        logging.info(f'       name={repr(tc.function.name)}')
                        logging.info(f'       args={repr(tc.function.arguments)}')

                # Validate and fix malformed tool_calls from API (OpenRouter sometimes splits tool calls)
                # CRITICAL: This must happen BEFORE adding to conversation history
                from BaseMachine.llm_helpers import validate_tool_calls
                fixed_tool_calls = validate_tool_calls(message.tool_calls, debug=debug)

                # Filter out redundant tool calls (already provided in this conversation)
                valid_tool_calls, redundant_calls, redundancy_feedback = _filter_redundant_tool_calls(
                    fixed_tool_calls,
                    provided_symbol_names,
                    tool_format='native'
                )

                # Check if all calls are redundant
                if redundancy_feedback and not valid_tool_calls:
                    # All requested symbols already provided, send feedback to model
                    logging.warning(f"[ToolCalling] All requested symbols already provided: {redundant_calls}")
                    temp_messages.append({
                        "role": "assistant",
                        "content": message.content,
                        "tool_calls": [
                            {
                                "id": tc.id,
                                "type": "function",
                                "function": {
                                    "name": tc.function.name,
                                    "arguments": tc.function.arguments
                                }
                            } for tc in fixed_tool_calls
                        ]
                    })
                    # Send feedback as a mock tool response
                    for tc in fixed_tool_calls:
                        temp_messages.append({
                            "role": "tool",
                            "tool_call_id": tc.id,
                            "content": redundancy_feedback
                        })
                    iteration += 1
                    continue

                # Use valid_tool_calls (filtered) instead of fixed_tool_calls
                fixed_tool_calls = valid_tool_calls

                # Add assistant message with FIXED tool calls to conversation
                # Use fixed_tool_calls instead of message.tool_calls to avoid sending invalid fragments back to API
                assistant_with_tools = {
                    "role": "assistant",
                    "content": message.content,
                    "tool_calls": [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {
                                "name": tc.function.name,
                                "arguments": tc.function.arguments
                            }
                        } for tc in fixed_tool_calls
                    ]
                }
                temp_messages.append(assistant_with_tools)

                # Save to conversation history
                if hasattr(machine, 'complete_conversation_history'):
                    machine.complete_conversation_history.append(assistant_with_tools)

                # Execute each tool call
                for tool_call in fixed_tool_calls:
                    tool_name = tool_call.function.name

                    # DEBUG: Print raw arguments before parsing
                    logging.info(Fore.MAGENTA + f'[DEBUG] Parsing tool arguments:')
                    logging.info(Fore.MAGENTA + f'  tool_name: {tool_name}')
                    logging.info(Fore.MAGENTA + f'  tool_call.id: {tool_call.id}')
                    logging.info(Fore.MAGENTA + f'  raw arguments: {repr(tool_call.function.arguments)}')
                    logging.info(Fore.MAGENTA + f'  arguments length: {len(tool_call.function.arguments)}')

                    # Parse arguments (already fixed by validate_tool_calls)
                    try:
                        tool_args = json.loads(tool_call.function.arguments)
                    except json.JSONDecodeError as e:
                        logging.warning(Fore.YELLOW + f'[WARN] Failed to parse tool arguments, attempting repair...')
                        logging.warning(Fore.YELLOW + f'  Error: {e}')
                        logging.warning(Fore.YELLOW + f'  Arguments: {repr(tool_call.function.arguments)}')
                        if JSON_REPAIR_AVAILABLE:
                            try:
                                repaired = repair_json(tool_call.function.arguments)
                                tool_args = json.loads(repaired)
                                logging.info(Fore.GREEN + f'[RECOVERED] Tool arguments repaired successfully')
                                logging.info(Fore.GREEN + f'  Repaired: {repr(repaired)}')
                            except Exception as repair_error:
                                logging.error(Fore.RED + f'[ERROR] Tool argument repair also failed: {repair_error}')
                                raise e
                        else:
                            logging.error(Fore.RED + f'[ERROR] json_repair not available, cannot recover')
                            raise

                    logging.info(Fore.CYAN + f'Executing tool: {tool_name} with args: {tool_args}')

                    # Execute the tool
                    if tool_name in tool_executors:
                        try:
                            tool_result_content = tool_executors[tool_name](tool_args, machine)

                            # Track provided symbols (use shared extractor)
                            symbol_name = _extract_symbol_name(tool_args)
                            if symbol_name:
                                provided_symbol_names.add(symbol_name)

                        except Exception as e:
                            logging.error(Fore.RED + f'Tool execution error: {e}')
                            tool_result_content = f"Error executing tool: {str(e)}"
                    else:
                        logging.warning(Fore.YELLOW + f'No executor found for tool: {tool_name}')
                        tool_result_content = f"Tool {tool_name} not implemented"

                    # Format result as string if needed
                    if not isinstance(tool_result_content, str):
                        tool_result_content = json.dumps(tool_result_content, indent=2)

                    if debug:
                        logging.debug(Fore.GREEN + f'Tool result: {tool_result_content[:500]}...')

                    # Add tool result to conversation
                    tool_response = {
                        "tool_call_id": tool_call.id,
                        "role": "tool",
                        "content": tool_result_content
                    }
                    temp_messages.append(tool_response)

                    # Save to conversation history
                    if hasattr(machine, 'complete_conversation_history'):
                        machine.complete_conversation_history.append(tool_response)

                # Update request messages for next iteration
                request_params['messages'] = temp_messages
                iteration += 1

            else:
                # No tool calls - model is ready to give final response
                context_info = f"[{context_label}] " if context_label else ""

                # DEBUG: Print why we're exiting
                logging.info(Fore.MAGENTA + f'[DEBUG] Exiting tool calling loop:')
                logging.info(Fore.MAGENTA + f'  message.content: {repr(message.content)}')
                logging.info(Fore.MAGENTA + f'  iteration: {iteration}')

                if iteration > 0:
                    logging.info(Fore.GREEN + f'{context_info}Model finished tool calling loop after {iteration + 1} iteration(s)')
                else:
                    logging.info(Fore.GREEN + f'{context_info}Model did not use tools, exiting tool calling loop')
                break

        if iteration >= max_tool_iterations:
            logging.warning(Fore.YELLOW + f'Reached max tool iterations ({max_tool_iterations})')

        # Check if model already provided JSON in the tool calling phase
        json_already_provided = False
        json_schema = None
        final_parsed_json = None  # Store the final validated JSON to avoid redundant parsing

        if expected_fields:
            # Build JSON schema (will be used for validation either way)
            json_schema = _build_json_schema(expected_fields)

            # Try to validate the current response content
            current_content = response.choices[0].message.content if hasattr(response.choices[0].message, 'content') else None

            if current_content and current_content.strip():
                # Try to validate current content as JSON
                from BaseMachine.llm_helpers import validate_json_schema
                success, parsed, error_msg = validate_json_schema(current_content, json_schema, debug=debug, retry_count=0)

                if success:
                    context_info = f"[{context_label}] " if context_label else ""
                    logging.info(Fore.GREEN + f'{context_info}Model provided valid JSON directly in tool calling phase')
                    json_already_provided = True
                    final_parsed_json = parsed  # Save the validated JSON
                else:
                    if debug:
                        logging.debug(f'Current content is not valid JSON: {error_msg}')

        # If JSON not yet provided and expected_fields required, make a second request with response_format
        if expected_fields and not json_already_provided:
            state_name = machine.state.name if hasattr(machine, 'state') and machine.state else 'Unknown'
            context_info = f"[{context_label}] " if context_label else ""

            logging.info(Fore.CYAN + f'[State:{state_name}|Phase:JSONOutput|Iter:1] {context_info}Requesting final JSON response with response_format...')

            # DEBUG: Print the conversation history being sent
            logging.info(Fore.MAGENTA + f'[DEBUG] Sending JSON request with conversation history:')
            logging.info(Fore.MAGENTA + f'  Number of messages: {len(temp_messages)}')
            if temp_messages:
                logging.info(Fore.MAGENTA + f'  Last message role: {temp_messages[-1].get("role")}')
                last_content = temp_messages[-1].get("content", "")
                logging.info(Fore.MAGENTA + f'  Last message content (first 200 chars): {repr(last_content[:200])}')

            # Remove tools for final request - we want JSON output only
            final_request_params = {
                'model': info['model_name'],
                'messages': temp_messages,
                'temperature': 0.01,
                'top_p': machine.config.top_p if hasattr(machine.config, 'top_p') else 0.95,
                'response_format': {
                    "type": "json_schema",
                    "json_schema": {
                        "name": "analysis_response",
                        "strict": True,
                        "schema": json_schema
                    }
                }
            }

            # Dump prompt before final JSON API call
            _dump_prompt(
                final_request_params['messages'],
                phase='json_output',
                context_label=context_label,
                response_format=final_request_params.get('response_format'),
            )

            response, final_parsed_json = reliable_parse(client_to_use, final_request_params, max_retries=5, debug=debug, model_info=info)

            # DEBUG: Print response metadata after JSON request (without full content)
            logging.info(Fore.MAGENTA + f'[DEBUG] JSON request response:')
            logging.info(Fore.MAGENTA + f'  response.id: {response.id if response else None}')
            if response and response.choices:
                msg = response.choices[0].message
                content_len = len(msg.content) if msg.content else 0
                logging.info(Fore.MAGENTA + f'  message.content length: {content_len} chars')
                logging.info(Fore.MAGENTA + f'  message.role: {msg.role}')
                if hasattr(msg, 'reasoning'):
                    logging.info(Fore.MAGENTA + f'  message.reasoning: {repr(msg.reasoning)}')
                if hasattr(response, 'usage'):
                    logging.info(Fore.MAGENTA + f'  usage: {response.usage}')

        # Parse final response
        raw_content = response.choices[0].message.content

        # Add to conversation history
        if hasattr(machine, 'complete_conversation_history'):
            machine.complete_conversation_history.append({"role": "assistant", "content": raw_content})

        # Parse JSON if expected_fields provided
        # Optimization: Use the parsed JSON from reliable_parse() or the validation check above
        # This avoids redundant JSON parsing
        if expected_fields:
            if final_parsed_json is not None:
                # Use the already validated and parsed JSON
                result = final_parsed_json
                if debug:
                    logging.debug('Using pre-validated JSON result (no redundant parsing)')
            else:
                # Fallback: This should rarely happen (only if response_format wasn't used)
                # Parse the JSON using validate_json_schema
                success, result, error_msg = validate_json_schema(raw_content, json_schema, debug=debug, retry_count=0)

                if not success:
                    logging.error(Fore.RED + f'Unexpected: JSON validation failed in action_utils: {error_msg}')
                    logging.error(Fore.RED + '  This may indicate a bug in validate_json_schema')
                    result = {"analysis": raw_content, "parse_error": error_msg}
        elif response_parser:
            result = response_parser(response.choices[0].message)
        else:
            result = raw_content

        # Update machine state
        machine.messages.extend(temp_messages)
        machine.messages.append({"role": "assistant", "content": raw_content})

        # Save based on save_option
        if save_option in ['prompt', 'both']:
            machine.analysis_result.append({'prompt': prompt})
        if save_option in ['result', 'both']:
            machine.analysis_result.append({message_key: result})

        return result

    return chat_action


def create_chat_action_with_tools_fallback(prompt_template, response_parser=None, save_option='both', model_name='gpt-oss-120b', debug=False, expected_fields=None, purpose_rules=None, transition_rules=None, context_label=None):
    """
    Create a chat action function with XML-based tool calling format.
    This is the fallback version for models that don't support OpenAI native Tools API (e.g., QwQ).
    Uses XML tags for tool calls and supports multiple symbol lookup tools.

    Response types:
    1. Tool Call Response: <tool_call>{"name": "tool_name", "arguments": {...}}</tool_call>
    2. Analysis Response: JSON format with expected_fields

    :param prompt_template: The prompt template
    :param response_parser: Optional response parser (not supported, must be None)
    :param save_option: Save option, can be 'both', 'prompt', 'result', or 'none'
    :param model_name: The model name to use
    :param debug: Whether to enable debugging
    :param expected_fields: List of expected fields in the analysis response
    :param purpose_rules: List of purpose rules for rule_checks examples
    :param transition_rules: List of transition rules for transition_checks examples
    :return: The action function
    """
    def chat_action(machine, **kwargs):
        from BaseMachine.code_filling.code_filling_tools import (
            ALL_SYMBOL_TOOLS,
            ALL_SYMBOL_EXECUTORS
        )
        import os

        # Get the client for the specified model
        client, info = next(((client, info) for client, info in machine.clients if info['name'] == model_name), (None, None))

        base_prompt = safe_format(prompt_template, **kwargs)
        
        # Build the analysis response template
        analysis_template = _build_analysis_template(expected_fields, purpose_rules, transition_rules)

        # Build XML tool descriptions
        tool_descriptions = _build_xml_tool_descriptions(ALL_SYMBOL_TOOLS)

        # Build the XML-based output requirements
        output_requirements = f'''
        ---------------
        <!!! TOOL CALLING FORMAT>:

        You have access to the following symbol lookup tools to help with analysis:

{tool_descriptions}

        **CRITICAL - ONLY use the tools listed above:**
        - These are the ONLY available tools - do NOT attempt to call any other tools
        - Do NOT create, invent, or guess tool names (e.g., do NOT call "get_global_var_definition" or any tool not explicitly listed above)
        - If a tool you think should exist is not listed, it means it is unavailable - work with the available tools only

        **Tool Calling Priority - ALWAYS prefer using tools:**
        - **Use tools liberally to eliminate ANY uncertainty and increase analysis credibility**
        - Call tools to verify information about functions, macros, variables, classes, etc.
        - Using tools provides concrete evidence and makes your analysis more trustworthy
        - You can call multiple tools in one response - use them to resolve every point of doubt

        **CRITICAL - When you see function calls in the provided code:**
        - If you see a function call (e.g., 'data = someFunction(arg)'), you MUST use get_function_definition to look up the function BEFORE concluding its definition is unavailable
        - NEVER say "function definition is not visible" or "implementation is not provided" without first trying the tool
        - The system has access to definitions across the entire codebase - the tool can find them
        - Only if get_function_definition returns "NOT FOUND" can you conclude the definition is unavailable
        - This applies to ANY function you see called in the code context, even if the call is in a different file

        **Examples:**
        - You see 'result = processData(input)' → MUST call get_function_definition("processData") first
        - You see 'foo = bar()' → MUST call get_function_definition("bar") before analyzing
        - Unsure about function behavior? Call get_function_definition
        - Don't know what a macro does? Call get_macro_definition

        **When to skip tools:**
        - ONLY skip tools if the prompt already provides the COMPLETE definition of that specific symbol
        - Standard library functions (printf, malloc, etc.) - these are well-known
        - If you have ANY doubt about code behavior, USE TOOLS FIRST - better to over-verify than assume

        **Technical constraints:**
        - Do NOT call tools for standard library symbols or already-provided definitions (avoid redundancy)
        - Symbol names must consist only of letters, digits, underscores, and :: (for qualified names)
        - Do NOT include template parameters (e.g., use "MyFunc" not "MyFunc<int>")

        **Tool call format** (MUST have "name" and "arguments" fields):
        Wrap each tool call in <tool_call> tags with JSON inside:
        <tool_call>
        {{"name": "tool_name", "arguments": {{"param_name": "param_value"}}}}
        </tool_call>

        You can make multiple tool calls:
        <tool_call>
        {{"name": "get_function_definition", "arguments": {{"function_name": "my_function"}}}}
        </tool_call>
        <tool_call>
        {{"name": "get_macro_definition", "arguments": {{"macro_name": "MAX_SIZE"}}}}
        </tool_call>

        **Analysis format** (NO <tool_call> tags, just plain JSON):
        When you have all information needed, provide your analysis as plain JSON (NOT wrapped in <tool_call> tags):
        {analysis_template['example']}

        Required fields for analysis:
{analysis_template['field_descriptions']}

        CRITICAL FORMAT RULES:
        1. Tool calls: MUST use <tool_call> tags AND have {{"name": "...", "arguments": {{...}}}} structure
        2. Final analysis: MUST be plain JSON (starting with ```json or just {{) - NO <tool_call> tags
        3. NEVER put analysis JSON inside <tool_call> tags
        4. NEVER put {{"analysis": "..."}} inside <tool_call> - that's wrong!
        5. Choose ONE format per response: either tool calls OR final analysis, never both
        '''
        
        # For subsequent iterations, emphasize not requesting already-provided symbols
        output_requirements_with_context = f'''
        ---------------
        <!!! TOOL RESPONSES PROVIDED>:

        You have already been provided with the following symbol definitions: {{provided_function_names_str}}

        **Available Tools**:
{tool_descriptions}

        **CRITICAL - ONLY use the tools listed above:**
        - These are the ONLY available tools - do NOT attempt to call any other tools
        - Do NOT create, invent, or guess tool names (e.g., do NOT call "get_global_var_definition" or any tool not explicitly listed above)
        - If a tool you think should exist is not listed, it means it is unavailable - work with the available tools only

        **If you need MORE symbols**:
        Use <tool_call> tags (with "name" and "arguments") to request additional symbols:
        <tool_call>
        {{"name": "tool_name", "arguments": {{"param_name": "value"}}}}
        </tool_call>

        IMPORTANT: Do NOT request symbols that have already been provided above!

        **When you have enough information**:
        Provide your final analysis as plain JSON (NO <tool_call> tags):
        {analysis_template['example']}

        Required fields:
{analysis_template['field_descriptions']}

        CRITICAL FORMAT RULES:
        1. Tool calls: use <tool_call> with {{"name": "...", "arguments": {{...}}}}
        2. Final analysis: plain JSON with NO <tool_call> tags
        3. NEVER mix the two formats
        '''

        # Initialize loop variables
        accumulated_function_implementations = ""
        provided_function_names = set()
        already_provided_functions = set()
        iteration_count = 0
        json_retry_count = 0  # For strict validation of analysis responses
        validation_error_feedback = ""  # Store validation errors across iterations

        # Main execution loop
        while iteration_count < 20:
            # Determine which prompt to use
            if provided_function_names:
                prompt = base_prompt + f"\n\n --------------- <!!! TOOL RESPONSES PROVIDED !!!> \n The following symbol definitions have been fetched for you: {', '.join(provided_function_names)}\n{accumulated_function_implementations}\n" + safe_format(output_requirements_with_context, provided_function_names_str=', '.join(provided_function_names))
            else:
                prompt = base_prompt + output_requirements
            
            # Add validation error feedback if present
            if validation_error_feedback:
                prompt = prompt + validation_error_feedback
                
            if debug:
                logging.debug(Fore.BLUE + f'Chat Action Prompt: {prompt}')
                
            temp_messages = [{"role": "user", "content": prompt}]
            
            # Add to conversation history
            if hasattr(machine, 'complete_conversation_history'):
                machine.complete_conversation_history.append({"role": "user", "content": prompt})
                logging.debug(f'Added user message to conversation history at iteration {iteration_count}')

            # Make request to LLM
            request_params = {
                'model': info['model_name'],
                'messages': temp_messages[-1:],
                **({
                    "temperature": 0.01, "top_p": machine.config.top_p}
                   if info['model_name'] not in ["o1-mini", "o1-preview"] else {}),
            }

            state_name = machine.state.name if hasattr(machine, 'state') and machine.state else 'Unknown'
            context_info = f"[{context_label}] " if context_label else ""

            logging.info(Fore.YELLOW + f'[State:{state_name}|Phase:XMLTools|Iter:{iteration_count + 1}|Symbols:{len(provided_function_names)}] {context_info}Waiting for {info["name"]} to process request...')

            # Dump prompt before API call (XML fallback)
            _dump_prompt(
                request_params['messages'],
                phase=f'xml_tool_iter{iteration_count + 1}',
                context_label=context_label,
            )

            response, _ = reliable_parse(client, request_params, max_retries=5, debug=debug, model_info=info)
            logging.debug(Fore.YELLOW + f'Response: {response}')
            
            # Parse the response
            try:
                raw_content = response.choices[0].message.content

                # Add assistant response to history
                if hasattr(machine, 'complete_conversation_history'):
                    machine.complete_conversation_history.append({
                        "role": "assistant",
                        "content": raw_content
                    })

                # Try to parse XML tool calls first
                from BaseMachine.llm_helpers import validate_xml_tool_calls
                tool_calls = validate_xml_tool_calls(raw_content, debug=debug)
                is_tool_call = tool_calls is not None and len(tool_calls) > 0

                if is_tool_call:
                    logging.info(f"[XMLTools] Found {len(tool_calls)} tool call(s)")

                if not is_tool_call:
                    # No tool calls found, try to parse as final analysis JSON
                    try:
                        response_obj = _parse_response(raw_content, debug)
                    except Exception as parse_error:
                        # Neither tool calls nor valid JSON
                        logging.error(f"[XMLFallback] Parse error: {str(parse_error)}")

                        # Check if they put analysis JSON inside <tool_call> tags (common mistake)
                        if '<tool_call>' in raw_content and '"analysis"' in raw_content:
                            error_hint = "\n\n❌ FORMAT ERROR DETECTED: You put analysis JSON inside <tool_call> tags!\n\n"
                            error_hint += "WRONG:\n<tool_call>\n{{\"analysis\": \"...\"}}\n</tool_call>\n\n"
                            error_hint += "CORRECT (for tool calls):\n<tool_call>\n{{\"name\": \"get_function_definition\", \"arguments\": {{\"function_name\": \"foo\"}}}}\n</tool_call>\n\n"
                            error_hint += "CORRECT (for final analysis):\n```json\n{{\"analysis\": \"...\", \"reachability\": \"...\", ...}}\n```\n\n"
                            error_hint += "Please provide your response in the correct format.\n"
                        else:
                            error_hint = f"\n\nError: Your response must be either:\n1. Tool calls: <tool_call>{{\"name\": \"...\", \"arguments\": {{...}}}}</tool_call>\n2. Final analysis: plain JSON (no <tool_call> tags)\n\nParse error: {str(parse_error)[:200]}\n\nPlease provide a valid response.\n"

                        if iteration_count < 3:
                            validation_error_feedback = error_hint
                            iteration_count += 1
                            continue
                        else:
                            raise

                if is_tool_call:
                    # Handle tool call response
                    logging.info(f"[XMLTools] Detected {len(tool_calls)} tool call(s)")

                    # Clear any validation errors since we got valid tool calls
                    validation_error_feedback = ""

                    # Check for redundant tool calls (already provided symbols) using shared function
                    valid_tool_calls, redundant_calls, redundancy_feedback = _filter_redundant_tool_calls(
                        tool_calls,
                        already_provided_functions,
                        tool_format='xml'
                    )

                    if redundancy_feedback and not valid_tool_calls:
                        # All requested symbols already provided
                        logging.warning(f"[XMLTools] All requested symbols already provided: {redundant_calls}")
                        validation_error_feedback = redundancy_feedback
                        iteration_count += 1
                        continue

                    # Update tool_calls to only include valid ones
                    tool_calls = valid_tool_calls

                    logging.info(f"[XMLTools] Processing {len(tool_calls)} tool call(s): {[tc['name'] for tc in tool_calls]}")
                
                if not is_tool_call:
                    # Handle analysis response (Option 2)
                    # Use unified validation function
                    if expected_fields:
                        # Build schema for validation
                        schema = _build_json_schema(expected_fields)

                        # Validate using the unified function
                        # Convert response_obj back to JSON string for validation
                        success, validated_result, error_msg = validate_json_schema(
                            json.dumps(response_obj),
                            schema,
                            debug,
                            retry_count=json_retry_count
                        )

                        # Also check for unexpected fields (additional validation specific to fallback mode)
                        unexpected_keys = None
                        if success:
                            allowed_keys = set(['analysis'] + expected_fields)
                            unexpected_keys = set(response_obj.keys()) - allowed_keys
                            if unexpected_keys:
                                success = False
                                error_msg = f"Unexpected fields: {unexpected_keys}"

                        if not success:
                            if json_retry_count < 3:
                                # Validation failed
                                json_retry_count += 1
                                logging.warning(f"JSON validation failed (attempt {json_retry_count}/3): {error_msg}")

                                validation_error_feedback = "\n\nYou chose Option 2 (Provide Analysis), but your JSON response had validation errors:\n"
                                validation_error_feedback += f"- Error: {error_msg}\n"
                                validation_error_feedback += f"- Fields you provided: {list(response_obj.keys())}\n"
                                allowed_keys = set(['analysis'] + expected_fields)
                                validation_error_feedback += f"- Required fields for Option 2: {sorted(allowed_keys)}\n"
                                validation_error_feedback += f"\nYour previous response:\n{json.dumps(response_obj, indent=2)[:500]}...\n"
                                validation_error_feedback += f"\nPlease provide your analysis again using Option 2 with EXACTLY these fields: {sorted(allowed_keys)}\n"
                                validation_error_feedback += "No other fields should be included.\n\n"
                                validation_error_feedback += "CORRECT FORMAT EXAMPLE:\n" + analysis_template['example']

                                continue
                            else:
                                # Exceeded retry limit
                                logging.warning(f"Exceeded validation retry limit ({json_retry_count} attempts)")

                    # Analysis response is valid - clear error feedback
                    validation_error_feedback = ""

                    # Log success with details
                    context_info = f"[{context_label}] " if context_label else ""
                    state_name = machine.state.name if hasattr(machine, 'state') and machine.state else 'Unknown'

                    logging.info(Fore.GREEN + f'[State:{state_name}|Phase:XMLTools] {context_info}Analysis complete!')
                    logging.info(Fore.GREEN + f'  Total iterations: {iteration_count + 1}')
                    if json_retry_count > 0:
                        logging.info(Fore.YELLOW + f'  JSON validation retries: {json_retry_count}')
                    if provided_function_names:
                        logging.info(Fore.CYAN + f'  Symbols fetched: {len(provided_function_names)} ({", ".join(sorted(provided_function_names))})')
                    break
                
                else:
                    # Tool call response - execute the requested tools
                    logging.info(f"[XMLTools] Executing {len(tool_calls)} tool(s)")

                    # Clear any validation errors since we're processing valid tool calls
                    validation_error_feedback = ""

                    # Execute each tool call
                    for tool_call in tool_calls:
                        tool_name = tool_call['name']
                        tool_args = tool_call['arguments']

                        if tool_name not in ALL_SYMBOL_EXECUTORS:
                            logging.warning(f"[XMLTools] Unknown tool: {tool_name}, skipping")
                            accumulated_function_implementations += f"\n\n<tool_response>\nTool: {tool_name}\nError: Unknown tool\n</tool_response>\n"
                            continue

                        # Execute tool
                        try:
                            logging.info(f"[XMLTools] Executing {tool_name} with args: {tool_args}")
                            tool_result = ALL_SYMBOL_EXECUTORS[tool_name](tool_args, machine)

                            # Format as XML tool response
                            accumulated_function_implementations += f"\n\n<tool_response>\nTool: {tool_name}\nArguments: {json.dumps(tool_args)}\n\nResult:\n{tool_result}\n</tool_response>\n"

                            # Track provided symbols (use shared extractor)
                            symbol_name = _extract_symbol_name(tool_args)
                            if symbol_name:
                                provided_function_names.add(symbol_name)
                                already_provided_functions.add(symbol_name)

                            logging.info(f"[XMLTools] {tool_name}({symbol_name}): SUCCESS")

                        except Exception as tool_error:
                            logging.error(f"[XMLTools] {tool_name}: execution failed - {tool_error}")
                            accumulated_function_implementations += f"\n\n<tool_response>\nTool: {tool_name}\nArguments: {json.dumps(tool_args)}\n\nError: {str(tool_error)}\n</tool_response>\n"

            except Exception as e:
                logging.error(f"Unexpected error during response processing: {str(e)}")
                logging.error(f"Error type: {type(e).__name__}")
                
                if iteration_count < 3:
                    logging.warning(f"Retrying due to error (attempt {iteration_count + 1}/3)")
                    iteration_count += 1
                    continue
                else:
                    raise
            
            iteration_count += 1

        # Save messages to machine context
        machine.messages.extend(temp_messages[-2:])
        
        # Always return the full JSON object
        return response_obj

    return chat_action


# ============================================================
# Helper Functions
# ============================================================

def _extract_symbol_name(tool_args):
    """
    Extract symbol name from tool arguments.

    Args:
        tool_args: Dict with arguments like {'function_name': 'foo'} or {'macro_name': 'MAX'}

    Returns:
        Symbol name string or None
    """
    return (tool_args.get('function_name') or
            tool_args.get('macro_name') or
            tool_args.get('var_name') or
            tool_args.get('class_name'))


def _filter_redundant_tool_calls(tool_calls, already_provided, tool_format='native'):
    """
    Filter out redundant tool calls that request already-provided symbols.

    Args:
        tool_calls: List of tool calls (OpenAI native format or XML dict format)
        already_provided: Set of symbol names already provided in this conversation
        tool_format: 'native' (OpenAI ToolCall objects) or 'xml' (dicts with 'name'/'arguments')

    Returns:
        Tuple of (valid_tool_calls, redundant_calls_list, feedback_message)
        - valid_tool_calls: Filtered list without redundant calls
        - redundant_calls_list: List of "tool_name(symbol)" strings that were redundant
        - feedback_message: Message to send to model, or empty string if no redundancy
    """
    redundant_calls = []
    valid_tool_calls = []

    for tool_call in tool_calls:
        # Extract tool name and arguments based on format
        if tool_format == 'native':
            tool_name = tool_call.function.name
            tool_args_str = tool_call.function.arguments
            try:
                tool_args = json.loads(tool_args_str)
            except json.JSONDecodeError:
                # If parsing fails, treat as valid (will be handled by executor)
                valid_tool_calls.append(tool_call)
                continue
        else:  # xml format
            tool_name = tool_call['name']
            tool_args = tool_call['arguments']

        # Extract symbol name
        symbol_name = _extract_symbol_name(tool_args)

        # Check if already provided
        if symbol_name and symbol_name in already_provided:
            redundant_calls.append(f"{tool_name}({symbol_name})")
        else:
            valid_tool_calls.append(tool_call)

    # Generate feedback message
    feedback_message = ""
    if redundant_calls:
        if not valid_tool_calls:
            # All calls are redundant
            feedback_message = f"\n\nNOTE: The symbols you requested have ALREADY been provided:\n"
            feedback_message += f"- {', '.join(redundant_calls)}\n"
            feedback_message += f"- Already provided: {', '.join(sorted(already_provided))}\n"
            feedback_message += "Please review the provided definitions. If you need additional symbols, request them. Otherwise, provide your final analysis.\n"
        else:
            # Some calls are redundant, some are valid
            logging.info(f"[ToolCalling] Skipping redundant calls: {redundant_calls}")

    return valid_tool_calls, redundant_calls, feedback_message


def _build_json_schema(expected_fields):
    """
    Build JSON schema for OpenAI response_format based on expected_fields.

    Args:
        expected_fields: List of expected field names

    Returns:
        JSON schema dict for OpenAI structured outputs
    """
    # Define schema for each known field
    field_schemas = {
        'analysis': {'type': 'string', 'description': 'Comprehensive analysis of the vulnerability'},
        'reachability': {'type': 'string', 'enum': ['REACHABLE', 'UNREACHABLE'], 'description': 'Whether the path is reachable'},
        'reachability_explanation': {'type': 'string', 'description': 'Explanation for the reachability verdict'},
        'required_conditions': {'type': 'array', 'items': {'type': 'string'}, 'description': 'Conditions required for execution'},
        'reachability_confidence': {'type': 'string', 'enum': ['HIGH', 'MEDIUM', 'LOW'], 'description': 'Confidence level'},
        'is_false_positive': {'type': 'boolean', 'description': 'True if this is a false positive'},
        'false_positive_confidence': {'type': 'string', 'enum': ['HIGH', 'MEDIUM', 'LOW'], 'description': 'Confidence in FP determination'},
        'overall_assessment': {'type': 'string', 'description': 'Summary of key findings'},
        'rule_checks': {
            'type': 'array',
            'items': {
                'type': 'object',
                'properties': {
                    'rule_text': {'type': 'string'},
                    'what_checked': {'type': 'string'},
                    'findings': {'type': 'string'},
                    'confidence': {'type': 'string', 'enum': ['HIGH', 'MEDIUM', 'LOW']}
                },
                'required': ['rule_text', 'what_checked', 'findings', 'confidence'],
                'additionalProperties': False
            },
            'description': 'Checks for each rule'
        },
        'transition_checks': {
            'type': 'array',
            'items': {
                'type': 'object',
                'properties': {
                    'rule_text': {'type': 'string'},
                    'what_analyzed': {'type': 'string'},
                    'findings': {'type': 'string'},
                    'breaks_propagation': {'type': 'boolean'},
                    'confidence': {'type': 'string', 'enum': ['HIGH', 'MEDIUM', 'LOW']}
                },
                'required': ['rule_text', 'what_analyzed', 'findings', 'breaks_propagation', 'confidence'],
                'additionalProperties': False
            },
            'description': 'Checks for each transition rule'
        }
    }

    # Build properties and required fields
    properties = {'analysis': field_schemas['analysis']}  # analysis is always required
    required = ['analysis']

    for field in expected_fields:
        if field in field_schemas and field != 'analysis':
            properties[field] = field_schemas[field]
            required.append(field)

    return {
        'type': 'object',
        'properties': properties,
        'required': required,
        'additionalProperties': False
    }


def _build_analysis_template(expected_fields, purpose_rules, transition_rules):
    """Build the analysis response template with examples and field descriptions."""
    
    # Build example fields based on expected_fields
    if expected_fields and ('rule_checks' in expected_fields or 'transition_checks' in expected_fields):
        # Determine which type of checks we're dealing with
        if 'rule_checks' in expected_fields:
            # Build rule_checks examples from purpose_rules if provided
            check_examples = []
            if purpose_rules and len(purpose_rules) > 0:
                # Add first rule as example
                first_rule = purpose_rules[0]
                rule_title = first_rule.get('title', first_rule) if isinstance(first_rule, dict) else str(first_rule)
                check_examples.append(f'''                {{
                    "rule_text": "{rule_title}",
                    "what_checked": "[Specific code locations examined for this rule]",
                    "findings": "[Detailed findings with line numbers and code]",
                    "confidence": "[HIGH, MEDIUM, or LOW]"
                }}''')
                
                # Add placeholder for remaining rules
                if len(purpose_rules) > 1:
                    check_examples.append(f"                // ... include ALL {len(purpose_rules)} rules from the checklist")
            else:
                # Generic placeholder if no purpose_rules provided
                check_examples.append('''                {
                    "rule_text": "[Exact rule title from checklist]",
                    "what_checked": "[Specific code locations examined]",
                    "findings": "[Detailed findings with line numbers and code]",
                    "confidence": "[HIGH, MEDIUM, or LOW]"
                }''')
            
            checks_str = ',\n'.join(check_examples)
            checks_field_name = "rule_checks"
            
        elif 'transition_checks' in expected_fields:
            # Build transition_checks examples from transition_rules if provided
            check_examples = []
            if transition_rules and len(transition_rules) > 0:
                # Add first rule as example
                first_rule = transition_rules[0]
                rule_text = first_rule.get('title', first_rule) if isinstance(first_rule, dict) else str(first_rule)[:80] + "..."
                check_examples.append(f'''                {{
                    "rule_text": "{rule_text}",
                    "what_analyzed": "[Specific code locations and propagation paths analyzed]",
                    "findings": "[Detailed findings about the propagation]",
                    "breaks_propagation": [true if this rule breaks the vulnerability propagation, false otherwise],
                    "confidence": "[HIGH, MEDIUM, or LOW]"
                }}''')
                
                # Add placeholder for remaining rules
                if len(transition_rules) > 1:
                    check_examples.append(f"                // ... include ALL {len(transition_rules)} transition rules")
            else:
                # Generic placeholder if no transition_rules provided
                check_examples.append('''                {
                    "rule_text": "[Transition rule description]",
                    "what_analyzed": "[Specific code locations and propagation paths analyzed]",
                    "findings": "[Detailed findings about the propagation]",
                    "breaks_propagation": [true if this rule breaks the vulnerability propagation, false otherwise],
                    "confidence": "[HIGH, MEDIUM, or LOW]"
                }''')
            
            checks_str = ',\n'.join(check_examples)
            checks_field_name = "transition_checks"
        
        # Build the full example JSON structure
        example_fields = []
        # Always include analysis
        example_fields.append('            "analysis": "[Provide comprehensive analysis of the vulnerability]"')
        
        # Add other expected fields in order
        for field in expected_fields:
            if field == 'reachability':
                example_fields.append('            "reachability": "[REACHABLE or UNREACHABLE]"')
            elif field == 'reachability_explanation':
                example_fields.append('            "reachability_explanation": "[Explain why the path is reachable/unreachable with specific code references]"')
            elif field == 'required_conditions':
                example_fields.append('            "required_conditions": ["[Condition 1]", "[Condition 2]", "[etc, or empty array if unconditional]"]')
            elif field == 'reachability_confidence':
                example_fields.append('            "reachability_confidence": "[HIGH, MEDIUM, or LOW]"')
            elif field in ['rule_checks', 'transition_checks']:
                example_fields.append(f'            "{checks_field_name}": [\n{checks_str}\n            ]')
            elif field == 'is_false_positive':
                example_fields.append('            "is_false_positive": [true or false based on overall analysis]')
            elif field == 'false_positive_confidence':
                example_fields.append('            "false_positive_confidence": "[HIGH, MEDIUM, or LOW]"')
            elif field == 'overall_assessment':
                example_fields.append('            "overall_assessment": "[3-5 key points summarizing the analysis]"')
        
        fields_str = ',\n'.join(example_fields)
        example_json = f'''```json
        {{
{fields_str}
        }}
        ```'''
    else:
        # Simple analysis example without checks
        example_json = '''```json
        {
            "analysis": "[Your comprehensive analysis]"
        }
        ```'''
    
    # Build field descriptions
    field_descriptions = ['        - **analysis**: Comprehensive analysis summary (required)']
    
    if expected_fields:
        # Define detailed descriptions for known fields
        field_desc_map = {
            'reachability': '"REACHABLE" or "UNREACHABLE" - whether the call chain can execute in real scenarios',
            'reachability_explanation': 'Detailed explanation with specific code references for the reachability verdict',
            'required_conditions': 'Array of strings listing conditions required for execution (empty array if unconditional)',
            'reachability_confidence': '"HIGH", "MEDIUM", or "LOW" - confidence in the reachability assessment',
            'rule_checks': 'Array of objects, one for EACH rule in the checklist. Each object must contain: rule_text (exact rule title), what_checked, findings, confidence',
            'transition_checks': 'Array of objects checking EACH transition rule. Each object must contain: rule_text (exact rule description), what_analyzed, findings, breaks_propagation (true if this rule breaks the vulnerability propagation), confidence',
            'is_false_positive': 'true if this is NOT a real vulnerability (false positive), false if this IS a real vulnerability (true positive)',
            'false_positive_confidence': '"HIGH", "MEDIUM", or "LOW" - confidence in false positive determination',
            'overall_assessment': 'String summarizing the key findings and evidence (3-5 key points)'
        }
        
        for field in expected_fields:
            desc = field_desc_map.get(field, f'As specified in the prompt above')
            field_descriptions.append(f'        - **{field}**: {desc}')
    
    return {
        'example': example_json,
        'field_descriptions': '\n'.join(field_descriptions)
    }

def _build_xml_tool_descriptions(tools):
    """Build natural language tool descriptions for XML format."""
    descriptions = []
    for tool in tools:
        func = tool['function']
        name = func['name']
        desc = func['description']
        params = func['parameters']['properties']

        param_desc = []
        for param_name, param_info in params.items():
            param_desc.append(f"  - {param_name}: {param_info['description']}")

        # Build example arguments
        example_args = {p: "example_value" for p in params.keys()}
        example_json = json.dumps({"name": name, "arguments": example_args}, indent=0).replace('\n', '')

        tool_text = f"""
**Tool: {name}**
{desc}

Parameters:
{chr(10).join(param_desc)}

Example usage:
<tool_call>
{example_json}
</tool_call>
"""
        descriptions.append(tool_text)

    return "\n".join(descriptions)


def _parse_response(raw_content, debug=False):
    """Parse the response, handling both tool calls and analysis responses."""
    content = raw_content.strip()
    
    if debug:
        logging.debug(Fore.CYAN + "Starting JSON parsing...")
        logging.debug(f"Content length: {len(content)} characters")
    
    # Remove markdown wrappers if present
    if content.startswith('```json') and content.endswith('```'):
        content = '\n'.join(content.split('\n')[1:-1]).strip()
        if debug:
            logging.debug("Removed ```json markdown wrapper")
    elif content.startswith('```') and content.endswith('```'):
        content = '\n'.join(content.split('\n')[1:-1]).strip()
        if debug:
            logging.debug("Removed ``` markdown wrapper")
    
    # Try direct parse first
    try:
        response_obj = json.loads(content)
        
        if debug:
            logging.debug(Fore.GREEN + "Direct JSON parse successful!")
            logging.debug(f"Keys found: {list(response_obj.keys())}")
        
        # Validate it's one of the two expected formats
        if 'needed_functions_not_provided' in response_obj:
            # Tool call response
            if len(response_obj) > 1:
                logging.warning(f"Tool call response has extra fields: {list(response_obj.keys())}")
                # Extract only the tool call field
                response_obj = {'needed_functions_not_provided': response_obj['needed_functions_not_provided']}
                if debug:
                    logging.debug("Cleaned tool call response to only include needed_functions_not_provided")
        else:
            # Analysis response - should have 'analysis' field
            if 'analysis' not in response_obj:
                raise ValueError("Analysis response missing 'analysis' field")
            if debug:
                logging.debug("Valid analysis response detected")
        
        return response_obj
        
    except (json.JSONDecodeError, ValueError) as e:
        if debug:
            logging.debug(f"Direct parse failed: {e}")
        
        # Try to repair JSON using json_repair library
        if JSON_REPAIR_AVAILABLE:
            try:
                if debug:
                    logging.debug(Fore.YELLOW + "Attempting JSON repair...")
                repaired = repair_json(content)
                response_obj = json.loads(repaired)

                if debug:
                    logging.debug(Fore.GREEN + "JSON repair successful!")
                    logging.debug(f"Repaired keys: {list(response_obj.keys())}")

                # Validate format again
                if 'needed_functions_not_provided' in response_obj:
                    if len(response_obj) > 1:
                        response_obj = {'needed_functions_not_provided': response_obj['needed_functions_not_provided']}
                elif 'analysis' not in response_obj:
                    raise ValueError("Repaired JSON still missing 'analysis' field")

                return response_obj

            except Exception as repair_error:
                if debug:
                    logging.debug(f"JSON repair failed: {repair_error}")
        else:
            if debug:
                logging.debug("json_repair not available, skipping repair attempt")
            
            # Last resort: try to extract needed_functions if it looks like a tool call
            if 'needed_functions_not_provided' in content:
                if debug:
                    logging.debug(Fore.YELLOW + "Attempting to extract needed_functions_not_provided using regex...")
                needed_funcs = extract_needed_functions_from_json(content)
                if needed_funcs:
                    if debug:
                        logging.debug(Fore.GREEN + f"Successfully extracted functions: {needed_funcs}")
                    return {'needed_functions_not_provided': list(needed_funcs)}
            
            # Give up and raise the original error
            if debug:
                logging.debug(Fore.RED + "All parsing attempts failed, raising original error" + Fore.RESET)
            raise e


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