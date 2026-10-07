"""
Helper functions for LLM interactions
"""

import json
import logging
import time
from colorama import Fore
from .token_tracker import get_token_tracker


def validate_xml_tool_calls(content, debug=False):
    """
    Validate and parse XML-formatted tool calls from LLM response.

    This is for fallback mode where models don't support OpenAI native tools API.
    Parses <tool_call>...</tool_call> tags and validates their structure.

    :param content: Raw LLM response content containing <tool_call> tags
    :param debug: Whether to output debug information
    :return: List of tool call dicts [{"name": "...", "arguments": {...}}, ...] or None
    """
    import re

    # Find all <tool_call>...</tool_call> blocks
    pattern = r'<tool_call>\s*(\{.*?\})\s*</tool_call>'
    matches = re.findall(pattern, content, re.DOTALL)

    if not matches:
        return None

    tool_calls = []
    for match in matches:
        try:
            call = json.loads(match)
            if 'name' in call and 'arguments' in call:
                tool_calls.append(call)
            else:
                # Detect common mistake: putting analysis JSON in tool_call tags
                if 'analysis' in call or 'reachability' in call:
                    logging.warning(f"[validate_xml_tool_calls] ✗ WRONG FORMAT: Found analysis JSON inside <tool_call> tags!")
                    logging.warning(f"[validate_xml_tool_calls] Hint: Analysis JSON should NOT be wrapped in <tool_call> tags")
                    if debug:
                        logging.debug(f"[validate_xml_tool_calls] Content preview: {match[:150]}")
                else:
                    logging.warning(f"[validate_xml_tool_calls] ✗ Tool call missing 'name' or 'arguments': {match[:100]}")
        except json.JSONDecodeError as e:
            logging.warning(f"[validate_xml_tool_calls] ✗ Failed to parse tool_call JSON: {str(e)}")
            continue

    return tool_calls if tool_calls else None


def validate_tool_calls(tool_calls, debug=False):
    """
    Validate and fix malformed tool_calls from OpenAI native API responses.

    Issues fixed:
    1. Split tool_calls: Some API providers split a single tool_call into multiple fragments
    2. Malformed arguments: Missing opening/closing braces in arguments JSON

    :param tool_calls: List of tool_call objects from API response
    :param debug: Whether to output debug information
    :return: List of validated/fixed tool_call objects
    """
    if not tool_calls:
        return []

    fixed_tool_calls = []
    i = 0

    # Step 1: Merge split tool_calls
    # Example: Some API providers split a single tool_call into multiple fragments:
    #   [ToolCall(id='abc', name='get_func', args='{"func'),
    #    ToolCall(id=None, name=None, args='_name": "foo"}')]
    #   → [ToolCall(id='abc', name='get_func', args='{"func_name": "foo"}')]
    while i < len(tool_calls):
        current = tool_calls[i]

        # Check if current tool_call is valid (has id and name)
        if current.id is None or current.function.name is None:
            # This is a fragment, try to merge with previous
            if fixed_tool_calls:
                if debug:
                    logging.debug(f'[validate_tool_calls] Detected split tool_call, merging fragment: {repr(current.function.arguments[:50])}...')
                # Merge arguments with the last valid tool_call
                fixed_tool_calls[-1].function.arguments += current.function.arguments
            else:
                logging.error(f'[validate_tool_calls] Invalid tool_call at start: {current}')
            i += 1
            continue

        # Check if next tool_call is a fragment (id=None)
        if i + 1 < len(tool_calls):
            next_call = tool_calls[i + 1]
            if next_call.id is None or next_call.function.name is None:
                # Next is a fragment, merge it
                if debug:
                    logging.debug(f'[validate_tool_calls] Detected split tool_call for {current.function.name}, merging with next fragment')
                current.function.arguments += next_call.function.arguments
                i += 2  # Skip the fragment
                fixed_tool_calls.append(current)
                continue

        # Normal valid tool_call
        fixed_tool_calls.append(current)
        i += 1

    if len(fixed_tool_calls) != len(tool_calls):
        logging.info(f'[validate_tool_calls] Fixed split tool_calls: {len(tool_calls)} -> {len(fixed_tool_calls)}')

    # Step 2: Fix malformed arguments in each tool_call
    for tool_call in fixed_tool_calls:
        original_args = tool_call.function.arguments
        fixed_args = original_args.strip()

        # Corner case 1: Missing opening brace and/or opening quote
        # Example 1: ' "function_name": "FOPEN"\n}' → '{"function_name": "FOPEN"\n}'
        # Example 2: 'function_name": "goodG2B"}' → '{"function_name": "goodG2B"}'
        if not fixed_args.startswith('{'):
            # Check if it looks like JSON content (contains ": or }")
            if '":' in fixed_args or fixed_args.endswith('}'):
                if debug:
                    logging.debug(f'[validate_tool_calls] Fixing missing opening brace for {tool_call.function.name}')
                # Also add opening quote if key doesn't start with quote
                if not fixed_args.startswith('"'):
                    fixed_args = '{"' + fixed_args
                else:
                    fixed_args = '{' + fixed_args

        # Corner case 2: Missing closing brace
        # Example: '{"function_name": "FOPEN"' → '{"function_name": "FOPEN"}'
        if not fixed_args.endswith('}') and '"' in fixed_args:
            if debug:
                logging.debug(f'[validate_tool_calls] Fixing missing closing brace for {tool_call.function.name}')
            fixed_args = fixed_args + '}'

        # Update arguments if changed
        if fixed_args != original_args:
            logging.warning(f'[validate_tool_calls] Fixed malformed arguments for {tool_call.function.name}')
            logging.warning(f'  Original: {repr(original_args)}')
            logging.warning(f'  Fixed: {repr(fixed_args)}')
            tool_call.function.arguments = fixed_args

    return fixed_tool_calls


def validate_json_schema(content, schema=None, debug=False, retry_count=None):
    """
    Validate JSON content against optional schema.

    This is an independent validation function that can be used anywhere in the codebase.
    It validates JSON format, structure, and optionally checks against a schema.

    :param content: Raw response content (string)
    :param schema: JSON schema (optional, if None only validates format)
    :param debug: Whether to output debug information
    :param retry_count: Optional retry count for success logging (0 = first attempt, None = no logging)
    :return: (success: bool, parsed_result: dict/None, error_msg: str)
    """
    # 1. Check for empty/null content
    if content is None or (isinstance(content, str) and content.strip() == ""):
        error_msg = "Empty response"
        if debug:
            logging.debug(f"[validate_json_schema] {error_msg}")
        return (False, None, error_msg)

    # 2. Extract JSON from response content
    # LLMs sometimes add extra text, markdown wrappers, or duplicate characters
    content = content.strip()

    # Step 2.1: Remove markdown code blocks
    if content.startswith('```json'):
        lines = content.split('\n')
        for i in range(len(lines) - 1, 0, -1):
            if lines[i].strip() == '```':
                content = '\n'.join(lines[1:i]).strip()
                break
        else:
            # No closing found, just remove first line
            content = '\n'.join(lines[1:]).strip()
        if debug:
            logging.debug("[validate_json_schema] Removed ```json markdown wrapper")
    elif content.startswith('```'):
        lines = content.split('\n')
        for i in range(len(lines) - 1, 0, -1):
            if lines[i].strip() == '```':
                content = '\n'.join(lines[1:i]).strip()
                break
        else:
            content = '\n'.join(lines[1:]).strip()
        if debug:
            logging.debug("[validate_json_schema] Removed ``` markdown wrapper")

    # Step 2.2: Find JSON start position - skip any prefix text
    # Example: ". \n\n{ ..." -> skip the ". \n\n" part
    first_brace = content.find('{')
    first_bracket = content.find('[')

    json_start = -1
    if first_brace >= 0 and first_bracket >= 0:
        json_start = min(first_brace, first_bracket)
    elif first_brace >= 0:
        json_start = first_brace
    elif first_bracket >= 0:
        json_start = first_bracket

    if json_start > 0:
        # Found JSON start after some text
        skipped_text = content[:json_start]
        content = content[json_start:]
        if debug:
            logging.debug(f"[validate_json_schema] Skipped {json_start} characters before JSON: {repr(skipped_text[:50])}")

    # Step 2.3: Fix duplicate opening characters (common LLM mistake)
    # Handles consecutive and whitespace-separated duplicates
    # Examples: "{{ ...", "{\n{ ...", "{\n   { ...", "[[ ...", "[\n[ ..."

    # For braces: check for duplicate { with optional whitespace between
    if content.startswith('{'):
        # Find the next non-whitespace character
        next_pos = 1
        while next_pos < len(content) and content[next_pos] in ' \n\t':
            next_pos += 1

        # If next non-whitespace is also {, remove everything up to it
        if next_pos < len(content) and content[next_pos] == '{':
            content = content[next_pos:]  # Remove first { and whitespace
            if debug:
                logging.debug(f"[validate_json_schema] Fixed duplicate opening brace (removed {next_pos} chars)")

    # For brackets: check for duplicate [ with optional whitespace between
    elif content.startswith('['):
        next_pos = 1
        while next_pos < len(content) and content[next_pos] in ' \n\t':
            next_pos += 1

        if next_pos < len(content) and content[next_pos] == '[':
            content = content[next_pos:]  # Remove first [ and whitespace
            if debug:
                logging.debug(f"[validate_json_schema] Fixed duplicate opening bracket (removed {next_pos} chars)")

    # 3. Validate JSON format (parse)
    try:
        parsed = json.loads(content)
        if debug:
            logging.debug("[validate_json_schema] JSON parse successful")
    except json.JSONDecodeError as e:
        error_msg = f"Invalid JSON format: {str(e)}"
        if debug:
            logging.debug(f"[validate_json_schema] {error_msg}")
            logging.debug(f"  Error position: line {e.lineno}, column {e.colno}, char {e.pos}")
            logging.debug(f"  Content preview: {content[:200]}")
        return (False, None, error_msg)

    # 4. Validate JSON structure (non-empty)
    if isinstance(parsed, dict) and len(parsed) == 0:
        error_msg = "Empty JSON object {}"
        if debug:
            logging.debug(f"[validate_json_schema] {error_msg}")
        return (False, None, error_msg)
    elif isinstance(parsed, list) and len(parsed) == 0:
        error_msg = "Empty JSON array []"
        if debug:
            logging.debug(f"[validate_json_schema] {error_msg}")
        return (False, None, error_msg)
    elif parsed is None:
        error_msg = "JSON is null"
        if debug:
            logging.debug(f"[validate_json_schema] {error_msg}")
        return (False, None, error_msg)

    # 5. Validate against schema (if provided)
    if schema and isinstance(parsed, dict):
        # Check required fields
        required_fields = schema.get('required', [])
        missing_fields = [field for field in required_fields if field not in parsed]

        if missing_fields:
            error_msg = f"Missing required fields: {missing_fields}"
            if debug:
                logging.debug(f"[validate_json_schema] {error_msg}")
                logging.debug(f"  Expected: {required_fields}")
                logging.debug(f"  Got keys: {list(parsed.keys())}")
            return (False, None, error_msg)

        # Check for empty string fields
        properties = schema.get('properties', {})
        empty_fields = []
        for field, value in parsed.items():
            if field in properties:
                field_type = properties[field].get('type')
                if field_type == 'string' and isinstance(value, str) and value.strip() == '':
                    empty_fields.append(field)

        if empty_fields:
            error_msg = f"Empty string fields: {empty_fields}"
            if debug:
                logging.debug(f"[validate_json_schema] {error_msg}")
            return (False, None, error_msg)

    # 6. Validation successful
    if debug:
        logging.debug("[validate_json_schema] Validation successful")
        if isinstance(parsed, dict):
            logging.debug(f"  JSON keys: {list(parsed.keys())}")

    # Log validation success if retry_count provided
    if retry_count is not None and schema:  # Only log when schema validation is requested
        if retry_count == 0:
            logging.info(Fore.GREEN + '[validate_json_schema] Validation successful (first attempt)')
        else:
            logging.info(Fore.GREEN + f'[validate_json_schema] Validation successful (after {retry_count} retries)')

    return (True, parsed, "")


def reliable_parse(client, request_params, max_retries=3, debug=False, model_info=None):
    """
    Reliably parse responses with retry mechanism.

    :return: (response, parsed_json) tuple
             - response: The API response object
             - parsed_json: Validated and fixed JSON (dict/list) if response_format provided, else None
    """
    # TEMPORARY: Disable LLM calls for constraint testing
    # To re-enable LLM calls, change DISABLE_LLM to False
    DISABLE_LLM = False  # Set to True to disable LLM calls for testing
    if DISABLE_LLM:
        logging.info("[TEST MODE] LLM calls disabled - returning None instead of API call")
        return (None, None)
    
    from openai import APITimeoutError
    import openai
    from pydantic import BaseModel

    # Inject max_tokens, reasoning, provider from model config into request params
    # so every API call respects the configured limits (e.g. preventing 65536 default).
    if model_info is not None:
        additional = model_info.get('additional_kwargs', {})
        if 'max_tokens' in additional and 'max_tokens' not in request_params:
            request_params['max_tokens'] = additional['max_tokens']
        if 'reasoning' in additional and 'reasoning' not in request_params:
            request_params['reasoning'] = additional['reasoning']
        if 'provider' in additional and 'provider' not in request_params:
            request_params['provider'] = additional['provider']

    parsed_json = None  # Will be set if response_format validation succeeds

    for attempt in range(max_retries):
        try:
            start_time = time.time()
            
            # Check if response_format is a Pydantic BaseModel class
            if 'response_format' in request_params and isinstance(request_params['response_format'], type) and issubclass(request_params['response_format'], BaseModel):
                # Use beta.chat.completions.parse for structured outputs
                pydantic_model = request_params.pop('response_format')
                response = client.beta.chat.completions.parse(
                    **request_params,
                    response_format=pydantic_model
                )
            else:
                # Use regular chat.completions.create
                response = client.chat.completions.create(**request_params)

            # CRITICAL: Validate response before proceeding
            # If API returns None or invalid response without throwing exception,
            # we need to catch it here and trigger retry mechanism
            if response is None:
                raise Exception("API returned None response")
            if not hasattr(response, 'choices'):
                raise Exception(f"API returned response without 'choices' attribute: {type(response)}")
            if not response.choices or len(response.choices) == 0:
                raise Exception("API returned empty choices list")

            elapsed_time = time.time() - start_time
            
            if elapsed_time > 60:  # Log if request took more than 60 seconds
                logging.warning(f"Long request: {elapsed_time:.2f} seconds for model {request_params.get('model', 'unknown')}")
            
            # Track token usage if available
            try:
                if hasattr(response, 'usage') and response.usage:
                    model_name = request_params.get('model', 'unknown')
                    # Skip Azure models
                    if not ('azure' in model_name.lower() or 'gpt4' in model_name.lower()):
                        tracker = get_token_tracker()
                        tracker.add_record(
                            model_name=model_name,
                            prompt_tokens=response.usage.prompt_tokens,
                            completion_tokens=response.usage.completion_tokens,
                            total_tokens=response.usage.total_tokens,
                            additional_info={
                                'elapsed_time': elapsed_time,
                                'attempt': attempt + 1
                            }
                        )

                        if debug:
                            logging.debug(f"Token usage - Model: {model_name}, "
                                        f"Prompt: {response.usage.prompt_tokens}, "
                                        f"Completion: {response.usage.completion_tokens}, "
                                        f"Total: {response.usage.total_tokens}")
            except Exception as e:
                if debug:
                    logging.debug(f"Failed to track token usage: {e}")

            # Validate JSON response if response_format is specified
            # BUT: Only validate if this is NOT a tool_call response
            if 'response_format' in request_params and request_params['response_format'] is not None:
                message = response.choices[0].message if hasattr(response, 'choices') and response.choices else None

                # Check if this is a tool call response
                is_tool_call = hasattr(message, 'tool_calls') and message.tool_calls

                if is_tool_call:
                    # This is a tool call response, skip JSON validation
                    if debug:
                        logging.debug(f"[reliable_parse] Skipping JSON validation - this is a tool_call response")
                else:
                    # This is a content response, validate JSON
                    content = message.content if message else None

                    # Extract schema from response_format
                    schema = None
                    response_format = request_params['response_format']
                    if isinstance(response_format, dict):
                        if response_format.get('type') == 'json_schema' and 'json_schema' in response_format:
                            schema = response_format['json_schema'].get('schema', {})

                    # Call the independent validation function
                    success, parsed, error_msg = validate_json_schema(content, schema, debug)

                    if not success:
                        logging.warning(f"[JSON Validation Failed] Attempt {attempt + 1}/{max_retries}: {error_msg}")

                        # Show content preview for debugging
                        if content:
                            if len(content) <= 500:
                                logging.warning(f"  Full content: {repr(content)}")
                            else:
                                logging.warning(f"  Content preview (first 300 chars): {repr(content[:300])}")
                                logging.warning(f"  Content preview (last 200 chars): {repr(content[-200:])}")
                        else:
                            logging.warning(f"  Response object: {response}")

                        time.sleep(2 * (attempt + 1))
                        continue  # Retry

                    # Validation successful - save the parsed result
                    parsed_json = parsed
                    logging.info(f"[JSON Validation Success] Attempt {attempt + 1}: Valid and complete JSON response")
                    if debug and parsed and isinstance(parsed, dict):
                        logging.debug(f"  JSON keys: {list(parsed.keys())}")
                        logging.debug(f"  JSON preview: {str(parsed)[:200]}...")

            return (response, parsed_json)
        except APITimeoutError as e:
            logging.warning(f"Request timeout on attempt {attempt + 1}: {e}")
            time.sleep(5 * (attempt + 1))
        except Exception as e:
            logging.warning(f"Request failed on attempt {attempt + 1}: {e}")
            time.sleep(2 * (attempt + 1))

            if "rate limit" in str(e).lower():
                logging.warning("Rate limit detected, waiting longer...")
                time.sleep(10 * (attempt + 1))

    raise Exception(f"Failed after {max_retries} attempts")


def safe_format(template, **kwargs):
    """
    Safe string formatting that doesn't fail on extra placeholders
    """
    import re
    
    def replace_placeholder(match):
        key = match.group(1)
        if key in kwargs:
            return str(kwargs[key])
        else:
            return match.group(0)
    
    return re.sub(r'\{(\w+)\}', replace_placeholder, template)


def extract_code_snippets(text):
    """
    Extract code snippets from text
    """
    import re
    
    # Simple pattern to find code between backticks
    code_pattern = r'```[\w]*\n(.*?)```'
    code_snippets = re.findall(code_pattern, text, re.DOTALL)
    
    # Also find inline code
    inline_pattern = r'`([^`]+)`'
    inline_snippets = re.findall(inline_pattern, text)
    
    # Combine all snippets
    all_snippets = code_snippets + inline_snippets
    
    # Remove duplicates while preserving order
    seen = set()
    unique_snippets = []
    for snippet in all_snippets:
        if snippet not in seen:
            seen.add(snippet)
            unique_snippets.append(snippet)
    
    return '\n'.join(unique_snippets)


# Note: parse_and_validate_json_response() and suggest_json_fix() functions
# have been removed as they were not being used. The json_repair and GPT-4
# repair logic can be re-added if needed in the future.