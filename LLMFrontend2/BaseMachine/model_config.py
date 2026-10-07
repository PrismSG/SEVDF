"""
Model configuration utilities for SEVDF.
Provides centralized model name management through environment variables.
"""
import os


def get_model_name(default_model='qwen3-next-80b'):
    """
    Get the model name from environment variable or use default.

    Environment variable: VK_MODEL_NAME

    Args:
        default_model: Default model name if environment variable not set.
                      Defaults to 'gpt-oss-120b'.

    Returns:
        str: Model name to use
    """
    return os.getenv('VK_MODEL_NAME', default_model)