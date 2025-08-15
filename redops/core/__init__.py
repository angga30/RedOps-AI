"""Core utilities and shared components for RedOps-AI.

This package contains configuration management, logging, validation,
and other shared utilities used across the application.
"""

from .config import Config, load_config
from .logging import setup_logging, get_logger
from .validation import validate_target, TargetType
from .exceptions import RedOpsError, ValidationError, AgentError

__all__ = [
    "Config",
    "load_config",
    "setup_logging",
    "get_logger",
    "validate_target",
    "TargetType",
    "RedOpsError",
    "ValidationError",
    "AgentError"
]