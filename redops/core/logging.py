"""Logging configuration for RedOps-AI.

This module sets up structured logging using structlog for better
log analysis and debugging capabilities.
"""

import os
import sys
import logging
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime

import structlog
from structlog.stdlib import LoggerFactory

from .exceptions import ConfigurationError


def setup_logging(
    log_level: str = "INFO",
    log_dir: Optional[str] = None,
    log_format: str = "json",
    enable_console: bool = True,
    enable_file: bool = True
) -> None:
    """Set up structured logging for the application.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_dir: Directory to store log files. If None, uses 'logs' directory
        log_format: Log format ('json' or 'console')
        enable_console: Whether to enable console logging
        enable_file: Whether to enable file logging
        
    Raises:
        ConfigurationError: If logging setup fails
    """
    try:
        # Convert log level string to logging constant
        numeric_level = getattr(logging, log_level.upper(), logging.INFO)
        
        # Create log directory if it doesn't exist
        if enable_file:
            if log_dir is None:
                log_dir = "logs"
            log_path = Path(log_dir)
            log_path.mkdir(parents=True, exist_ok=True)
        
        # Configure structlog
        processors = [
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
        ]
        
        # Add appropriate formatter based on format preference
        if log_format == "json":
            processors.append(structlog.processors.JSONRenderer())
        else:
            processors.append(structlog.dev.ConsoleRenderer(colors=True))
        
        # Configure structlog
        structlog.configure(
            processors=processors,
            wrapper_class=structlog.stdlib.BoundLogger,
            logger_factory=LoggerFactory(),
            cache_logger_on_first_use=True,
        )
        
        # Configure standard library logging
        logging.basicConfig(
            format="%(message)s",
            stream=sys.stdout if enable_console else None,
            level=numeric_level,
        )
        
        # Set up file handler if enabled
        if enable_file and log_dir:
            # Create file handler for general logs
            log_file = log_path / f"redops_{datetime.now().strftime('%Y%m%d')}.log"
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(numeric_level)
            
            # Create formatter for file logs
            if log_format == "json":
                file_formatter = logging.Formatter('%(message)s')
            else:
                file_formatter = logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                )
            file_handler.setFormatter(file_formatter)
            
            # Add handler to root logger
            root_logger = logging.getLogger()
            root_logger.addHandler(file_handler)
            
            # Create separate error log file
            error_log_file = log_path / f"redops_errors_{datetime.now().strftime('%Y%m%d')}.log"
            error_handler = logging.FileHandler(error_log_file)
            error_handler.setLevel(logging.ERROR)
            error_handler.setFormatter(file_formatter)
            root_logger.addHandler(error_handler)
        
        # Suppress noisy third-party loggers
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        logging.getLogger("requests").setLevel(logging.WARNING)
        logging.getLogger("httpx").setLevel(logging.WARNING)
        
    except Exception as e:
        raise ConfigurationError(f"Failed to setup logging: {e}")


def get_logger(name: str) -> structlog.BoundLogger:
    """Get a structured logger instance.
    
    Args:
        name: Logger name (typically __name__)
        
    Returns:
        Structured logger instance
    """
    return structlog.get_logger(name)


class LoggerMixin:
    """Mixin class to add logging capabilities to other classes."""
    
    @property
    def logger(self) -> structlog.BoundLogger:
        """Get logger instance for this class."""
        if not hasattr(self, '_logger'):
            self._logger = get_logger(self.__class__.__name__)
        return self._logger
    
    def log_operation(self, operation: str, **kwargs) -> None:
        """Log an operation with additional context.
        
        Args:
            operation: Name of the operation being performed
            **kwargs: Additional context to include in the log
        """
        self.logger.info("Operation started", operation=operation, **kwargs)
    
    def log_success(self, operation: str, **kwargs) -> None:
        """Log successful completion of an operation.
        
        Args:
            operation: Name of the operation that completed
            **kwargs: Additional context to include in the log
        """
        self.logger.info("Operation completed successfully", operation=operation, **kwargs)
    
    def log_error(self, operation: str, error: Exception, **kwargs) -> None:
        """Log an error that occurred during an operation.
        
        Args:
            operation: Name of the operation that failed
            error: The exception that occurred
            **kwargs: Additional context to include in the log
        """
        self.logger.error(
            "Operation failed",
            operation=operation,
            error=str(error),
            error_type=type(error).__name__,
            **kwargs
        )


class OperationLogger:
    """Context manager for logging operations with timing."""
    
    def __init__(self, logger: structlog.BoundLogger, operation: str, **context):
        """Initialize operation logger.
        
        Args:
            logger: Logger instance to use
            operation: Name of the operation
            **context: Additional context to include in logs
        """
        self.logger = logger
        self.operation = operation
        self.context = context
        self.start_time = None
    
    def __enter__(self):
        """Start the operation logging."""
        self.start_time = datetime.now()
        self.logger.info(
            "Operation started",
            operation=self.operation,
            start_time=self.start_time.isoformat(),
            **self.context
        )
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """End the operation logging."""
        end_time = datetime.now()
        duration = (end_time - self.start_time).total_seconds()
        
        if exc_type is None:
            self.logger.info(
                "Operation completed successfully",
                operation=self.operation,
                duration_seconds=duration,
                end_time=end_time.isoformat(),
                **self.context
            )
        else:
            self.logger.error(
                "Operation failed",
                operation=self.operation,
                duration_seconds=duration,
                end_time=end_time.isoformat(),
                error=str(exc_val),
                error_type=exc_type.__name__,
                **self.context
            )
    
    def log_progress(self, message: str, **kwargs):
        """Log progress during the operation.
        
        Args:
            message: Progress message
            **kwargs: Additional context
        """
        self.logger.info(
            message,
            operation=self.operation,
            **self.context,
            **kwargs
        )


def log_function_call(func):
    """Decorator to automatically log function calls.
    
    Args:
        func: Function to decorate
        
    Returns:
        Decorated function
    """
    def wrapper(*args, **kwargs):
        logger = get_logger(func.__module__)
        
        # Extract 'self' if it's a method
        if args and hasattr(args[0], '__class__'):
            class_name = args[0].__class__.__name__
            func_name = f"{class_name}.{func.__name__}"
        else:
            func_name = func.__name__
        
        with OperationLogger(logger, func_name):
            return func(*args, **kwargs)
    
    return wrapper