"""Custom exceptions for RedOps-AI.

This module defines custom exception classes used throughout the RedOps-AI
system for better error handling and debugging.
"""

from typing import Optional, Dict, Any


class RedOpsError(Exception):
    """Base exception class for RedOps-AI.
    
    All custom exceptions in RedOps-AI should inherit from this class.
    """
    
    def __init__(self, message: str, error_code: Optional[str] = None, 
                 details: Optional[Dict[str, Any]] = None):
        """Initialize RedOps error.
        
        Args:
            message: Error message
            error_code: Optional error code for categorization
            details: Optional additional error details
        """
        super().__init__(message)
        self.message = message
        self.error_code = error_code or self.__class__.__name__
        self.details = details or {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary.
        
        Returns:
            Dictionary representation of the exception
        """
        return {
            "error_type": self.__class__.__name__,
            "error_code": self.error_code,
            "message": self.message,
            "details": self.details
        }
    
    def __str__(self) -> str:
        """String representation of the exception."""
        if self.details:
            return f"{self.message} (Details: {self.details})"
        return self.message


class ConfigurationError(RedOpsError):
    """Exception raised for configuration-related errors.
    
    This includes missing configuration files, invalid configuration values,
    or configuration parsing errors.
    """
    pass


class ValidationError(RedOpsError):
    """Exception raised for input validation errors.
    
    This includes invalid targets, malformed input data, or constraint violations.
    """
    pass


class NetworkError(RedOpsError):
    """Exception raised for network-related errors.
    
    This includes connection failures, DNS resolution errors, or network timeouts.
    """
    pass


class ToolError(RedOpsError):
    """Exception raised for external tool errors.
    
    This includes tool execution failures, missing tools, or tool output parsing errors.
    """
    
    def __init__(self, message: str, tool_name: Optional[str] = None,
                 command: Optional[str] = None, exit_code: Optional[int] = None,
                 stderr: Optional[str] = None, **kwargs):
        """Initialize tool error.
        
        Args:
            message: Error message
            tool_name: Name of the tool that failed
            command: Command that was executed
            exit_code: Exit code from the tool
            stderr: Standard error output from the tool
            **kwargs: Additional arguments for parent class
        """
        details = kwargs.get('details', {})
        details.update({
            "tool_name": tool_name,
            "command": command,
            "exit_code": exit_code,
            "stderr": stderr
        })
        kwargs['details'] = details
        super().__init__(message, **kwargs)
        self.tool_name = tool_name
        self.command = command
        self.exit_code = exit_code
        self.stderr = stderr


class AgentError(RedOpsError):
    """Exception raised for agent-related errors.
    
    This includes agent initialization failures, workflow errors, or agent communication issues.
    """
    
    def __init__(self, message: str, agent_name: Optional[str] = None,
                 agent_state: Optional[str] = None, **kwargs):
        """Initialize agent error.
        
        Args:
            message: Error message
            agent_name: Name of the agent that failed
            agent_state: Current state of the agent
            **kwargs: Additional arguments for parent class
        """
        details = kwargs.get('details', {})
        details.update({
            "agent_name": agent_name,
            "agent_state": agent_state
        })
        kwargs['details'] = details
        super().__init__(message, **kwargs)
        self.agent_name = agent_name
        self.agent_state = agent_state


class WorkflowError(RedOpsError):
    """Exception raised for workflow execution errors.
    
    This includes workflow state errors, step execution failures, or workflow coordination issues.
    """
    
    def __init__(self, message: str, workflow_step: Optional[str] = None,
                 workflow_state: Optional[Dict[str, Any]] = None, **kwargs):
        """Initialize workflow error.
        
        Args:
            message: Error message
            workflow_step: Current workflow step
            workflow_state: Current workflow state
            **kwargs: Additional arguments for parent class
        """
        details = kwargs.get('details', {})
        details.update({
            "workflow_step": workflow_step,
            "workflow_state": workflow_state
        })
        kwargs['details'] = details
        super().__init__(message, **kwargs)
        self.workflow_step = workflow_step
        self.workflow_state = workflow_state


class ScanError(RedOpsError):
    """Exception raised for scanning-related errors.
    
    This includes scan execution failures, result parsing errors, or scan configuration issues.
    """
    
    def __init__(self, message: str, target: Optional[str] = None,
                 scan_type: Optional[str] = None, **kwargs):
        """Initialize scan error.
        
        Args:
            message: Error message
            target: Target that was being scanned
            scan_type: Type of scan that failed
            **kwargs: Additional arguments for parent class
        """
        details = kwargs.get('details', {})
        details.update({
            "target": target,
            "scan_type": scan_type
        })
        kwargs['details'] = details
        super().__init__(message, **kwargs)
        self.target = target
        self.scan_type = scan_type


class AuthenticationError(RedOpsError):
    """Exception raised for authentication-related errors.
    
    This includes API key validation failures, credential errors, or access denied issues.
    """
    pass


class RateLimitError(RedOpsError):
    """Exception raised when rate limits are exceeded.
    
    This includes API rate limits, scan frequency limits, or resource usage limits.
    """
    
    def __init__(self, message: str, retry_after: Optional[int] = None, **kwargs):
        """Initialize rate limit error.
        
        Args:
            message: Error message
            retry_after: Seconds to wait before retrying
            **kwargs: Additional arguments for parent class
        """
        details = kwargs.get('details', {})
        details.update({"retry_after": retry_after})
        kwargs['details'] = details
        super().__init__(message, **kwargs)
        self.retry_after = retry_after


class TimeoutError(RedOpsError):
    """Exception raised for timeout-related errors.
    
    This includes operation timeouts, network timeouts, or scan timeouts.
    """
    
    def __init__(self, message: str, timeout_duration: Optional[float] = None, **kwargs):
        """Initialize timeout error.
        
        Args:
            message: Error message
            timeout_duration: Duration of the timeout in seconds
            **kwargs: Additional arguments for parent class
        """
        details = kwargs.get('details', {})
        details.update({"timeout_duration": timeout_duration})
        kwargs['details'] = details
        super().__init__(message, **kwargs)
        self.timeout_duration = timeout_duration


class DataError(RedOpsError):
    """Exception raised for data-related errors.
    
    This includes data parsing errors, invalid data formats, or data corruption issues.
    """
    pass


class SecurityError(RedOpsError):
    """Exception raised for security-related errors.
    
    This includes permission errors, security policy violations, or unsafe operations.
    """
    pass


# Exception handling utilities
def handle_exception(func):
    """Decorator to handle exceptions and convert them to RedOps exceptions.
    
    Args:
        func: Function to wrap
        
    Returns:
        Wrapped function
    """
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except RedOpsError:
            # Re-raise RedOps exceptions as-is
            raise
        except Exception as e:
            # Convert other exceptions to RedOps exceptions
            raise RedOpsError(
                f"Unexpected error in {func.__name__}: {str(e)}",
                error_code="UNEXPECTED_ERROR",
                details={"original_exception": str(e), "function": func.__name__}
            ) from e
    return wrapper


def format_exception(exception: Exception) -> Dict[str, Any]:
    """Format an exception for logging or display.
    
    Args:
        exception: Exception to format
        
    Returns:
        Formatted exception data
    """
    if isinstance(exception, RedOpsError):
        return exception.to_dict()
    
    return {
        "error_type": exception.__class__.__name__,
        "error_code": "UNKNOWN_ERROR",
        "message": str(exception),
        "details": {}
    }


def is_retryable_error(exception: Exception) -> bool:
    """Check if an exception represents a retryable error.
    
    Args:
        exception: Exception to check
        
    Returns:
        True if the error is retryable, False otherwise
    """
    retryable_errors = (
        NetworkError,
        TimeoutError,
        RateLimitError
    )
    
    return isinstance(exception, retryable_errors)


def get_retry_delay(exception: Exception) -> Optional[float]:
    """Get the recommended retry delay for an exception.
    
    Args:
        exception: Exception to check
        
    Returns:
        Retry delay in seconds, or None if not applicable
    """
    if isinstance(exception, RateLimitError) and exception.retry_after:
        return float(exception.retry_after)
    
    if isinstance(exception, TimeoutError):
        return 5.0  # Default 5 second delay for timeouts
    
    if isinstance(exception, NetworkError):
        return 2.0  # Default 2 second delay for network errors
    
    return None