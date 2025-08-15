"""Input validation utilities for RedOps-AI.

This module provides validation functions for various types of input
including network targets, configurations, and user data.
"""

import re
import ipaddress
from enum import Enum
from typing import List, Union, Optional, Tuple
from urllib.parse import urlparse

from .exceptions import ValidationError


class TargetType(Enum):
    """Enumeration of supported target types."""
    IP = "ip"
    DOMAIN = "domain"
    CIDR = "cidr"
    URL = "url"
    HOSTNAME = "hostname"


class NetworkValidator:
    """Validator for network-related inputs."""
    
    # Private IP address ranges (RFC 1918)
    PRIVATE_RANGES = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
        ipaddress.ip_network('127.0.0.0/8'),  # Loopback
        ipaddress.ip_network('169.254.0.0/16'),  # Link-local
    ]
    
    # Reserved/special use ranges
    RESERVED_RANGES = [
        ipaddress.ip_network('0.0.0.0/8'),
        ipaddress.ip_network('224.0.0.0/4'),  # Multicast
        ipaddress.ip_network('240.0.0.0/4'),  # Reserved
    ]
    
    @staticmethod
    def is_valid_ip(ip_str: str) -> bool:
        """Check if string is a valid IP address.
        
        Args:
            ip_str: String to validate as IP address
            
        Returns:
            True if valid IP address, False otherwise
        """
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def is_valid_cidr(cidr_str: str) -> bool:
        """Check if string is a valid CIDR notation.
        
        Args:
            cidr_str: String to validate as CIDR
            
        Returns:
            True if valid CIDR, False otherwise
        """
        try:
            ipaddress.ip_network(cidr_str, strict=False)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def is_valid_domain(domain_str: str) -> bool:
        """Check if string is a valid domain name.
        
        Args:
            domain_str: String to validate as domain
            
        Returns:
            True if valid domain, False otherwise
        """
        if not domain_str or len(domain_str) > 253:
            return False
        
        # Domain name regex pattern
        pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)' \
                 r'+[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        
        return bool(re.match(pattern, domain_str))
    
    @staticmethod
    def is_valid_hostname(hostname_str: str) -> bool:
        """Check if string is a valid hostname.
        
        Args:
            hostname_str: String to validate as hostname
            
        Returns:
            True if valid hostname, False otherwise
        """
        if not hostname_str or len(hostname_str) > 253:
            return False
        
        # Allow single labels (no dots) for hostnames
        if '.' not in hostname_str:
            # Single label hostname
            pattern = r'^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
            return bool(re.match(pattern, hostname_str))
        
        # Multi-label hostname (same as domain)
        return NetworkValidator.is_valid_domain(hostname_str)
    
    @staticmethod
    def is_valid_url(url_str: str) -> bool:
        """Check if string is a valid URL.
        
        Args:
            url_str: String to validate as URL
            
        Returns:
            True if valid URL, False otherwise
        """
        try:
            result = urlparse(url_str)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
    
    @classmethod
    def is_private_ip(cls, ip_str: str) -> bool:
        """Check if IP address is in private range.
        
        Args:
            ip_str: IP address string
            
        Returns:
            True if IP is private, False otherwise
        """
        try:
            ip = ipaddress.ip_address(ip_str)
            return any(ip in network for network in cls.PRIVATE_RANGES)
        except ValueError:
            return False
    
    @classmethod
    def is_reserved_ip(cls, ip_str: str) -> bool:
        """Check if IP address is in reserved range.
        
        Args:
            ip_str: IP address string
            
        Returns:
            True if IP is reserved, False otherwise
        """
        try:
            ip = ipaddress.ip_address(ip_str)
            return any(ip in network for network in cls.RESERVED_RANGES)
        except ValueError:
            return False


def validate_target(target: str, allowed_types: Optional[List[TargetType]] = None) -> Tuple[str, TargetType]:
    """Validate and classify a target string.
    
    Args:
        target: Target string to validate
        allowed_types: List of allowed target types. If None, all types are allowed
        
    Returns:
        Tuple of (normalized_target, target_type)
        
    Raises:
        ValidationError: If target is invalid or not in allowed types
    """
    if not target or not isinstance(target, str):
        raise ValidationError("Target must be a non-empty string", field="target", value=target)
    
    target = target.strip()
    
    # Determine target type
    target_type = None
    normalized_target = target
    
    # Check if it's an IP address
    if NetworkValidator.is_valid_ip(target):
        target_type = TargetType.IP
    
    # Check if it's a CIDR range
    elif NetworkValidator.is_valid_cidr(target):
        target_type = TargetType.CIDR
        # Normalize CIDR (ensure proper format)
        try:
            network = ipaddress.ip_network(target, strict=False)
            normalized_target = str(network)
        except ValueError:
            pass
    
    # Check if it's a URL
    elif NetworkValidator.is_valid_url(target):
        target_type = TargetType.URL
        # Extract hostname from URL for scanning
        parsed = urlparse(target)
        normalized_target = parsed.netloc
    
    # Check if it's a domain
    elif NetworkValidator.is_valid_domain(target):
        target_type = TargetType.DOMAIN
    
    # Check if it's a hostname
    elif NetworkValidator.is_valid_hostname(target):
        target_type = TargetType.HOSTNAME
    
    else:
        raise ValidationError(
            f"Invalid target format: {target}. Must be IP, CIDR, domain, hostname, or URL",
            field="target",
            value=target
        )
    
    # Check if target type is allowed
    if allowed_types and target_type not in allowed_types:
        allowed_str = ", ".join([t.value for t in allowed_types])
        raise ValidationError(
            f"Target type '{target_type.value}' not allowed. Allowed types: {allowed_str}",
            field="target_type",
            value=target_type.value
        )
    
    return normalized_target, target_type


def validate_targets(targets: List[str], allowed_types: Optional[List[TargetType]] = None) -> List[Tuple[str, TargetType]]:
    """Validate a list of targets.
    
    Args:
        targets: List of target strings to validate
        allowed_types: List of allowed target types
        
    Returns:
        List of tuples (normalized_target, target_type)
        
    Raises:
        ValidationError: If any target is invalid
    """
    if not targets:
        raise ValidationError("At least one target must be provided", field="targets")
    
    if not isinstance(targets, list):
        raise ValidationError("Targets must be provided as a list", field="targets")
    
    validated_targets = []
    for i, target in enumerate(targets):
        try:
            validated_target = validate_target(target, allowed_types)
            validated_targets.append(validated_target)
        except ValidationError as e:
            # Add index information to the error
            raise ValidationError(
                f"Invalid target at index {i}: {e.message}",
                field=f"targets[{i}]",
                value=target
            )
    
    return validated_targets


def validate_port_range(port_range: str) -> List[int]:
    """Validate and parse port range specification.
    
    Args:
        port_range: Port range string (e.g., "80", "80-443", "80,443,8080")
        
    Returns:
        List of valid port numbers
        
    Raises:
        ValidationError: If port range is invalid
    """
    if not port_range:
        raise ValidationError("Port range cannot be empty", field="port_range")
    
    ports = set()
    
    try:
        # Split by commas for multiple ranges/ports
        for part in port_range.split(','):
            part = part.strip()
            
            if '-' in part:
                # Handle range (e.g., "80-443")
                start_str, end_str = part.split('-', 1)
                start_port = int(start_str.strip())
                end_port = int(end_str.strip())
                
                if start_port > end_port:
                    raise ValidationError(
                        f"Invalid port range: {part}. Start port must be <= end port",
                        field="port_range",
                        value=part
                    )
                
                for port in range(start_port, end_port + 1):
                    if not (1 <= port <= 65535):
                        raise ValidationError(
                            f"Port {port} out of valid range (1-65535)",
                            field="port_range",
                            value=port
                        )
                    ports.add(port)
            else:
                # Handle single port
                port = int(part)
                if not (1 <= port <= 65535):
                    raise ValidationError(
                        f"Port {port} out of valid range (1-65535)",
                        field="port_range",
                        value=port
                    )
                ports.add(port)
    
    except ValueError as e:
        raise ValidationError(
            f"Invalid port range format: {port_range}",
            field="port_range",
            value=port_range
        )
    
    return sorted(list(ports))


def validate_scan_options(options: dict) -> dict:
    """Validate scan options dictionary.
    
    Args:
        options: Dictionary of scan options
        
    Returns:
        Validated and normalized options dictionary
        
    Raises:
        ValidationError: If options are invalid
    """
    if not isinstance(options, dict):
        raise ValidationError("Scan options must be a dictionary", field="options")
    
    validated_options = {}
    
    # Validate timeout
    if 'timeout' in options:
        timeout = options['timeout']
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValidationError(
                "Timeout must be a positive number",
                field="timeout",
                value=timeout
            )
        validated_options['timeout'] = float(timeout)
    
    # Validate max_retries
    if 'max_retries' in options:
        retries = options['max_retries']
        if not isinstance(retries, int) or retries < 0:
            raise ValidationError(
                "Max retries must be a non-negative integer",
                field="max_retries",
                value=retries
            )
        validated_options['max_retries'] = retries
    
    # Validate ports
    if 'ports' in options:
        ports = options['ports']
        if isinstance(ports, str):
            validated_options['ports'] = validate_port_range(ports)
        elif isinstance(ports, list):
            # Validate each port in the list
            validated_ports = []
            for port in ports:
                if not isinstance(port, int) or not (1 <= port <= 65535):
                    raise ValidationError(
                        f"Invalid port: {port}. Must be integer between 1-65535",
                        field="ports",
                        value=port
                    )
                validated_ports.append(port)
            validated_options['ports'] = validated_ports
        else:
            raise ValidationError(
                "Ports must be a string range or list of integers",
                field="ports",
                value=ports
            )
    
    # Copy other options as-is (they will be validated by specific tools)
    for key, value in options.items():
        if key not in validated_options:
            validated_options[key] = value
    
    return validated_options