"""Configuration management for RedOps-AI.

Simplified version without external dependencies for testing.
"""

import os
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from pathlib import Path


@dataclass
class ApplicationConfig:
    """Application-level configuration."""
    name: str = "RedOps-AI"
    version: str = "0.1.0"
    description: str = "AI-Powered Red Team Operations Platform"
    debug: bool = False


@dataclass
class AgentConfig:
    """Agent configuration."""
    name: str
    description: str
    enabled: bool = True
    max_retries: int = 3
    timeout: int = 300
    tools: List[str] = field(default_factory=list)


@dataclass
class LLMConfig:
    """LLM configuration."""
    provider: str = "openai"
    model: str = "gpt-4"
    temperature: float = 0.1
    max_tokens: int = 2000
    api_key: Optional[str] = None


@dataclass
class ToolConfig:
    """Tool configuration."""
    name: str
    enabled: bool = True
    path: Optional[str] = None
    options: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SecurityConfig:
    """Security configuration."""
    rate_limit: int = 10
    max_concurrent_scans: int = 5
    allowed_networks: List[str] = field(default_factory=list)
    blocked_networks: List[str] = field(default_factory=list)
    require_confirmation: bool = True


@dataclass
class OutputConfig:
    """Output configuration."""
    format: str = "json"
    directory: str = "./output"
    timestamp: bool = True
    compress: bool = False


@dataclass
class Config:
    """Main configuration class."""
    application: ApplicationConfig = field(default_factory=ApplicationConfig)
    agents: Dict[str, AgentConfig] = field(default_factory=dict)
    llm: LLMConfig = field(default_factory=LLMConfig)
    tools: Dict[str, ToolConfig] = field(default_factory=dict)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    output: OutputConfig = field(default_factory=OutputConfig)


def load_config(config_path: str = "config.yaml") -> Config:
    """Load configuration from file or environment variables.
    
    Simplified version that creates default config for testing.
    """
    config = Config()
    
    # Set up default agents
    config.agents = {
        "coordinator": AgentConfig(
            name="coordinator",
            description="Coordinates multi-agent workflows",
            tools=["nmap", "reporting"]
        ),
        "reconnaissance": AgentConfig(
            name="reconnaissance",
            description="Network reconnaissance and scanning",
            tools=["nmap"]
        )
    }
    
    # Set up default tools
    config.tools = {
        "nmap": ToolConfig(
            name="nmap",
            path="/usr/bin/nmap"
        )
    }
    
    # Override with environment variables
    if "OPENAI_API_KEY" in os.environ:
        config.llm.api_key = os.environ["OPENAI_API_KEY"]
    
    if "REDOPS_DEBUG" in os.environ:
        config.application.debug = os.environ["REDOPS_DEBUG"].lower() == "true"
    
    return config


def get_config() -> Config:
    """Get the global configuration instance."""
    return load_config()