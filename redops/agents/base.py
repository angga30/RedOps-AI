"""Base agent class for RedOps-AI multi-agent system.

This module defines the base agent class that all specialized agents
inherit from, providing common functionality and LangGraph integration.
"""

import asyncio
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass, field
from datetime import datetime

from langchain_core.messages import BaseMessage, HumanMessage, AIMessage
from langchain_core.language_models import BaseLanguageModel
from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode
from typing_extensions import Annotated, TypedDict

from ..core.config import Config, get_config
from ..core.logging import LoggerMixin, OperationLogger
from ..core.exceptions import AgentError, ConfigurationError


@dataclass
class AgentResult:
    """Result returned by agent operations."""
    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    messages: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    
    def add_message(self, message: str) -> None:
        """Add an informational message."""
        self.messages.append(message)
    
    def add_error(self, error: str) -> None:
        """Add an error message."""
        self.errors.append(error)
        self.success = False
    
    def merge(self, other: 'AgentResult') -> 'AgentResult':
        """Merge another result into this one."""
        self.data.update(other.data)
        self.messages.extend(other.messages)
        self.errors.extend(other.errors)
        self.metadata.update(other.metadata)
        if not other.success:
            self.success = False
        return self


class AgentState(TypedDict):
    """State structure for LangGraph agents."""
    messages: Annotated[List[BaseMessage], add_messages]
    target: str
    scan_type: str
    options: Dict[str, Any]
    results: Dict[str, Any]
    errors: List[str]
    metadata: Dict[str, Any]


class BaseAgent(ABC, LoggerMixin):
    """Base class for all RedOps-AI agents.
    
    This class provides common functionality for all agents including:
    - LangGraph integration
    - Configuration management
    - Logging and error handling
    - State management
    """
    
    def __init__(self, name: str, config: Optional[Config] = None):
        """Initialize the base agent.
        
        Args:
            name: Name of the agent
            config: Configuration object. If None, uses global config
        """
        self.name = name
        self.config = config or get_config()
        self._llm = None
        self._graph = None
        self._tools = []
        
        # Get agent-specific configuration
        self.agent_config = getattr(self.config, name.lower(), None)
        if not self.agent_config:
            # Use default configuration if specific config not found
            from ..core.config import AgentConfig
            self.agent_config = AgentConfig()
        
        self.logger.info("Agent initialized", agent=self.name)
    
    @property
    def llm(self) -> BaseLanguageModel:
        """Get the language model instance."""
        if self._llm is None:
            self._llm = self._create_llm()
        return self._llm
    
    def _create_llm(self) -> BaseLanguageModel:
        """Create and configure the language model."""
        llm_config = self.config.llm
        
        try:
            if llm_config.provider == "openai":
                return ChatOpenAI(
                    model=llm_config.model,
                    temperature=llm_config.temperature,
                    max_tokens=llm_config.max_tokens,
                    api_key=llm_config.api_key
                )
            elif llm_config.provider == "anthropic":
                return ChatAnthropic(
                    model=llm_config.model,
                    temperature=llm_config.temperature,
                    max_tokens=llm_config.max_tokens,
                    api_key=llm_config.api_key
                )
            else:
                raise ConfigurationError(f"Unsupported LLM provider: {llm_config.provider}")
        
        except Exception as e:
            raise ConfigurationError(f"Failed to create LLM: {e}")
    
    @property
    def graph(self) -> StateGraph:
        """Get the LangGraph state graph."""
        if self._graph is None:
            self._graph = self._create_graph()
        return self._graph
    
    def _create_graph(self) -> StateGraph:
        """Create the LangGraph state graph for this agent."""
        # Create the graph
        workflow = StateGraph(AgentState)
        
        # Add nodes
        workflow.add_node("agent", self._agent_node)
        
        # Add tool node if tools are available
        if self._tools:
            tool_node = ToolNode(self._tools)
            workflow.add_node("tools", tool_node)
            
            # Add conditional edges for tool calling
            workflow.add_conditional_edges(
                "agent",
                self._should_continue,
                {
                    "continue": "tools",
                    "end": END,
                }
            )
            workflow.add_edge("tools", "agent")
        else:
            workflow.add_edge("agent", END)
        
        # Set entry point
        workflow.set_entry_point("agent")
        
        return workflow.compile()
    
    def _agent_node(self, state: AgentState) -> AgentState:
        """Main agent processing node."""
        try:
            # Get the last message or create initial message
            messages = state.get("messages", [])
            if not messages:
                # Create initial message based on task
                initial_message = self._create_initial_message(state)
                messages = [initial_message]
            
            # Process with LLM
            response = self.llm.invoke(messages)
            
            # Update state
            state["messages"] = messages + [response]
            
            # Process the response
            result = self._process_response(response, state)
            
            # Update results
            if "results" not in state:
                state["results"] = {}
            state["results"].update(result.data)
            
            # Update errors
            if "errors" not in state:
                state["errors"] = []
            state["errors"].extend(result.errors)
            
            return state
        
        except Exception as e:
            self.log_error("agent_node", e)
            if "errors" not in state:
                state["errors"] = []
            state["errors"].append(str(e))
            return state
    
    def _should_continue(self, state: AgentState) -> str:
        """Determine if the agent should continue or end."""
        messages = state.get("messages", [])
        if not messages:
            return "end"
        
        last_message = messages[-1]
        
        # Check if the last message has tool calls
        if hasattr(last_message, 'tool_calls') and last_message.tool_calls:
            return "continue"
        
        return "end"
    
    @abstractmethod
    def _create_initial_message(self, state: AgentState) -> BaseMessage:
        """Create the initial message for the agent.
        
        Args:
            state: Current agent state
            
        Returns:
            Initial message to start the conversation
        """
        pass
    
    @abstractmethod
    def _process_response(self, response: BaseMessage, state: AgentState) -> AgentResult:
        """Process the LLM response and extract results.
        
        Args:
            response: Response from the LLM
            state: Current agent state
            
        Returns:
            AgentResult with processed data
        """
        pass
    
    @abstractmethod
    async def execute(self, target: str, scan_type: str = "basic", 
                     options: Optional[Dict[str, Any]] = None) -> AgentResult:
        """Execute the agent's main functionality.
        
        Args:
            target: Target to operate on
            scan_type: Type of scan/operation to perform
            options: Additional options for the operation
            
        Returns:
            AgentResult with operation results
        """
        pass
    
    async def run_graph(self, initial_state: AgentState) -> AgentState:
        """Run the agent's LangGraph workflow.
        
        Args:
            initial_state: Initial state for the workflow
            
        Returns:
            Final state after workflow completion
        """
        try:
            with OperationLogger(self.logger, "run_graph", agent=self.name):
                final_state = await self.graph.ainvoke(initial_state)
                return final_state
        
        except Exception as e:
            self.log_error("run_graph", e, agent=self.name)
            raise AgentError(f"Graph execution failed: {e}", self.name, "run_graph")
    
    def add_tool(self, tool) -> None:
        """Add a tool to the agent's toolkit.
        
        Args:
            tool: Tool to add to the agent
        """
        self._tools.append(tool)
        # Reset graph to rebuild with new tools
        self._graph = None
        self.logger.info("Tool added to agent", agent=self.name, tool=str(tool))
    
    def get_status(self) -> Dict[str, Any]:
        """Get current agent status.
        
        Returns:
            Dictionary with agent status information
        """
        return {
            "name": self.name,
            "enabled": self.agent_config.enabled,
            "tools_count": len(self._tools),
            "llm_provider": self.config.llm.provider,
            "llm_model": self.config.llm.model,
        }
    
    async def health_check(self) -> bool:
        """Perform a health check on the agent.
        
        Returns:
            True if agent is healthy, False otherwise
        """
        try:
            # Test LLM connectivity
            test_message = HumanMessage(content="Health check")
            response = await self.llm.ainvoke([test_message])
            
            if response:
                self.logger.info("Health check passed", agent=self.name)
                return True
            else:
                self.logger.warning("Health check failed - no response", agent=self.name)
                return False
        
        except Exception as e:
            self.log_error("health_check", e, agent=self.name)
            return False
    
    def __str__(self) -> str:
        """String representation of the agent."""
        return f"{self.__class__.__name__}(name='{self.name}')"
    
    def __repr__(self) -> str:
        """Detailed string representation of the agent."""
        return (f"{self.__class__.__name__}(name='{self.name}', "
                f"enabled={self.agent_config.enabled}, tools={len(self._tools)})")