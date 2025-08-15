"""Tools module for external tool integrations.

This module provides interfaces and utilities for integrating with external
security tools like Nmap, Nikto, SQLMap, etc.
"""

import subprocess
import json
import shlex
from typing import Dict, List, Any, Optional, Union
from pathlib import Path
from dataclasses import dataclass
import tempfile
import os


@dataclass
class ToolResult:
    """Result from executing an external tool."""
    tool_name: str
    command: str
    exit_code: int
    stdout: str
    stderr: str
    success: bool
    execution_time: float
    metadata: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "tool_name": self.tool_name,
            "command": self.command,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "success": self.success,
            "execution_time": self.execution_time,
            "metadata": self.metadata
        }


class ToolExecutor:
    """Base class for executing external tools."""
    
    def __init__(self, timeout: int = 300):
        """Initialize tool executor.
        
        Args:
            timeout: Command timeout in seconds
        """
        self.timeout = timeout
        self.temp_dir = Path(tempfile.gettempdir()) / "redops_tools"
        self.temp_dir.mkdir(exist_ok=True)
    
    def execute_command(self, command: Union[str, List[str]], 
                       cwd: Optional[str] = None,
                       env: Optional[Dict[str, str]] = None) -> ToolResult:
        """Execute a command and return results.
        
        Args:
            command: Command to execute (string or list)
            cwd: Working directory
            env: Environment variables
            
        Returns:
            ToolResult with execution details
        """
        import time
        
        start_time = time.time()
        
        # Convert string command to list if needed
        if isinstance(command, str):
            cmd_list = shlex.split(command)
            cmd_str = command
        else:
            cmd_list = command
            cmd_str = " ".join(shlex.quote(arg) for arg in command)
        
        try:
            # Execute command
            result = subprocess.run(
                cmd_list,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                cwd=cwd,
                env=env
            )
            
            execution_time = time.time() - start_time
            
            return ToolResult(
                tool_name=cmd_list[0] if cmd_list else "unknown",
                command=cmd_str,
                exit_code=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
                success=result.returncode == 0,
                execution_time=execution_time,
                metadata={}
            )
            
        except subprocess.TimeoutExpired:
            execution_time = time.time() - start_time
            return ToolResult(
                tool_name=cmd_list[0] if cmd_list else "unknown",
                command=cmd_str,
                exit_code=-1,
                stdout="",
                stderr=f"Command timed out after {self.timeout} seconds",
                success=False,
                execution_time=execution_time,
                metadata={"timeout": True}
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            return ToolResult(
                tool_name=cmd_list[0] if cmd_list else "unknown",
                command=cmd_str,
                exit_code=-1,
                stdout="",
                stderr=str(e),
                success=False,
                execution_time=execution_time,
                metadata={"error": str(e)}
            )
    
    def check_tool_availability(self, tool_name: str) -> bool:
        """Check if a tool is available in the system.
        
        Args:
            tool_name: Name of the tool to check
            
        Returns:
            True if tool is available, False otherwise
        """
        try:
            result = subprocess.run(
                ["which", tool_name],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except:
            return False
    
    def get_tool_version(self, tool_name: str, version_flag: str = "--version") -> Optional[str]:
        """Get version of a tool.
        
        Args:
            tool_name: Name of the tool
            version_flag: Flag to get version (default: --version)
            
        Returns:
            Version string or None if not available
        """
        try:
            result = subprocess.run(
                [tool_name, version_flag],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                return result.stdout.strip()
            return None
        except:
            return None


class NmapTool(ToolExecutor):
    """Nmap tool integration."""
    
    def __init__(self, timeout: int = 600):
        """Initialize Nmap tool.
        
        Args:
            timeout: Scan timeout in seconds
        """
        super().__init__(timeout)
        self.tool_name = "nmap"
    
    def is_available(self) -> bool:
        """Check if Nmap is available."""
        return self.check_tool_availability("nmap")
    
    def basic_scan(self, target: str, ports: Optional[str] = None) -> ToolResult:
        """Perform basic Nmap scan.
        
        Args:
            target: Target to scan
            ports: Port specification (e.g., "80,443,1-1000")
            
        Returns:
            ToolResult with scan results
        """
        cmd = ["nmap", "-sS", "-O", "-sV", "-sC"]
        
        if ports:
            cmd.extend(["-p", ports])
        
        cmd.append(target)
        
        result = self.execute_command(cmd)
        result.metadata["scan_type"] = "basic"
        result.metadata["target"] = target
        result.metadata["ports"] = ports
        
        return result
    
    def stealth_scan(self, target: str, ports: Optional[str] = None) -> ToolResult:
        """Perform stealth Nmap scan.
        
        Args:
            target: Target to scan
            ports: Port specification
            
        Returns:
            ToolResult with scan results
        """
        cmd = ["nmap", "-sS", "-T2", "-f"]
        
        if ports:
            cmd.extend(["-p", ports])
        
        cmd.append(target)
        
        result = self.execute_command(cmd)
        result.metadata["scan_type"] = "stealth"
        result.metadata["target"] = target
        result.metadata["ports"] = ports
        
        return result
    
    def comprehensive_scan(self, target: str) -> ToolResult:
        """Perform comprehensive Nmap scan.
        
        Args:
            target: Target to scan
            
        Returns:
            ToolResult with scan results
        """
        cmd = [
            "nmap", "-sS", "-sU", "-O", "-sV", "-sC",
            "--script", "vuln", "-p-", target
        ]
        
        result = self.execute_command(cmd)
        result.metadata["scan_type"] = "comprehensive"
        result.metadata["target"] = target
        
        return result
    
    def parse_nmap_output(self, nmap_output: str) -> Dict[str, Any]:
        """Parse Nmap output into structured data.
        
        Args:
            nmap_output: Raw Nmap output
            
        Returns:
            Parsed scan results
        """
        parsed = {
            "hosts": [],
            "services": [],
            "ports": [],
            "os_info": {},
            "scripts": []
        }
        
        lines = nmap_output.split('\n')
        current_host = None
        
        for line in lines:
            line = line.strip()
            
            # Parse host information
            if "Nmap scan report for" in line:
                host_info = line.replace("Nmap scan report for ", "")
                current_host = {
                    "host": host_info,
                    "state": "up",
                    "ports": []
                }
                parsed["hosts"].append(current_host)
            
            # Parse port information
            elif "/tcp" in line or "/udp" in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_info = {
                        "port": parts[0],
                        "state": parts[1],
                        "service": parts[2] if len(parts) > 2 else "unknown"
                    }
                    
                    if len(parts) > 3:
                        port_info["version"] = " ".join(parts[3:])
                    
                    parsed["ports"].append(port_info)
                    parsed["services"].append(port_info)
                    
                    if current_host:
                        current_host["ports"].append(port_info)
            
            # Parse OS information
            elif "OS details:" in line:
                parsed["os_info"]["details"] = line.replace("OS details: ", "")
            
            # Parse script results
            elif line.startswith("|"):
                parsed["scripts"].append(line)
        
        return parsed


class ToolManager:
    """Manager for all external tools."""
    
    def __init__(self):
        """Initialize tool manager."""
        self.tools = {
            "nmap": NmapTool()
        }
        self.available_tools = {}
        self._check_tool_availability()
    
    def _check_tool_availability(self) -> None:
        """Check availability of all tools."""
        for name, tool in self.tools.items():
            self.available_tools[name] = tool.is_available()
    
    def get_tool(self, tool_name: str) -> Optional[ToolExecutor]:
        """Get a tool by name.
        
        Args:
            tool_name: Name of the tool
            
        Returns:
            Tool instance or None if not available
        """
        if tool_name in self.tools and self.available_tools.get(tool_name, False):
            return self.tools[tool_name]
        return None
    
    def is_tool_available(self, tool_name: str) -> bool:
        """Check if a tool is available.
        
        Args:
            tool_name: Name of the tool
            
        Returns:
            True if available, False otherwise
        """
        return self.available_tools.get(tool_name, False)
    
    def get_available_tools(self) -> List[str]:
        """Get list of available tools.
        
        Returns:
            List of available tool names
        """
        return [name for name, available in self.available_tools.items() if available]
    
    def get_tool_info(self) -> Dict[str, Any]:
        """Get information about all tools.
        
        Returns:
            Dictionary with tool information
        """
        info = {}
        
        for name, tool in self.tools.items():
            info[name] = {
                "available": self.available_tools.get(name, False),
                "version": tool.get_tool_version(name) if self.available_tools.get(name, False) else None,
                "type": tool.__class__.__name__
            }
        
        return info


# Global tool manager instance
tool_manager = ToolManager()


# Convenience functions
def get_nmap_tool() -> Optional[NmapTool]:
    """Get Nmap tool instance.
    
    Returns:
        NmapTool instance or None if not available
    """
    return tool_manager.get_tool("nmap")


def is_nmap_available() -> bool:
    """Check if Nmap is available.
    
    Returns:
        True if Nmap is available, False otherwise
    """
    return tool_manager.is_tool_available("nmap")


def get_available_tools() -> List[str]:
    """Get list of available tools.
    
    Returns:
        List of available tool names
    """
    return tool_manager.get_available_tools()


def get_tool_info() -> Dict[str, Any]:
    """Get information about all tools.
    
    Returns:
        Dictionary with tool information
    """
    return tool_manager.get_tool_info()