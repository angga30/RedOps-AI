"""Nmap integration for network scanning.

Simplified version without LangChain dependencies for testing.
"""

import subprocess
import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Union
from pathlib import Path
import shutil


@dataclass
class NmapResult:
    """Result from an Nmap scan."""
    target: str
    scan_type: str
    command: str
    hosts: List[Dict[str, Any]] = field(default_factory=list)
    scan_stats: Dict[str, Any] = field(default_factory=dict)
    raw_output: str = ""
    xml_output: str = ""
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "target": self.target,
            "scan_type": self.scan_type,
            "command": self.command,
            "hosts": self.hosts,
            "scan_stats": self.scan_stats,
            "raw_output": self.raw_output,
            "xml_output": self.xml_output,
            "error": self.error
        }


class NmapScanner:
    """Nmap scanner wrapper."""
    
    def __init__(self, nmap_path: str = "nmap"):
        """Initialize Nmap scanner.
        
        Args:
            nmap_path: Path to nmap binary
        """
        self.nmap_path = nmap_path
        self._verify_nmap()
    
    def _verify_nmap(self) -> None:
        """Verify that Nmap is available.
        
        Raises:
            FileNotFoundError: If nmap is not found
        """
        if not shutil.which(self.nmap_path):
            raise FileNotFoundError(f"Nmap not found at {self.nmap_path}")
    
    def _build_nmap_args(self, target: str, scan_type: str = "basic", 
                        ports: Optional[str] = None, timing: str = "T3") -> List[str]:
        """Build Nmap command arguments.
        
        Args:
            target: Target to scan
            scan_type: Type of scan (basic, quick, comprehensive, stealth, udp)
            ports: Port specification
            timing: Timing template
            
        Returns:
            List of command arguments
        """
        args = [self.nmap_path]
        
        # Scan type configurations
        scan_configs = {
            "basic": ["-sS", "-sV"],
            "quick": ["-sS", "-F"],
            "comprehensive": ["-sS", "-sV", "-sC", "-O"],
            "stealth": ["-sS", "-f", "-D", "RND:10"],
            "udp": ["-sU", "--top-ports", "100"]
        }
        
        # Add scan type specific arguments
        if scan_type in scan_configs:
            args.extend(scan_configs[scan_type])
        else:
            args.extend(scan_configs["basic"])
        
        # Add timing
        args.append(f"-{timing}")
        
        # Add port specification
        if ports:
            args.extend(["-p", ports])
        
        # Add XML output
        args.extend(["-oX", "-"])
        
        # Add target
        args.append(target)
        
        return args
    
    def _parse_xml_output(self, xml_output: str) -> List[Dict[str, Any]]:
        """Parse Nmap XML output.
        
        Args:
            xml_output: XML output from Nmap
            
        Returns:
            List of host information dictionaries
        """
        hosts = []
        
        try:
            root = ET.fromstring(xml_output)
            
            for host in root.findall('host'):
                host_info = {
                    "state": "unknown",
                    "addresses": [],
                    "hostnames": [],
                    "ports": [],
                    "os": {}
                }
                
                # Get host state
                status = host.find('status')
                if status is not None:
                    host_info["state"] = status.get('state', 'unknown')
                
                # Get addresses
                for address in host.findall('address'):
                    addr_info = {
                        "addr": address.get('addr'),
                        "addrtype": address.get('addrtype')
                    }
                    host_info["addresses"].append(addr_info)
                
                # Get hostnames
                hostnames = host.find('hostnames')
                if hostnames is not None:
                    for hostname in hostnames.findall('hostname'):
                        host_info["hostnames"].append({
                            "name": hostname.get('name'),
                            "type": hostname.get('type')
                        })
                
                # Get ports
                ports = host.find('ports')
                if ports is not None:
                    for port in ports.findall('port'):
                        port_info = {
                            "portid": port.get('portid'),
                            "protocol": port.get('protocol'),
                            "state": "unknown",
                            "service": {}
                        }
                        
                        # Get port state
                        state = port.find('state')
                        if state is not None:
                            port_info["state"] = state.get('state')
                        
                        # Get service info
                        service = port.find('service')
                        if service is not None:
                            port_info["service"] = {
                                "name": service.get('name'),
                                "product": service.get('product'),
                                "version": service.get('version'),
                                "extrainfo": service.get('extrainfo')
                            }
                        
                        host_info["ports"].append(port_info)
                
                # Get OS info
                os_elem = host.find('os')
                if os_elem is not None:
                    osmatch = os_elem.find('osmatch')
                    if osmatch is not None:
                        host_info["os"] = {
                            "name": osmatch.get('name'),
                            "accuracy": osmatch.get('accuracy')
                        }
                
                hosts.append(host_info)
        
        except ET.ParseError as e:
            print(f"Error parsing XML: {e}")
        
        return hosts
    
    def scan(self, target: str, scan_type: str = "basic", 
             ports: Optional[str] = None, timing: str = "T3") -> NmapResult:
        """Perform Nmap scan.
        
        Args:
            target: Target to scan (IP, hostname, or CIDR)
            scan_type: Type of scan to perform
            ports: Port specification (e.g., "80,443", "1-1000")
            timing: Timing template (T0-T5)
            
        Returns:
            NmapResult with scan results
        """
        args = self._build_nmap_args(target, scan_type, ports, timing)
        command = " ".join(args)
        
        result = NmapResult(
            target=target,
            scan_type=scan_type,
            command=command
        )
        
        try:
            # Run Nmap command
            process = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            result.raw_output = process.stderr
            result.xml_output = process.stdout
            
            if process.returncode == 0:
                # Parse XML output
                result.hosts = self._parse_xml_output(result.xml_output)
                result.scan_stats = {
                    "hosts_up": len([h for h in result.hosts if h["state"] == "up"]),
                    "hosts_total": len(result.hosts),
                    "ports_scanned": sum(len(h["ports"]) for h in result.hosts)
                }
            else:
                result.error = f"Nmap failed with return code {process.returncode}: {process.stderr}"
        
        except subprocess.TimeoutExpired:
            result.error = "Nmap scan timed out"
        except Exception as e:
            result.error = f"Nmap scan failed: {str(e)}"
        
        return result
    
    async def scan_async(self, target: str, scan_type: str = "basic", 
                        ports: Optional[str] = None, timing: str = "T3") -> NmapResult:
        """Perform asynchronous Nmap scan.
        
        Args:
            target: Target to scan
            scan_type: Type of scan to perform
            ports: Port specification
            timing: Timing template
            
        Returns:
            NmapResult with scan results
        """
        # For now, just call the synchronous version
        # In a real implementation, this would use asyncio.subprocess
        return self.scan(target, scan_type, ports, timing)


class NmapTool:
    """Simplified Nmap tool wrapper."""
    
    def __init__(self, nmap_path: str = "nmap"):
        """Initialize Nmap tool.
        
        Args:
            nmap_path: Path to nmap binary
        """
        self.scanner = NmapScanner(nmap_path)
    
    def run(self, target: str, scan_type: str = "basic", 
            ports: Optional[str] = None, timing: str = "T3") -> str:
        """Run Nmap scan and return JSON result.
        
        Args:
            target: Target to scan
            scan_type: Type of scan to perform
            ports: Port specification
            timing: Timing template
            
        Returns:
            JSON string with scan results
        """
        result = self.scanner.scan(target, scan_type, ports, timing)
        return json.dumps(result.to_dict(), indent=2)