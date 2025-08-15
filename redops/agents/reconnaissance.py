"""Reconnaissance Agent for network scanning and analysis.

Simplified version without LangChain dependencies for testing.
"""

import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field

from ..tools.nmap import NmapScanner, NmapResult


@dataclass
class ReconResult:
    """Result from reconnaissance analysis."""
    target: str
    scan_results: List[NmapResult] = field(default_factory=list)
    analysis: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    risk_level: str = "unknown"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "target": self.target,
            "scan_results": [result.to_dict() for result in self.scan_results],
            "analysis": self.analysis,
            "recommendations": self.recommendations,
            "risk_level": self.risk_level
        }


class ReconnaissanceAgent:
    """Agent for network reconnaissance and analysis."""
    
    def __init__(self, nmap_path: str = "nmap"):
        """Initialize reconnaissance agent.
        
        Args:
            nmap_path: Path to nmap binary
        """
        self.scanner = NmapScanner(nmap_path)
        self.name = "reconnaissance"
    
    def analyze_target(self, target: str, scan_type: str = "basic", 
                      ports: Optional[str] = None) -> ReconResult:
        """Analyze a target using network reconnaissance.
        
        Args:
            target: Target to analyze
            scan_type: Type of scan to perform
            ports: Port specification
            
        Returns:
            ReconResult with analysis
        """
        result = ReconResult(target=target)
        
        try:
            # Perform Nmap scan
            scan_result = self.scanner.scan(target, scan_type, ports)
            result.scan_results.append(scan_result)
            
            if scan_result.error:
                result.analysis["error"] = scan_result.error
                result.risk_level = "unknown"
                return result
            
            # Analyze scan results
            analysis = self._analyze_scan_results(scan_result)
            result.analysis = analysis
            
            # Generate recommendations
            recommendations = self._generate_recommendations(analysis)
            result.recommendations = recommendations
            
            # Determine risk level
            result.risk_level = self._assess_risk_level(analysis)
            
        except Exception as e:
            result.analysis["error"] = f"Analysis failed: {str(e)}"
            result.risk_level = "unknown"
        
        return result
    
    def _analyze_scan_results(self, scan_result: NmapResult) -> Dict[str, Any]:
        """Analyze Nmap scan results.
        
        Args:
            scan_result: Nmap scan result
            
        Returns:
            Analysis dictionary
        """
        analysis = {
            "hosts_discovered": len(scan_result.hosts),
            "hosts_up": len([h for h in scan_result.hosts if h["state"] == "up"]),
            "total_ports": 0,
            "open_ports": 0,
            "services": [],
            "interesting_findings": []
        }
        
        # Analyze hosts and ports
        for host in scan_result.hosts:
            if host["state"] == "up":
                analysis["total_ports"] += len(host["ports"])
                
                for port in host["ports"]:
                    if port["state"] == "open":
                        analysis["open_ports"] += 1
                        
                        # Extract service information
                        service_info = {
                            "port": port["portid"],
                            "protocol": port["protocol"],
                            "service": port["service"].get("name", "unknown"),
                            "product": port["service"].get("product", ""),
                            "version": port["service"].get("version", "")
                        }
                        analysis["services"].append(service_info)
                        
                        # Check for interesting services
                        self._check_interesting_service(port, analysis["interesting_findings"])
        
        # Categorize services
        analysis["service_categories"] = self._categorize_services(analysis["services"])
        
        return analysis
    
    def _check_interesting_service(self, port: Dict[str, Any], findings: List[str]) -> None:
        """Check if a service is interesting from security perspective.
        
        Args:
            port: Port information
            findings: List to append findings to
        """
        port_num = port["portid"]
        service_name = port["service"].get("name", "")
        product = port["service"].get("product", "")
        
        # Common interesting services
        interesting_services = {
            "22": "SSH service detected",
            "23": "Telnet service detected (insecure)",
            "21": "FTP service detected",
            "80": "HTTP web service detected",
            "443": "HTTPS web service detected",
            "3389": "RDP service detected",
            "445": "SMB service detected",
            "139": "NetBIOS service detected",
            "135": "RPC service detected",
            "1433": "SQL Server detected",
            "3306": "MySQL service detected",
            "5432": "PostgreSQL service detected",
            "6379": "Redis service detected",
            "27017": "MongoDB service detected"
        }
        
        if port_num in interesting_services:
            findings.append(f"Port {port_num}: {interesting_services[port_num]}")
        
        # Check for default credentials indicators
        if "default" in product.lower() or "admin" in product.lower():
            findings.append(f"Port {port_num}: Potential default credentials ({product})")
        
        # Check for outdated versions
        version = port["service"].get("version", "")
        if version and any(old_ver in version.lower() for old_ver in ["2.0", "1.0", "legacy"]):
            findings.append(f"Port {port_num}: Potentially outdated version ({version})")
    
    def _categorize_services(self, services: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """Categorize services by type.
        
        Args:
            services: List of service information
            
        Returns:
            Dictionary of categorized services
        """
        categories = {
            "web": [],
            "database": [],
            "remote_access": [],
            "file_sharing": [],
            "email": [],
            "other": []
        }
        
        for service in services:
            service_name = service["service"].lower()
            port = service["port"]
            
            if service_name in ["http", "https", "apache", "nginx"] or port in ["80", "443", "8080", "8443"]:
                categories["web"].append(f"{port}/{service_name}")
            elif service_name in ["mysql", "postgresql", "mssql", "oracle", "mongodb", "redis"] or port in ["3306", "5432", "1433", "1521", "27017", "6379"]:
                categories["database"].append(f"{port}/{service_name}")
            elif service_name in ["ssh", "telnet", "rdp", "vnc"] or port in ["22", "23", "3389", "5900"]:
                categories["remote_access"].append(f"{port}/{service_name}")
            elif service_name in ["ftp", "smb", "nfs", "samba"] or port in ["21", "445", "139", "2049"]:
                categories["file_sharing"].append(f"{port}/{service_name}")
            elif service_name in ["smtp", "pop3", "imap"] or port in ["25", "110", "143", "587", "993", "995"]:
                categories["email"].append(f"{port}/{service_name}")
            else:
                categories["other"].append(f"{port}/{service_name}")
        
        # Remove empty categories
        return {k: v for k, v in categories.items() if v}
    
    def _generate_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on analysis.
        
        Args:
            analysis: Analysis results
            
        Returns:
            List of recommendations
        """
        recommendations = []
        
        # Check for open ports
        if analysis["open_ports"] > 10:
            recommendations.append("Consider closing unnecessary open ports to reduce attack surface")
        
        # Check for interesting findings
        if analysis["interesting_findings"]:
            recommendations.append("Review interesting services found for potential security issues")
        
        # Service-specific recommendations
        service_categories = analysis.get("service_categories", {})
        
        if "remote_access" in service_categories:
            recommendations.append("Secure remote access services with strong authentication and encryption")
        
        if "database" in service_categories:
            recommendations.append("Ensure database services are not exposed to the internet unnecessarily")
        
        if "web" in service_categories:
            recommendations.append("Perform web application security testing on discovered web services")
        
        if "file_sharing" in service_categories:
            recommendations.append("Review file sharing services for proper access controls")
        
        # General recommendations
        if analysis["hosts_up"] > 1:
            recommendations.append("Consider network segmentation to limit lateral movement")
        
        if not recommendations:
            recommendations.append("No specific security concerns identified, but continue monitoring")
        
        return recommendations
    
    def _assess_risk_level(self, analysis: Dict[str, Any]) -> str:
        """Assess overall risk level based on analysis.
        
        Args:
            analysis: Analysis results
            
        Returns:
            Risk level (low, medium, high, critical)
        """
        risk_score = 0
        
        # Score based on open ports
        if analysis["open_ports"] > 20:
            risk_score += 3
        elif analysis["open_ports"] > 10:
            risk_score += 2
        elif analysis["open_ports"] > 5:
            risk_score += 1
        
        # Score based on interesting findings
        risk_score += min(len(analysis["interesting_findings"]), 5)
        
        # Score based on service categories
        service_categories = analysis.get("service_categories", {})
        if "database" in service_categories:
            risk_score += 2
        if "remote_access" in service_categories:
            risk_score += 1
        if "file_sharing" in service_categories:
            risk_score += 1
        
        # Determine risk level
        if risk_score >= 8:
            return "critical"
        elif risk_score >= 5:
            return "high"
        elif risk_score >= 2:
            return "medium"
        else:
            return "low"
    
    def health_check(self) -> Dict[str, Any]:
        """Perform health check of the agent.
        
        Returns:
            Health status dictionary
        """
        try:
            # Test Nmap availability
            test_result = self.scanner.scan("127.0.0.1", "quick", "80")
            
            return {
                "status": "healthy",
                "nmap_available": test_result.error is None,
                "agent_name": self.name
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
                "agent_name": self.name
            }