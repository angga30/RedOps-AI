"""Coordinator Agent for orchestrating multi-agent workflows.

Simplified version without LangGraph dependencies for testing.
"""

import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime

from .reconnaissance import ReconnaissanceAgent, ReconResult


@dataclass
class WorkflowState:
    """State management for the multi-agent workflow."""
    target: str
    current_phase: str = "reconnaissance"
    reconnaissance_results: Optional[ReconResult] = None
    analysis_results: Dict[str, Any] = field(default_factory=dict)
    exploitation_results: Dict[str, Any] = field(default_factory=dict)
    report_data: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    completed_phases: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert state to dictionary."""
        return {
            "target": self.target,
            "current_phase": self.current_phase,
            "reconnaissance_results": self.reconnaissance_results.to_dict() if self.reconnaissance_results else None,
            "analysis_results": self.analysis_results,
            "exploitation_results": self.exploitation_results,
            "report_data": self.report_data,
            "errors": self.errors,
            "completed_phases": self.completed_phases,
            "metadata": self.metadata
        }


class CoordinatorAgent:
    """Coordinator agent for orchestrating multi-agent workflows."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize coordinator agent.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.name = "coordinator"
        
        # Initialize agents
        self.recon_agent = ReconnaissanceAgent()
        
        # Workflow configuration
        self.workflow_phases = ["reconnaissance", "analysis", "exploitation", "reporting"]
        self.autonomous_mode = False
    
    def execute_workflow(self, target: str, options: Optional[Dict[str, Any]] = None) -> WorkflowState:
        """Execute the complete multi-agent workflow.
        
        Args:
            target: Target to analyze
            options: Workflow options
            
        Returns:
            Final workflow state
        """
        # Initialize workflow state
        state = WorkflowState(target=target)
        state.metadata["start_time"] = datetime.now().isoformat()
        state.metadata["options"] = options or {}
        
        # Set autonomous mode
        self.autonomous_mode = options.get("autonomous", False) if options else False
        
        try:
            # Execute workflow phases
            for phase in self.workflow_phases:
                state.current_phase = phase
                
                if phase == "reconnaissance":
                    self._execute_reconnaissance(state, options)
                elif phase == "analysis":
                    self._execute_analysis(state, options)
                elif phase == "exploitation":
                    self._execute_exploitation(state, options)
                elif phase == "reporting":
                    self._execute_reporting(state, options)
                
                # Mark phase as completed
                state.completed_phases.append(phase)
                
                # Check if we should continue in autonomous mode
                if not self.autonomous_mode and phase == "reconnaissance":
                    # In non-autonomous mode, stop after reconnaissance
                    break
            
            state.metadata["end_time"] = datetime.now().isoformat()
            state.metadata["success"] = True
            
        except Exception as e:
            state.errors.append(f"Workflow execution failed: {str(e)}")
            state.metadata["end_time"] = datetime.now().isoformat()
            state.metadata["success"] = False
        
        return state
    
    def _execute_reconnaissance(self, state: WorkflowState, options: Optional[Dict[str, Any]]) -> None:
        """Execute reconnaissance phase.
        
        Args:
            state: Current workflow state
            options: Phase options
        """
        try:
            # Extract reconnaissance options
            recon_options = options.get("reconnaissance", {}) if options else {}
            scan_type = recon_options.get("scan_type", "basic")
            ports = recon_options.get("ports")
            
            # Execute reconnaissance
            recon_result = self.recon_agent.analyze_target(
                target=state.target,
                scan_type=scan_type,
                ports=ports
            )
            
            state.reconnaissance_results = recon_result
            
            # Update metadata
            state.metadata["reconnaissance"] = {
                "scan_type": scan_type,
                "ports": ports,
                "hosts_discovered": recon_result.analysis.get("hosts_discovered", 0),
                "open_ports": recon_result.analysis.get("open_ports", 0),
                "risk_level": recon_result.risk_level
            }
            
        except Exception as e:
            state.errors.append(f"Reconnaissance failed: {str(e)}")
            raise
    
    def _execute_analysis(self, state: WorkflowState, options: Optional[Dict[str, Any]]) -> None:
        """Execute analysis phase.
        
        Args:
            state: Current workflow state
            options: Phase options
        """
        try:
            if not state.reconnaissance_results:
                raise ValueError("No reconnaissance results available for analysis")
            
            # Perform advanced analysis on reconnaissance results
            analysis = self._analyze_reconnaissance_results(state.reconnaissance_results)
            state.analysis_results = analysis
            
            # Update metadata
            state.metadata["analysis"] = {
                "vulnerabilities_found": len(analysis.get("vulnerabilities", [])),
                "attack_vectors": len(analysis.get("attack_vectors", [])),
                "priority_targets": len(analysis.get("priority_targets", []))
            }
            
        except Exception as e:
            state.errors.append(f"Analysis failed: {str(e)}")
            raise
    
    def _execute_exploitation(self, state: WorkflowState, options: Optional[Dict[str, Any]]) -> None:
        """Execute exploitation phase (placeholder).
        
        Args:
            state: Current workflow state
            options: Phase options
        """
        try:
            # Placeholder for exploitation logic
            # In a real implementation, this would coordinate with exploitation agents
            
            exploitation_results = {
                "status": "not_implemented",
                "message": "Exploitation phase is not yet implemented",
                "potential_exploits": self._identify_potential_exploits(state)
            }
            
            state.exploitation_results = exploitation_results
            
            # Update metadata
            state.metadata["exploitation"] = {
                "status": "skipped",
                "reason": "Not implemented in current version"
            }
            
        except Exception as e:
            state.errors.append(f"Exploitation failed: {str(e)}")
            raise
    
    def _execute_reporting(self, state: WorkflowState, options: Optional[Dict[str, Any]]) -> None:
        """Execute reporting phase.
        
        Args:
            state: Current workflow state
            options: Phase options
        """
        try:
            # Generate comprehensive report
            report = self._generate_report(state)
            state.report_data = report
            
            # Update metadata
            state.metadata["reporting"] = {
                "report_sections": len(report.get("sections", [])),
                "total_findings": len(report.get("findings", [])),
                "recommendations": len(report.get("recommendations", []))
            }
            
        except Exception as e:
            state.errors.append(f"Reporting failed: {str(e)}")
            raise
    
    def _analyze_reconnaissance_results(self, recon_result: ReconResult) -> Dict[str, Any]:
        """Perform advanced analysis on reconnaissance results.
        
        Args:
            recon_result: Reconnaissance results
            
        Returns:
            Analysis results
        """
        analysis = {
            "vulnerabilities": [],
            "attack_vectors": [],
            "priority_targets": [],
            "security_posture": "unknown"
        }
        
        # Analyze services for potential vulnerabilities
        services = recon_result.analysis.get("services", [])
        for service in services:
            # Check for common vulnerabilities
            vulns = self._check_service_vulnerabilities(service)
            analysis["vulnerabilities"].extend(vulns)
            
            # Identify attack vectors
            vectors = self._identify_attack_vectors(service)
            analysis["attack_vectors"].extend(vectors)
        
        # Identify priority targets
        analysis["priority_targets"] = self._identify_priority_targets(services)
        
        # Assess overall security posture
        analysis["security_posture"] = self._assess_security_posture(recon_result)
        
        return analysis
    
    def _check_service_vulnerabilities(self, service: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check a service for potential vulnerabilities.
        
        Args:
            service: Service information
            
        Returns:
            List of potential vulnerabilities
        """
        vulnerabilities = []
        
        service_name = service.get("service", "").lower()
        port = service.get("port", "")
        version = service.get("version", "")
        
        # Common vulnerability patterns
        vuln_patterns = {
            "ssh": {
                "name": "SSH Brute Force",
                "description": "SSH service may be vulnerable to brute force attacks",
                "severity": "medium"
            },
            "ftp": {
                "name": "FTP Anonymous Access",
                "description": "FTP service may allow anonymous access",
                "severity": "high"
            },
            "telnet": {
                "name": "Unencrypted Protocol",
                "description": "Telnet transmits data in plaintext",
                "severity": "high"
            },
            "http": {
                "name": "Web Application Vulnerabilities",
                "description": "Web service may have application-level vulnerabilities",
                "severity": "medium"
            }
        }
        
        if service_name in vuln_patterns:
            vuln = vuln_patterns[service_name].copy()
            vuln["service"] = service
            vulnerabilities.append(vuln)
        
        # Check for version-specific vulnerabilities
        if version and any(old_ver in version.lower() for old_ver in ["2.0", "1.0", "legacy"]):
            vulnerabilities.append({
                "name": "Outdated Software Version",
                "description": f"Service running potentially outdated version: {version}",
                "severity": "medium",
                "service": service
            })
        
        return vulnerabilities
    
    def _identify_attack_vectors(self, service: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify potential attack vectors for a service.
        
        Args:
            service: Service information
            
        Returns:
            List of attack vectors
        """
        attack_vectors = []
        
        service_name = service.get("service", "").lower()
        port = service.get("port", "")
        
        # Common attack vectors
        vector_patterns = {
            "ssh": ["Brute Force", "Key-based Authentication Bypass"],
            "ftp": ["Anonymous Access", "Directory Traversal"],
            "http": ["SQL Injection", "Cross-Site Scripting", "Directory Traversal"],
            "https": ["SSL/TLS Vulnerabilities", "Certificate Issues"],
            "smb": ["SMB Relay", "Null Session"],
            "rdp": ["Brute Force", "BlueKeep Vulnerability"]
        }
        
        if service_name in vector_patterns:
            for vector in vector_patterns[service_name]:
                attack_vectors.append({
                    "name": vector,
                    "service": service,
                    "likelihood": "medium"
                })
        
        return attack_vectors
    
    def _identify_priority_targets(self, services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify priority targets based on services.
        
        Args:
            services: List of services
            
        Returns:
            List of priority targets
        """
        priority_targets = []
        
        # High-value services
        high_value_services = ["ssh", "rdp", "ftp", "smb", "mysql", "postgresql", "mssql"]
        
        for service in services:
            service_name = service.get("service", "").lower()
            if service_name in high_value_services:
                priority_targets.append({
                    "service": service,
                    "priority": "high",
                    "reason": f"{service_name.upper()} service provides high-value access"
                })
        
        return priority_targets
    
    def _assess_security_posture(self, recon_result: ReconResult) -> str:
        """Assess overall security posture.
        
        Args:
            recon_result: Reconnaissance results
            
        Returns:
            Security posture assessment
        """
        risk_level = recon_result.risk_level
        open_ports = recon_result.analysis.get("open_ports", 0)
        interesting_findings = len(recon_result.analysis.get("interesting_findings", []))
        
        if risk_level == "critical" or open_ports > 20:
            return "poor"
        elif risk_level == "high" or open_ports > 10:
            return "weak"
        elif risk_level == "medium" or interesting_findings > 3:
            return "moderate"
        else:
            return "good"
    
    def _identify_potential_exploits(self, state: WorkflowState) -> List[Dict[str, Any]]:
        """Identify potential exploits based on analysis results.
        
        Args:
            state: Current workflow state
            
        Returns:
            List of potential exploits
        """
        potential_exploits = []
        
        if not state.analysis_results:
            return potential_exploits
        
        vulnerabilities = state.analysis_results.get("vulnerabilities", [])
        
        for vuln in vulnerabilities:
            exploit = {
                "name": f"Exploit for {vuln.get('name', 'Unknown')}",
                "vulnerability": vuln,
                "difficulty": "medium",
                "impact": vuln.get("severity", "unknown"),
                "status": "potential"
            }
            potential_exploits.append(exploit)
        
        return potential_exploits
    
    def _generate_report(self, state: WorkflowState) -> Dict[str, Any]:
        """Generate comprehensive report.
        
        Args:
            state: Final workflow state
            
        Returns:
            Report data
        """
        report = {
            "title": f"Security Assessment Report - {state.target}",
            "timestamp": datetime.now().isoformat(),
            "target": state.target,
            "executive_summary": self._generate_executive_summary(state),
            "sections": [],
            "findings": [],
            "recommendations": [],
            "metadata": state.metadata
        }
        
        # Add reconnaissance section
        if state.reconnaissance_results:
            recon_section = {
                "title": "Network Reconnaissance",
                "content": state.reconnaissance_results.to_dict()
            }
            report["sections"].append(recon_section)
            
            # Add findings from reconnaissance
            for finding in state.reconnaissance_results.analysis.get("interesting_findings", []):
                report["findings"].append({
                    "type": "reconnaissance",
                    "description": finding,
                    "severity": "info"
                })
            
            # Add recommendations from reconnaissance
            report["recommendations"].extend(state.reconnaissance_results.recommendations)
        
        # Add analysis section
        if state.analysis_results:
            analysis_section = {
                "title": "Security Analysis",
                "content": state.analysis_results
            }
            report["sections"].append(analysis_section)
            
            # Add findings from analysis
            for vuln in state.analysis_results.get("vulnerabilities", []):
                report["findings"].append({
                    "type": "vulnerability",
                    "description": vuln.get("description", ""),
                    "severity": vuln.get("severity", "unknown")
                })
        
        return report
    
    def _generate_executive_summary(self, state: WorkflowState) -> str:
        """Generate executive summary.
        
        Args:
            state: Workflow state
            
        Returns:
            Executive summary text
        """
        summary_parts = []
        
        if state.reconnaissance_results:
            recon = state.reconnaissance_results
            hosts_up = recon.analysis.get("hosts_up", 0)
            open_ports = recon.analysis.get("open_ports", 0)
            risk_level = recon.risk_level
            
            summary_parts.append(
                f"Network reconnaissance identified {hosts_up} active host(s) "
                f"with {open_ports} open port(s). Overall risk level: {risk_level}."
            )
        
        if state.analysis_results:
            analysis = state.analysis_results
            vuln_count = len(analysis.get("vulnerabilities", []))
            posture = analysis.get("security_posture", "unknown")
            
            summary_parts.append(
                f"Security analysis identified {vuln_count} potential vulnerabilities. "
                f"Security posture assessed as: {posture}."
            )
        
        if not summary_parts:
            summary_parts.append("Assessment completed with limited results.")
        
        return " ".join(summary_parts)
    
    def health_check(self) -> Dict[str, Any]:
        """Perform health check of the coordinator.
        
        Returns:
            Health status dictionary
        """
        try:
            # Check agent health
            recon_health = self.recon_agent.health_check()
            
            return {
                "status": "healthy" if recon_health["status"] == "healthy" else "unhealthy",
                "coordinator_name": self.name,
                "agents": {
                    "reconnaissance": recon_health
                },
                "workflow_phases": self.workflow_phases
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
                "coordinator_name": self.name
            }