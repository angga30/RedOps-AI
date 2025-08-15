"""Main CLI module for RedOps-AI.

Provides the primary command-line interface for the RedOps-AI
autonomous penetration testing framework.
"""

import asyncio
import sys
from pathlib import Path
from typing import Optional, Dict, Any

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.json import JSON

# Add project root to path for imports
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from redops.core.config import load_config
from redops.core.logging import setup_logging, get_logger
from redops.core.exceptions import RedOpsError, ConfigurationError, ValidationError
from redops.core.validation import validate_target, validate_targets
from redops.agents.coordinator import CoordinatorAgent
from redops.agents.reconnaissance import ReconnaissanceAgent

# Initialize console for rich output
console = Console()
logger = None


def init_logging(verbose: bool = False, debug: bool = False) -> None:
    """Initialize logging configuration.
    
    Args:
        verbose: Enable verbose logging
        debug: Enable debug logging
    """
    global logger
    
    log_level = "DEBUG" if debug else ("INFO" if verbose else "WARNING")
    setup_logging(level=log_level)
    logger = get_logger("redops.cli")


def load_app_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Load application configuration.
    
    Args:
        config_path: Optional path to config file
        
    Returns:
        Loaded configuration
        
    Raises:
        ConfigurationError: If config cannot be loaded
    """
    try:
        if config_path:
            config_file = Path(config_path)
            if not config_file.exists():
                raise ConfigurationError(f"Config file not found: {config_path}")
        else:
            # Look for config in standard locations
            config_file = None
            for path in ["config.yaml", "config.yml", ".redops/config.yaml"]:
                if Path(path).exists():
                    config_file = Path(path)
                    break
        
        return load_config(config_file)
    
    except Exception as e:
        raise ConfigurationError(f"Failed to load configuration: {e}")


def display_banner() -> None:
    """Display the RedOps-AI banner."""
    banner = """
██████╗ ███████╗██████╗  ██████╗ ██████╗ ███████╗      █████╗ ██╗
██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔══██╗██╔════╝     ██╔══██╗██║
██████╔╝█████╗  ██║  ██║██║   ██║██████╔╝███████╗     ███████║██║
██╔══██╗██╔══╝  ██║  ██║██║   ██║██╔═══╝ ╚════██║     ██╔══██║██║
██║  ██║███████╗██████╔╝╚██████╔╝██║     ███████║     ██║  ██║██║
╚═╝  ╚═╝╚══════╝╚═════╝  ╚═════╝ ╚═╝     ╚══════╝     ╚═╝  ╚═╝╚═╝

    Autonomous Penetration Testing Framework
    """
    
    console.print(Panel(banner, style="bold red", padding=(1, 2)))


def display_results(results: Dict[str, Any], format_type: str = "table") -> None:
    """Display scan results in the specified format.
    
    Args:
        results: Results to display
        format_type: Format type (table, json, summary)
    """
    if format_type == "json":
        console.print(JSON.from_data(results))
        return
    
    if format_type == "summary":
        _display_summary(results)
        return
    
    # Default table format
    _display_table_results(results)


def _display_summary(results: Dict[str, Any]) -> None:
    """Display results summary.
    
    Args:
        results: Results to summarize
    """
    data = results.get("data", {})
    stats = data.get("statistics", {})
    
    # Create summary panel
    summary_text = f"""
[bold]Target:[/bold] {data.get('target', 'Unknown')}
[bold]Scan Type:[/bold] {data.get('target_type', 'Unknown')}
[bold]Status:[/bold] {'✅ Success' if results.get('success') else '❌ Failed'}

[bold]Statistics:[/bold]
• Total Hosts: {stats.get('total_hosts', 0)}
• Active Hosts: {stats.get('active_hosts', 0)}
• Open Ports: {stats.get('open_ports', 0)}
• Services Found: {stats.get('total_services', 0)}
    """
    
    console.print(Panel(summary_text, title="Scan Summary", style="green"))
    
    # Display interesting findings if available
    findings = data.get("interesting_findings", [])
    if findings:
        console.print("\n[bold yellow]Interesting Findings:[/bold yellow]")
        for finding in findings[:5]:  # Show top 5 findings
            severity_color = {
                "low": "blue",
                "medium": "yellow", 
                "high": "red",
                "critical": "bright_red"
            }.get(finding.get("severity", "low"), "white")
            
            console.print(f"• [{severity_color}]{finding.get('description', 'Unknown finding')}[/{severity_color}]")
    
    # Display AI analysis if available
    ai_analysis = data.get("ai_analysis", {})
    if ai_analysis and "error" not in ai_analysis:
        console.print("\n[bold cyan]AI Analysis:[/bold cyan]")
        console.print(f"Risk Level: [{_get_risk_color(ai_analysis.get('risk_level', 'unknown'))}]{ai_analysis.get('risk_level', 'Unknown').upper()}[/{_get_risk_color(ai_analysis.get('risk_level', 'unknown'))}]")
        console.print(f"Summary: {ai_analysis.get('summary', 'No summary available')}")


def _display_table_results(results: Dict[str, Any]) -> None:
    """Display results in table format.
    
    Args:
        results: Results to display
    """
    data = results.get("data", {})
    
    # Display hosts table
    hosts = data.get("hosts", [])
    if hosts:
        hosts_table = Table(title="Discovered Hosts")
        hosts_table.add_column("IP Address", style="cyan")
        hosts_table.add_column("Hostname", style="green")
        hosts_table.add_column("State", style="yellow")
        hosts_table.add_column("OS", style="magenta")
        
        for host in hosts:
            hosts_table.add_row(
                host.get("ip", "Unknown"),
                host.get("hostname", "N/A"),
                host.get("state", "Unknown"),
                host.get("os", "N/A")
            )
        
        console.print(hosts_table)
    
    # Display services table
    services = data.get("services", [])
    if services:
        services_table = Table(title="Discovered Services")
        services_table.add_column("Host", style="cyan")
        services_table.add_column("Port", style="yellow")
        services_table.add_column("Protocol", style="green")
        services_table.add_column("Service", style="magenta")
        services_table.add_column("Version", style="blue")
        
        for service in services[:20]:  # Limit to first 20 services
            services_table.add_row(
                service.get("host", "Unknown"),
                str(service.get("port", "Unknown")),
                service.get("protocol", "Unknown"),
                service.get("service", "Unknown"),
                service.get("version", "N/A")
            )
        
        console.print(services_table)
        
        if len(services) > 20:
            console.print(f"[dim]... and {len(services) - 20} more services[/dim]")


def _get_risk_color(risk_level: str) -> str:
    """Get color for risk level.
    
    Args:
        risk_level: Risk level string
        
    Returns:
        Color name for rich formatting
    """
    colors = {
        "low": "green",
        "medium": "yellow",
        "high": "red",
        "critical": "bright_red"
    }
    return colors.get(risk_level.lower(), "white")


@click.group()
@click.option("--config", "-c", help="Path to configuration file")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.option("--debug", "-d", is_flag=True, help="Enable debug output")
@click.option("--no-banner", is_flag=True, help="Disable banner display")
@click.pass_context
def cli(ctx: click.Context, config: Optional[str], verbose: bool, debug: bool, no_banner: bool) -> None:
    """RedOps-AI - Autonomous Penetration Testing Framework.
    
    A multi-agent AI system for automated security assessments.
    """
    # Initialize logging
    init_logging(verbose, debug)
    
    # Display banner unless disabled
    if not no_banner:
        display_banner()
    
    # Load configuration
    try:
        app_config = load_app_config(config)
        ctx.ensure_object(dict)
        ctx.obj["config"] = app_config
        ctx.obj["verbose"] = verbose
        ctx.obj["debug"] = debug
        
        if logger:
            logger.info("RedOps-AI CLI initialized", config_loaded=bool(app_config))
    
    except ConfigurationError as e:
        console.print(f"[red]Configuration Error:[/red] {e}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Initialization Error:[/red] {e}")
        if debug:
            console.print_exception()
        sys.exit(1)


@cli.command()
@click.argument("target")
@click.option("--scan-type", "-t", 
              type=click.Choice(["quick", "basic", "comprehensive", "stealth"]),
              default="basic", help="Type of scan to perform")
@click.option("--ports", "-p", help="Ports to scan (e.g., 80,443,8080 or 1-1000)")
@click.option("--timing", type=click.IntRange(0, 5), default=3, 
              help="Nmap timing template (0-5)")
@click.option("--output", "-o", help="Output file path")
@click.option("--format", "-f", 
              type=click.Choice(["table", "json", "summary"]),
              default="summary", help="Output format")
@click.option("--autonomous", "-a", is_flag=True, 
              help="Enable autonomous mode (full workflow)")
@click.pass_context
def scan(ctx: click.Context, target: str, scan_type: str, ports: Optional[str],
         timing: int, output: Optional[str], format: str, autonomous: bool) -> None:
    """Perform reconnaissance scan on a target.
    
    TARGET can be an IP address, hostname, or CIDR range.
    
    Examples:
        redops scan 192.168.1.1
        redops scan example.com --scan-type comprehensive
        redops scan 192.168.1.0/24 --autonomous
    """
    config = ctx.obj["config"]
    verbose = ctx.obj["verbose"]
    
    try:
        # Validate target
        normalized_target, target_type = validate_target(target)
        
        if verbose:
            console.print(f"[green]Target validated:[/green] {normalized_target} ({target_type.value})")
        
        # Build scan options
        scan_options = {
            "scan_strategy": scan_type,
            "timing": timing
        }
        
        if ports:
            scan_options["ports"] = ports
        
        # Run scan
        if autonomous:
            # Use coordinator agent for full autonomous workflow
            results = asyncio.run(_run_autonomous_scan(config, normalized_target, scan_options))
        else:
            # Use reconnaissance agent only
            results = asyncio.run(_run_reconnaissance_scan(config, normalized_target, scan_options))
        
        # Display results
        display_results(results, format)
        
        # Save output if requested
        if output:
            _save_results(results, output, format)
            console.print(f"[green]Results saved to:[/green] {output}")
        
        # Exit with appropriate code
        sys.exit(0 if results.get("success") else 1)
    
    except ValidationError as e:
        console.print(f"[red]Invalid target:[/red] {e.message}")
        sys.exit(1)
    except RedOpsError as e:
        console.print(f"[red]RedOps Error:[/red] {e.message}")
        if verbose:
            console.print_exception()
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Unexpected error:[/red] {e}")
        if verbose:
            console.print_exception()
        sys.exit(1)


async def _run_reconnaissance_scan(config: Dict[str, Any], target: str, 
                                 options: Dict[str, Any]) -> Dict[str, Any]:
    """Run reconnaissance scan using ReconnaissanceAgent.
    
    Args:
        config: Application configuration
        target: Target to scan
        options: Scan options
        
    Returns:
        Scan results
    """
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task(f"Scanning {target}...", total=None)
        
        try:
            # Initialize reconnaissance agent
            recon_agent = ReconnaissanceAgent(config.get("agents", {}).get("reconnaissance", {}))
            
            # Execute scan
            result = await recon_agent.execute(target, options)
            
            progress.update(task, description=f"Scan completed for {target}")
            return result.to_dict()
        
        except Exception as e:
            progress.update(task, description=f"Scan failed for {target}")
            raise


async def _run_autonomous_scan(config: Dict[str, Any], target: str, 
                             options: Dict[str, Any]) -> Dict[str, Any]:
    """Run autonomous scan using CoordinatorAgent.
    
    Args:
        config: Application configuration
        target: Target to scan
        options: Scan options
        
    Returns:
        Scan results
    """
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task(f"Running autonomous assessment on {target}...", total=None)
        
        try:
            # Initialize coordinator agent
            coordinator = CoordinatorAgent(config.get("agents", {}).get("coordinator", {}))
            
            # Execute autonomous workflow
            result = await coordinator.execute(target, options)
            
            progress.update(task, description=f"Autonomous assessment completed for {target}")
            return result.to_dict()
        
        except Exception as e:
            progress.update(task, description=f"Autonomous assessment failed for {target}")
            raise


def _save_results(results: Dict[str, Any], output_path: str, format_type: str) -> None:
    """Save results to file.
    
    Args:
        results: Results to save
        output_path: Output file path
        format_type: Format type
    """
    import json
    
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    if format_type == "json":
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2, default=str)
    else:
        # Save as text format
        with open(output_file, "w") as f:
            f.write(f"RedOps-AI Scan Results\n")
            f.write(f"======================\n\n")
            f.write(f"Target: {results.get('data', {}).get('target', 'Unknown')}\n")
            f.write(f"Timestamp: {results.get('data', {}).get('timestamp', 'Unknown')}\n")
            f.write(f"Success: {results.get('success', False)}\n\n")
            
            # Add statistics
            stats = results.get("data", {}).get("statistics", {})
            f.write(f"Statistics:\n")
            for key, value in stats.items():
                f.write(f"  {key}: {value}\n")
            f.write("\n")
            
            # Add services
            services = results.get("data", {}).get("services", [])
            if services:
                f.write(f"Services ({len(services)} found):\n")
                for service in services:
                    f.write(f"  {service.get('host', 'Unknown')}:{service.get('port', 'Unknown')} - ")
                    f.write(f"{service.get('service', 'Unknown')} ({service.get('version', 'N/A')})\n")


@cli.command()
@click.argument("targets", nargs=-1, required=True)
@click.option("--scan-type", "-t", 
              type=click.Choice(["quick", "basic", "comprehensive", "stealth"]),
              default="basic", help="Type of scan to perform")
@click.option("--concurrent", "-j", type=int, default=5, 
              help="Number of concurrent scans")
@click.option("--output-dir", "-o", help="Output directory for results")
@click.option("--format", "-f", 
              type=click.Choice(["table", "json", "summary"]),
              default="summary", help="Output format")
@click.pass_context
def batch(ctx: click.Context, targets: tuple, scan_type: str, concurrent: int,
          output_dir: Optional[str], format: str) -> None:
    """Perform batch scanning on multiple targets.
    
    TARGETS can be multiple IP addresses, hostnames, or CIDR ranges.
    
    Examples:
        redops batch 192.168.1.1 192.168.1.2 example.com
        redops batch 192.168.1.0/24 10.0.0.0/24 --concurrent 10
    """
    config = ctx.obj["config"]
    verbose = ctx.obj["verbose"]
    
    try:
        # Validate all targets
        validated_targets = validate_targets(list(targets))
        
        if verbose:
            console.print(f"[green]Validated {len(validated_targets)} targets[/green]")
        
        # Run batch scan
        results = asyncio.run(_run_batch_scan(config, validated_targets, scan_type, concurrent))
        
        # Display results
        for i, result in enumerate(results):
            console.print(f"\n[bold]Results for {validated_targets[i]}:[/bold]")
            display_results(result, format)
        
        # Save results if output directory specified
        if output_dir:
            _save_batch_results(results, validated_targets, output_dir, format)
            console.print(f"[green]Batch results saved to:[/green] {output_dir}")
        
        # Exit with appropriate code
        success_count = sum(1 for r in results if r.get("success"))
        console.print(f"\n[green]Batch scan completed:[/green] {success_count}/{len(results)} successful")
        sys.exit(0 if success_count == len(results) else 1)
    
    except ValidationError as e:
        console.print(f"[red]Invalid targets:[/red] {e.message}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Batch scan error:[/red] {e}")
        if verbose:
            console.print_exception()
        sys.exit(1)


async def _run_batch_scan(config: Dict[str, Any], targets: List[str], 
                         scan_type: str, concurrent: int) -> List[Dict[str, Any]]:
    """Run batch scan on multiple targets.
    
    Args:
        config: Application configuration
        targets: List of targets to scan
        scan_type: Type of scan
        concurrent: Number of concurrent scans
        
    Returns:
        List of scan results
    """
    semaphore = asyncio.Semaphore(concurrent)
    
    async def scan_target(target: str) -> Dict[str, Any]:
        async with semaphore:
            try:
                recon_agent = ReconnaissanceAgent(config.get("agents", {}).get("reconnaissance", {}))
                result = await recon_agent.execute(target, {"scan_strategy": scan_type})
                return result.to_dict()
            except Exception as e:
                return {
                    "success": False,
                    "data": {},
                    "errors": [str(e)],
                    "metadata": {"target": target}
                }
    
    # Run all scans concurrently
    tasks = [scan_target(target) for target in targets]
    return await asyncio.gather(*tasks)


def _save_batch_results(results: List[Dict[str, Any]], targets: List[str], 
                       output_dir: str, format_type: str) -> None:
    """Save batch results to directory.
    
    Args:
        results: List of results
        targets: List of targets
        output_dir: Output directory
        format_type: Format type
    """
    import json
    from datetime import datetime
    
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    for i, (result, target) in enumerate(zip(results, targets)):
        # Sanitize target for filename
        safe_target = target.replace("/", "_").replace(":", "_")
        filename = f"{timestamp}_{safe_target}.{format_type if format_type == 'json' else 'txt'}"
        
        result_file = output_path / filename
        _save_results(result, str(result_file), format_type)


@cli.command()
@click.pass_context
def config(ctx: click.Context) -> None:
    """Display current configuration."""
    config_data = ctx.obj["config"]
    
    console.print("[bold]Current Configuration:[/bold]")
    console.print(JSON.from_data(config_data))


@cli.command()
@click.pass_context
def version(ctx: click.Context) -> None:
    """Display version information."""
    version_info = {
        "version": "1.0.0",
        "python_version": sys.version,
        "platform": sys.platform
    }
    
    console.print("[bold]RedOps-AI Version Information:[/bold]")
    console.print(JSON.from_data(version_info))


if __name__ == "__main__":
    cli()