"""CLI commands module for RedOps-AI.

Provides additional command implementations and utilities
for the RedOps-AI command-line interface.
"""

import asyncio
import json
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.json import JSON
from rich.prompt import Prompt, Confirm

from ..core.config import load_config, save_config
from ..core.logging import get_logger
from ..core.exceptions import RedOpsError, ConfigurationError, ValidationError
from ..core.validation import validate_target, validate_targets, NetworkValidator
from ..agents.reconnaissance import ReconnaissanceAgent
from ..agents.coordinator import CoordinatorAgent
from ..tools.nmap import NmapScanner

console = Console()
logger = get_logger("redops.cli.commands")


class TargetManager:
    """Manages target lists and validation."""
    
    def __init__(self, targets_file: str = ".redops/targets.json"):
        """Initialize target manager.
        
        Args:
            targets_file: Path to targets file
        """
        self.targets_file = Path(targets_file)
        self.targets_file.parent.mkdir(parents=True, exist_ok=True)
        self.validator = NetworkValidator()
    
    def load_targets(self) -> List[Dict[str, Any]]:
        """Load targets from file.
        
        Returns:
            List of target dictionaries
        """
        if not self.targets_file.exists():
            return []
        
        try:
            with open(self.targets_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Failed to load targets: {e}")
            return []
    
    def save_targets(self, targets: List[Dict[str, Any]]) -> None:
        """Save targets to file.
        
        Args:
            targets: List of target dictionaries
        """
        try:
            with open(self.targets_file, 'w') as f:
                json.dump(targets, f, indent=2, default=str)
        except IOError as e:
            logger.error(f"Failed to save targets: {e}")
            raise ConfigurationError(f"Failed to save targets: {e}")
    
    def add_target(self, target: str, name: Optional[str] = None, 
                   tags: Optional[List[str]] = None) -> Dict[str, Any]:
        """Add a target to the list.
        
        Args:
            target: Target address/range
            name: Optional target name
            tags: Optional tags
            
        Returns:
            Target dictionary
        """
        # Validate target
        normalized_target, target_type = validate_target(target)
        
        target_dict = {
            "id": len(self.load_targets()) + 1,
            "target": normalized_target,
            "original": target,
            "type": target_type.value,
            "name": name or target,
            "tags": tags or [],
            "added_at": datetime.now().isoformat(),
            "last_scanned": None,
            "scan_count": 0
        }
        
        targets = self.load_targets()
        
        # Check for duplicates
        for existing in targets:
            if existing["target"] == normalized_target:
                raise ValidationError(f"Target {normalized_target} already exists")
        
        targets.append(target_dict)
        self.save_targets(targets)
        
        return target_dict
    
    def remove_target(self, target_id: int) -> bool:
        """Remove a target by ID.
        
        Args:
            target_id: Target ID to remove
            
        Returns:
            True if removed, False if not found
        """
        targets = self.load_targets()
        original_count = len(targets)
        
        targets = [t for t in targets if t["id"] != target_id]
        
        if len(targets) < original_count:
            self.save_targets(targets)
            return True
        
        return False
    
    def update_scan_stats(self, target: str) -> None:
        """Update scan statistics for a target.
        
        Args:
            target: Target that was scanned
        """
        targets = self.load_targets()
        
        for target_dict in targets:
            if target_dict["target"] == target:
                target_dict["last_scanned"] = datetime.now().isoformat()
                target_dict["scan_count"] += 1
                break
        
        self.save_targets(targets)


class ScanHistory:
    """Manages scan history and results."""
    
    def __init__(self, history_dir: str = ".redops/history"):
        """Initialize scan history manager.
        
        Args:
            history_dir: Directory for scan history
        """
        self.history_dir = Path(history_dir)
        self.history_dir.mkdir(parents=True, exist_ok=True)
    
    def save_scan_result(self, target: str, result: Dict[str, Any]) -> str:
        """Save scan result to history.
        
        Args:
            target: Target that was scanned
            result: Scan result
            
        Returns:
            Path to saved result file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = target.replace("/", "_").replace(":", "_")
        filename = f"{timestamp}_{safe_target}.json"
        
        result_file = self.history_dir / filename
        
        # Add metadata
        result_with_meta = {
            "scan_metadata": {
                "target": target,
                "timestamp": datetime.now().isoformat(),
                "filename": filename
            },
            "result": result
        }
        
        with open(result_file, 'w') as f:
            json.dump(result_with_meta, f, indent=2, default=str)
        
        return str(result_file)
    
    def list_scans(self, target: Optional[str] = None, limit: int = 10) -> List[Dict[str, Any]]:
        """List recent scans.
        
        Args:
            target: Optional target filter
            limit: Maximum number of results
            
        Returns:
            List of scan metadata
        """
        scan_files = sorted(self.history_dir.glob("*.json"), reverse=True)
        scans = []
        
        for scan_file in scan_files[:limit * 2]:  # Get more to filter
            try:
                with open(scan_file, 'r') as f:
                    data = json.load(f)
                    scan_meta = data.get("scan_metadata", {})
                    
                    if target and scan_meta.get("target") != target:
                        continue
                    
                    scans.append({
                        "file": str(scan_file),
                        "target": scan_meta.get("target", "Unknown"),
                        "timestamp": scan_meta.get("timestamp", "Unknown"),
                        "success": data.get("result", {}).get("success", False)
                    })
                    
                    if len(scans) >= limit:
                        break
            
            except (json.JSONDecodeError, IOError):
                continue
        
        return scans
    
    def load_scan_result(self, filename: str) -> Optional[Dict[str, Any]]:
        """Load a specific scan result.
        
        Args:
            filename: Filename or path to scan result
            
        Returns:
            Scan result or None if not found
        """
        if "/" not in filename:
            result_file = self.history_dir / filename
        else:
            result_file = Path(filename)
        
        if not result_file.exists():
            return None
        
        try:
            with open(result_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return None


@click.group()
def target():
    """Target management commands."""
    pass


@target.command("add")
@click.argument("target")
@click.option("--name", "-n", help="Target name")
@click.option("--tag", "-t", multiple=True, help="Target tags")
def target_add(target: str, name: Optional[str], tag: tuple) -> None:
    """Add a target to the target list.
    
    TARGET can be an IP address, hostname, or CIDR range.
    
    Examples:
        redops target add 192.168.1.1 --name "Web Server"
        redops target add example.com --tag production --tag web
    """
    try:
        manager = TargetManager()
        target_dict = manager.add_target(target, name, list(tag))
        
        console.print(f"[green]✅ Target added successfully![/green]")
        console.print(f"ID: {target_dict['id']}")
        console.print(f"Target: {target_dict['target']}")
        console.print(f"Type: {target_dict['type']}")
        console.print(f"Name: {target_dict['name']}")
        if target_dict['tags']:
            console.print(f"Tags: {', '.join(target_dict['tags'])}")
    
    except ValidationError as e:
        console.print(f"[red]❌ Invalid target:[/red] {e.message}")
    except ConfigurationError as e:
        console.print(f"[red]❌ Configuration error:[/red] {e}")
    except Exception as e:
        console.print(f"[red]❌ Error adding target:[/red] {e}")


@target.command("list")
@click.option("--tag", "-t", help="Filter by tag")
@click.option("--type", "target_type", help="Filter by target type")
def target_list(tag: Optional[str], target_type: Optional[str]) -> None:
    """List all targets."""
    try:
        manager = TargetManager()
        targets = manager.load_targets()
        
        # Apply filters
        if tag:
            targets = [t for t in targets if tag in t.get("tags", [])]
        
        if target_type:
            targets = [t for t in targets if t.get("type") == target_type]
        
        if not targets:
            console.print("[yellow]No targets found.[/yellow]")
            return
        
        # Create table
        table = Table(title=f"Targets ({len(targets)} found)")
        table.add_column("ID", style="cyan")
        table.add_column("Name", style="green")
        table.add_column("Target", style="yellow")
        table.add_column("Type", style="magenta")
        table.add_column("Tags", style="blue")
        table.add_column("Scans", style="red")
        table.add_column("Last Scan", style="dim")
        
        for target_dict in targets:
            last_scan = target_dict.get("last_scanned")
            if last_scan:
                last_scan = datetime.fromisoformat(last_scan).strftime("%Y-%m-%d %H:%M")
            else:
                last_scan = "Never"
            
            table.add_row(
                str(target_dict["id"]),
                target_dict.get("name", "N/A"),
                target_dict["target"],
                target_dict["type"],
                ", ".join(target_dict.get("tags", [])),
                str(target_dict.get("scan_count", 0)),
                last_scan
            )
        
        console.print(table)
    
    except Exception as e:
        console.print(f"[red]❌ Error listing targets:[/red] {e}")


@target.command("remove")
@click.argument("target_id", type=int)
@click.option("--force", "-f", is_flag=True, help="Skip confirmation")
def target_remove(target_id: int, force: bool) -> None:
    """Remove a target by ID."""
    try:
        manager = TargetManager()
        targets = manager.load_targets()
        
        # Find target
        target_to_remove = None
        for target_dict in targets:
            if target_dict["id"] == target_id:
                target_to_remove = target_dict
                break
        
        if not target_to_remove:
            console.print(f"[red]❌ Target with ID {target_id} not found.[/red]")
            return
        
        # Confirm removal
        if not force:
            if not Confirm.ask(f"Remove target '{target_to_remove['name']}' ({target_to_remove['target']})?"):
                console.print("[yellow]Removal cancelled.[/yellow]")
                return
        
        # Remove target
        if manager.remove_target(target_id):
            console.print(f"[green]✅ Target removed successfully![/green]")
        else:
            console.print(f"[red]❌ Failed to remove target.[/red]")
    
    except Exception as e:
        console.print(f"[red]❌ Error removing target:[/red] {e}")


@click.group()
def history():
    """Scan history commands."""
    pass


@history.command("list")
@click.option("--target", "-t", help="Filter by target")
@click.option("--limit", "-l", type=int, default=10, help="Maximum results")
def history_list(target: Optional[str], limit: int) -> None:
    """List scan history."""
    try:
        history_manager = ScanHistory()
        scans = history_manager.list_scans(target, limit)
        
        if not scans:
            console.print("[yellow]No scan history found.[/yellow]")
            return
        
        # Create table
        table = Table(title=f"Scan History ({len(scans)} scans)")
        table.add_column("Target", style="cyan")
        table.add_column("Timestamp", style="green")
        table.add_column("Status", style="yellow")
        table.add_column("File", style="dim")
        
        for scan in scans:
            status = "✅ Success" if scan["success"] else "❌ Failed"
            timestamp = scan["timestamp"]
            if timestamp != "Unknown":
                try:
                    timestamp = datetime.fromisoformat(timestamp).strftime("%Y-%m-%d %H:%M:%S")
                except ValueError:
                    pass
            
            table.add_row(
                scan["target"],
                timestamp,
                status,
                Path(scan["file"]).name
            )
        
        console.print(table)
    
    except Exception as e:
        console.print(f"[red]❌ Error listing history:[/red] {e}")


@history.command("show")
@click.argument("filename")
@click.option("--format", "-f", 
              type=click.Choice(["table", "json", "summary"]),
              default="summary", help="Output format")
def history_show(filename: str, format: str) -> None:
    """Show details of a specific scan result."""
    try:
        history_manager = ScanHistory()
        scan_data = history_manager.load_scan_result(filename)
        
        if not scan_data:
            console.print(f"[red]❌ Scan result '{filename}' not found.[/red]")
            return
        
        result = scan_data.get("result", {})
        
        # Import display function from main module
        from .main import display_results
        display_results(result, format)
    
    except Exception as e:
        console.print(f"[red]❌ Error showing scan result:[/red] {e}")


@click.group()
def tools():
    """Tool management and testing commands."""
    pass


@tools.command("test")
@click.option("--tool", "-t", 
              type=click.Choice(["nmap", "all"]),
              default="all", help="Tool to test")
def tools_test(tool: str) -> None:
    """Test tool availability and functionality."""
    console.print("[bold]Testing tool availability...[/bold]\n")
    
    results = {}
    
    if tool in ["nmap", "all"]:
        results["nmap"] = _test_nmap()
    
    # Display results
    table = Table(title="Tool Test Results")
    table.add_column("Tool", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Version", style="yellow")
    table.add_column("Notes", style="dim")
    
    for tool_name, result in results.items():
        status = "✅ Available" if result["available"] else "❌ Not Available"
        table.add_row(
            tool_name.upper(),
            status,
            result.get("version", "Unknown"),
            result.get("notes", "")
        )
    
    console.print(table)
    
    # Show recommendations if any tools are missing
    missing_tools = [name for name, result in results.items() if not result["available"]]
    if missing_tools:
        console.print(f"\n[yellow]⚠️  Missing tools: {', '.join(missing_tools)}[/yellow]")
        console.print("[dim]Install missing tools for full functionality.[/dim]")


def _test_nmap() -> Dict[str, Any]:
    """Test Nmap availability.
    
    Returns:
        Test result dictionary
    """
    try:
        scanner = NmapScanner()
        scanner._verify_nmap()
        
        # Try to get version
        import subprocess
        result = subprocess.run(["nmap", "--version"], 
                              capture_output=True, text=True, timeout=10)
        
        version = "Unknown"
        if result.returncode == 0:
            lines = result.stdout.split("\n")
            for line in lines:
                if "Nmap version" in line:
                    version = line.split("version")[1].strip()
                    break
        
        return {
            "available": True,
            "version": version,
            "notes": "Ready for network scanning"
        }
    
    except Exception as e:
        return {
            "available": False,
            "version": "N/A",
            "notes": f"Error: {str(e)}"
        }


@tools.command("scan-test")
@click.option("--target", "-t", default="127.0.0.1", help="Test target")
def tools_scan_test(target: str) -> None:
    """Perform a test scan to verify tool functionality."""
    console.print(f"[bold]Performing test scan on {target}...[/bold]")
    
    try:
        # Validate target
        normalized_target, _ = validate_target(target)
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Running test scan...", total=None)
            
            # Create minimal config for test
            test_config = {
                "tools": {
                    "nmap": {
                        "path": "nmap",
                        "use_python_nmap": True,
                        "timing": 4  # Fast timing for test
                    }
                }
            }
            
            # Run test scan
            async def run_test():
                agent = ReconnaissanceAgent(test_config)
                return await agent.scan_single_host(
                    normalized_target, 
                    "quick", 
                    {"ports": "80,443,22", "timing": 4}
                )
            
            result = asyncio.run(run_test())
            
            progress.update(task, description="Test scan completed")
        
        # Display results
        console.print(f"\n[green]✅ Test scan completed successfully![/green]")
        console.print(f"Target: {result.target}")
        console.print(f"Scan Type: {result.scan_type}")
        console.print(f"Duration: {result.duration:.2f}s")
        console.print(f"Hosts Found: {len(result.hosts)}")
        console.print(f"Ports Found: {len(result.ports)}")
        console.print(f"Services Found: {len(result.services)}")
        
        if result.services:
            console.print("\n[bold]Services detected:[/bold]")
            for service in result.services[:5]:  # Show first 5
                console.print(f"  • {service.get('port', 'Unknown')}/{service.get('protocol', 'tcp')} - {service.get('service', 'Unknown')}")
    
    except ValidationError as e:
        console.print(f"[red]❌ Invalid target:[/red] {e.message}")
    except Exception as e:
        console.print(f"[red]❌ Test scan failed:[/red] {e}")
        console.print("[dim]Check tool installation and network connectivity.[/dim]")


@click.command()
@click.option("--config-file", "-c", help="Configuration file path")
@click.option("--interactive", "-i", is_flag=True, help="Interactive configuration")
def setup(config_file: Optional[str], interactive: bool) -> None:
    """Setup and configure RedOps-AI."""
    console.print("[bold]RedOps-AI Setup[/bold]\n")
    
    if interactive:
        _interactive_setup()
    else:
        _quick_setup(config_file)


def _interactive_setup() -> None:
    """Run interactive setup."""
    console.print("[green]Starting interactive setup...[/green]\n")
    
    # Get basic configuration
    config = {
        "application": {
            "name": "RedOps-AI",
            "version": "1.0.0",
            "debug": Confirm.ask("Enable debug mode?", default=False)
        },
        "agents": {
            "coordinator": {
                "max_iterations": int(Prompt.ask("Max workflow iterations", default="10")),
                "timeout": int(Prompt.ask("Agent timeout (seconds)", default="300"))
            },
            "reconnaissance": {
                "max_concurrent_scans": int(Prompt.ask("Max concurrent scans", default="5"))
            }
        },
        "tools": {
            "nmap": {
                "path": Prompt.ask("Nmap path", default="nmap"),
                "use_python_nmap": Confirm.ask("Use python-nmap library?", default=True),
                "timing": int(Prompt.ask("Default timing (0-5)", default="3"))
            }
        },
        "llm": {
            "provider": Prompt.ask("LLM provider", choices=["openai", "anthropic"], default="openai"),
            "model": Prompt.ask("Model name", default="gpt-4"),
            "temperature": float(Prompt.ask("Temperature (0.0-1.0)", default="0.1"))
        },
        "output": {
            "directory": Prompt.ask("Output directory", default="./results"),
            "format": Prompt.ask("Default format", choices=["json", "yaml", "xml"], default="json")
        },
        "security": {
            "rate_limit": int(Prompt.ask("Rate limit (requests/minute)", default="60")),
            "max_concurrent_scans": int(Prompt.ask("Max concurrent scans", default="5"))
        }
    }
    
    # Save configuration
    config_path = Path("config.yaml")
    try:
        save_config(config, config_path)
        console.print(f"\n[green]✅ Configuration saved to {config_path}[/green]")
    except Exception as e:
        console.print(f"\n[red]❌ Failed to save configuration:[/red] {e}")
        return
    
    # Test tools
    if Confirm.ask("\nTest tool availability?", default=True):
        from .main import cli
        ctx = click.Context(cli)
        ctx.obj = {"config": config}
        tools_test.invoke(ctx, tool="all")
    
    console.print("\n[green]🎉 Setup completed successfully![/green]")
    console.print("[dim]You can now run 'redops scan <target>' to start scanning.[/dim]")


def _quick_setup(config_file: Optional[str]) -> None:
    """Run quick setup with defaults."""
    console.print("[green]Running quick setup with defaults...[/green]\n")
    
    if config_file and Path(config_file).exists():
        console.print(f"[green]✅ Using existing configuration: {config_file}[/green]")
    else:
        # Create default config
        default_config = {
            "application": {
                "name": "RedOps-AI",
                "version": "1.0.0",
                "debug": False
            },
            "agents": {
                "coordinator": {
                    "max_iterations": 10,
                    "timeout": 300
                },
                "reconnaissance": {
                    "max_concurrent_scans": 5
                }
            },
            "tools": {
                "nmap": {
                    "path": "nmap",
                    "use_python_nmap": True,
                    "timing": 3
                }
            },
            "llm": {
                "provider": "openai",
                "model": "gpt-4",
                "temperature": 0.1
            },
            "output": {
                "directory": "./results",
                "format": "json"
            },
            "security": {
                "rate_limit": 60,
                "max_concurrent_scans": 5
            }
        }
        
        config_path = Path(config_file or "config.yaml")
        try:
            save_config(default_config, config_path)
            console.print(f"[green]✅ Default configuration created: {config_path}[/green]")
        except Exception as e:
            console.print(f"[red]❌ Failed to create configuration:[/red] {e}")
            return
    
    console.print("[green]🎉 Quick setup completed![/green]")
    console.print("[dim]Run 'redops setup --interactive' for custom configuration.[/dim]")


# Add commands to groups
target.add_command(target_add)
target.add_command(target_list)
target.add_command(target_remove)

history.add_command(history_list)
history.add_command(history_show)

tools.add_command(tools_test)
tools.add_command(tools_scan_test)