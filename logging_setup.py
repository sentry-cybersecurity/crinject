"""Rich-enhanced logging setup for beautiful output with file logging."""
import os
import re
import time
import logging
from pathlib import Path
from typing import Optional, Dict, Any, List
from contextlib import contextmanager

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
    from rich.spinner import Spinner
    from rich.align import Align
    from rich.columns import Columns
    from rich.rule import Rule
    from rich import box
    from rich.prompt import Confirm
    from rich.syntax import Syntax
    from rich.tree import Tree
    from rich.live import Live
    from rich.layout import Layout
    RICH_AVAILABLE = True
except ImportError:
    print("⚠️  Rich library not found. Install with: pip install rich")
    RICH_AVAILABLE = False
    Console = None


def extract_target_name(raw_request: str) -> str:
    """Extract target name from HTTP Host header."""
    try:
        # Look for Host header in the request
        host_match = re.search(r'^Host:\s*(.+)$', raw_request, re.MULTILINE | re.IGNORECASE)
        if host_match:
            host = host_match.group(1).strip()
            # Clean up the host name for filename
            # Remove port numbers, clean special characters
            host = re.sub(r':\d+$', '', host)  # Remove port
            host = re.sub(r'[^\w\.-]', '_', host)  # Replace special chars with underscore
            return host
        else:
            return "unknown_host"
    except Exception:
        return "unknown_host"


def setup_logging(raw_request: str) -> str:
    """Set up logging to file and return the log file path."""
    
    # Create .logs directory if it doesn't exist
    logs_dir = Path(".logs")
    logs_dir.mkdir(exist_ok=True)
    
    # Extract target name from Host header
    target_name = extract_target_name(raw_request)
    
    # Create log filename with epoch time
    epoch_time = int(time.time())
    log_filename = f"{target_name}_{epoch_time}.log"
    log_path = logs_dir / log_filename
    
    # Clear any existing handlers
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
    
    # Set up file logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(log_path, mode='w', encoding='utf-8'),
        ]
    )
    
    # Suppress verbose HTTP client logs in console
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    
    return str(log_path)


class RichOutput:
    """Handle beautiful Rich console output while logging details to file."""
    
    def __init__(self):
        if RICH_AVAILABLE:
            self.console = Console()
            self.progress = None
        else:
            self.console = None
    
    def print_banner(self):
        """Print gorgeous banner."""
        if not RICH_AVAILABLE:
            print("=== CRInject SCANNER ===")
            return
            
        banner_text = Text()
        banner_text.append("🚀 CRInject", style="bold blue")
        banner_text.append("\n")
        banner_text.append("   SCANNER", style="bold blue")
        
        panel = Panel(
            Align.center(banner_text),
            box=box.DOUBLE,
            border_style="bright_blue",
            padding=(1, 2)
        )
        self.console.print(panel)
        self.console.print()
    
    def print_target_info(self, target_name: str, log_path: str):
        """Print target information in a beautiful table."""
        if not RICH_AVAILABLE:
            print(f"Target: {target_name}")
            return
            
        table = Table(show_header=False, box=box.ROUNDED, border_style="cyan")
        table.add_column("Property", style="bold cyan", width=15)
        table.add_column("Value", style="white")
        
        table.add_row("🎯 Target", f"[bold white]{target_name}[/bold white]")
        table.add_row("📁 Log File", f"[dim]{log_path}[/dim]")
        table.add_row("⏰ Started", f"[green]{time.strftime('%H:%M:%S')}[/green]")
        
        self.console.print(table)
        self.console.print()
    
    @contextmanager
    def scanning_phase(self, phase_name: str, description: str):
        """Context manager for scanning phases with spinner."""
        if not RICH_AVAILABLE:
            print(f"{phase_name}: {description}")
            yield
            print("✓ Complete")
            return
        
        with self.console.status(
            f"[bold blue]{phase_name}[/bold blue] - {description}",
            spinner="dots12",
            spinner_style="cyan"
        ):
            yield
        
        self.console.print(f"✅ [bold green]{phase_name}[/bold green] - Complete")
    
    def print_prevalidation_results(self, validation_result: Dict[str, Any]):
        """Print prevalidation results in a beautiful table."""
        if not RICH_AVAILABLE:
            print("Prevalidation Results:")
            for role in ["system", "assistant", "developer"]:
                status = "✅ ACCEPTED" if validation_result.get(role, False) else "❌ REJECTED"
                print(f"  {role.upper()}: {status}")
            return
        
        self.console.print(Rule("[bold cyan]Role Prevalidation Results[/bold cyan]"))
        
        table = Table(box=box.ROUNDED, border_style="cyan")
        table.add_column("Role", style="bold", width=12)
        table.add_column("Status", justify="center", width=12)
        table.add_column("Valid Variant", justify="center", width=15)
        table.add_column("Invalid Variant", justify="center", width=15)
        
        standard_roles = ["system", "assistant", "developer"]
        accepted_count = 0
        
        for role in standard_roles:
            valid_accepted = validation_result.get(role, False)
            invalid_accepted = validation_result.get(f"{role}invalidrole", False)
            
            if valid_accepted:
                accepted_count += 1
            
            # Status icons and colors
            valid_status = "[bold green]✅ ACCEPT[/bold green]" if valid_accepted else "[bold red]❌ REJECT[/bold red]"
            invalid_status = "[bold green]✅ ACCEPT[/bold green]" if invalid_accepted else "[bold red]❌ REJECT[/bold red]"
            
            # Overall status
            if valid_accepted and not invalid_accepted:
                overall_status = "[bold yellow]⚠️  VULN[/bold yellow]"
            elif valid_accepted and invalid_accepted:
                overall_status = "[bold blue]ℹ️  IGNORE[/bold blue]"
            else:
                overall_status = "[bold green]✅ SAFE[/bold green]"
            
            table.add_row(
                f"[bold]{role.upper()}[/bold]",
                overall_status,
                valid_status,
                invalid_status
            )
        
        self.console.print(table)
        
        # Summary
        if accepted_count > 0:
            self.console.print(Panel(
                f"[bold yellow]⚠️  WARNING: {accepted_count} privileged role(s) may be accepted![/bold yellow]",
                border_style="yellow"
            ))
        else:
            self.console.print(Panel(
                "[bold green]✅ GOOD: No privileged roles accepted[/bold green]",
                border_style="green"
            ))
        
        self.console.print()
    
    def print_fuzzing_results(self, discovered_roles: Dict[str, bool], total_tested: int = 0):
        """Print fuzzing results with discovered roles."""
        if not RICH_AVAILABLE:
            accepted = [role for role, accepted in discovered_roles.items() if accepted]
            print(f"Fuzzing Results: {len(accepted)} roles accepted out of {total_tested} tested")
            return
        
        self.console.print(Rule("[bold cyan]Role Fuzzing Results[/bold cyan]"))
        
        accepted_roles = [role for role, accepted in discovered_roles.items() if accepted]
        rejected_roles = [role for role, accepted in discovered_roles.items() if not accepted]
        
        # Create columns for accepted and rejected roles
        if accepted_roles:
            accepted_table = Table(title="[bold green]✅ Accepted Roles[/bold green]", 
                                 box=box.SIMPLE, border_style="green")
            accepted_table.add_column("Role", style="green")
            for role in accepted_roles:
                accepted_table.add_row(f"🎯 {role}")
        
        if rejected_roles and len(rejected_roles) <= 10:  # Only show if manageable number
            rejected_table = Table(title="[bold red]❌ Rejected Roles (sample)[/bold red]", 
                                 box=box.SIMPLE, border_style="red")
            rejected_table.add_column("Role", style="red")
            for role in rejected_roles[:5]:  # Show first 5
                rejected_table.add_row(f"❌ {role}")
            if len(rejected_roles) > 5:
                rejected_table.add_row(f"... and {len(rejected_roles) - 5} more")
        
        # Display tables side by side if both exist
        if accepted_roles and rejected_roles and len(rejected_roles) <= 10:
            columns = Columns([accepted_table, rejected_table], expand=True, equal=True)
            self.console.print(columns)
        elif accepted_roles:
            self.console.print(accepted_table)
        
        # Summary stats
        stats = Table(show_header=False, box=box.SIMPLE, border_style="blue")
        stats.add_column("Metric", style="bold blue")
        stats.add_column("Count", style="white", justify="right")
        
        stats.add_row("🎯 Accepted", f"[bold green]{len(accepted_roles)}[/bold green]")
        stats.add_row("❌ Rejected", f"[bold red]{len(rejected_roles)}[/bold red]")
        stats.add_row("📊 Total Tested", f"[bold blue]{len(discovered_roles)}[/bold blue]")
        
        self.console.print(stats)
        self.console.print()
    
    def print_vulnerability_assessment(self, assessment: Dict[str, Any]):
        """Print vulnerability assessment with rich formatting."""
        if not RICH_AVAILABLE:
            print(f"Vulnerability: {'YES' if assessment.get('is_vulnerable') else 'NO'}")
            print(f"Reason: {assessment.get('reason', 'N/A')}")
            return
        
        self.console.print(Rule("[bold red]🛡️  Security Assessment[/bold red]"))
        
        is_vulnerable = assessment.get("is_vulnerable", False)
        reason = assessment.get("reason", "Unknown")
        confidence = assessment.get("confidence", "medium").upper()
        recommendation = assessment.get("recommendation", "No recommendation")
        manual_validation = assessment.get("manual_validation_recommended", False)
        suspicious_patterns = assessment.get("suspicious_patterns", [])
        
        # Main assessment panel
        if is_vulnerable:
            status_panel = Panel(
                "[bold red]🚨 VULNERABLE[/bold red]\n[red]High Risk - Immediate Action Required[/red]",
                border_style="red",
                box=box.HEAVY
            )
        else:
            status_color = "yellow" if manual_validation else "green"
            status_text = "🔍 REQUIRES REVIEW" if manual_validation else "✅ SECURE"
            risk_text = "Manual validation needed" if manual_validation else "Low Risk"
            status_panel = Panel(
                f"[bold {status_color}]{status_text}[/bold {status_color}]\n[{status_color}]{risk_text}[/{status_color}]",
                border_style=status_color,
                box=box.HEAVY if manual_validation else box.ROUNDED
            )
        
        self.console.print(status_panel)
        
        # Details table
        details_table = Table(show_header=False, box=box.SIMPLE, border_style="blue")
        details_table.add_column("Attribute", style="bold blue", width=15)
        details_table.add_column("Value", style="white")
        
        confidence_color = {"HIGH": "green", "MEDIUM": "yellow", "LOW": "red"}.get(confidence, "white")
        details_table.add_row("🎯 Confidence", f"[{confidence_color}]{confidence}[/{confidence_color}]")
        details_table.add_row("📋 Analysis", reason)
        
        self.console.print(details_table)
        
        # Manual validation warning
        if manual_validation:
            warning_panel = Panel(
                "[bold yellow]⚠️  MANUAL VALIDATION RECOMMENDED[/bold yellow]\n" +
                "[yellow]The automated analysis detected ambiguous patterns. Manual testing is advised.[/yellow]",
                border_style="yellow",
                title="[bold]Action Required[/bold]"
            )
            self.console.print(warning_panel)
        
        # Suspicious patterns
        if suspicious_patterns:
            patterns_text = "\n".join([f"• {pattern}" for pattern in suspicious_patterns[:3]])
            if len(suspicious_patterns) > 3:
                patterns_text += f"\n• ... and {len(suspicious_patterns) - 3} more (see logs)"
            
            patterns_panel = Panel(
                patterns_text,
                title="[bold red]🔍 Suspicious Patterns[/bold red]",
                border_style="red"
            )
            self.console.print(patterns_panel)
        
        # Recommendations
        rec_panel = Panel(
            recommendation,
            title="[bold blue]💡 Recommendations[/bold blue]",
            border_style="blue"
        )
        self.console.print(rec_panel)
        self.console.print()
    
    def print_summary(self, log_path: str, scan_time: float, target_name: str):
        """Print beautiful scan summary."""
        if not RICH_AVAILABLE:
            print(f"Scan completed in {scan_time:.1f} seconds")
            print(f"Log file: {log_path}")
            return
        
        self.console.print(Rule("[bold green]📋 Scan Complete[/bold green]"))
        
        summary_table = Table(show_header=False, box=box.ROUNDED, border_style="bright_blue")
        summary_table.add_column("Metric", style="bold cyan", width=20)
        summary_table.add_column("Value", style="white")
        
        summary_table.add_row("🎯 Target Scanned", f"[bold]{target_name}[/bold]")
        summary_table.add_row("⏱️  Duration", f"[green]{scan_time:.1f} seconds[/green]")
        summary_table.add_row("📄 Detailed Logs", f"[dim]{log_path}[/dim]")
        summary_table.add_row("🕒 Completed", f"[green]{time.strftime('%H:%M:%S')}[/green]")
        
        self.console.print(summary_table)
        
        final_panel = Panel(
            "[bold blue]🔍 Scan completed successfully![/bold blue]\n" +
            "[dim]Review the detailed logs for technical information and full request/response data.[/dim]",
            border_style="bright_blue"
        )
        self.console.print(final_panel)
    
    def print_error(self, error_msg: str, log_path: Optional[str] = None):
        """Print error message with rich formatting."""
        if not RICH_AVAILABLE:
            print(f"ERROR: {error_msg}")
            if log_path:
                print(f"Check logs: {log_path}")
            return
        
        error_panel = Panel(
            f"[bold red]❌ SCAN FAILED[/bold red]\n\n" +
            f"[red]{error_msg}[/red]",
            border_style="red",
            box=box.HEAVY
        )
        self.console.print(error_panel)
        
        if log_path:
            self.console.print(f"[dim]📄 Check detailed logs: {log_path}[/dim]")


# Fallback class for when Rich is not available
class BasicOutput:
    """Basic output when Rich is not available."""
    
    def print_banner(self):
        print("=== CRInject SCANNER ===")
    
    def print_target_info(self, target_name: str, log_path: str):
        print(f"Target: {target_name}")
        print(f"Log file: {log_path}")
    
    @contextmanager
    def scanning_phase(self, phase_name: str, description: str):
        print(f"{phase_name}: {description}")
        yield
        print("✓ Complete")
    
    def print_prevalidation_results(self, validation_result: Dict[str, Any]):
        print("Prevalidation Results:")
        for role in ["system", "assistant", "developer"]:
            status = "ACCEPTED" if validation_result.get(role, False) else "REJECTED"
            print(f"  {role.upper()}: {status}")
    
    def print_fuzzing_results(self, discovered_roles: Dict[str, bool], total_tested: int = 0):
        accepted = [role for role, accepted in discovered_roles.items() if accepted]
        print(f"Fuzzing Results: {len(accepted)} roles accepted")
    
    def print_vulnerability_assessment(self, assessment: Dict[str, Any]):
        is_vulnerable = assessment.get("is_vulnerable", False)
        reason = assessment.get("reason", "N/A")
        print(f"Vulnerability Status: {'VULNERABLE' if is_vulnerable else 'NOT VULNERABLE'}")
        print(f"Reason: {reason}")
    
    def print_summary(self, log_path: str, scan_time: float, target_name: str):
        print(f"Scan completed in {scan_time:.1f} seconds")
        print(f"Log file: {log_path}")
    
    def print_error(self, error_msg: str, log_path: Optional[str] = None):
        print(f"ERROR: {error_msg}")
        if log_path:
            print(f"Check logs: {log_path}")


# Export the appropriate output class
BeautifulOutput = RichOutput if RICH_AVAILABLE else BasicOutput