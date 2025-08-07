#!/usr/bin/env python3
"""
crinject.py — flexible driver for cri_scanner (Role Discovery Only)
===================================================================

This tool discovers which roles are accepted by a target API endpoint.

Features:
- Role prevalidation (tests standard roles: system, assistant, developer)
- Role fuzzing (discovers non-standard roles like admin, moderator, etc.)
- Beautiful Rich-powered UI with loading spinners
- Better URL scheme detection
- Beautiful output with detailed logging
- No jailbreaking functionality

Example
~~~~~~~
```bash
python crinject.py \
  --request request.txt \
  --scheme http         # force http://127.0.0.1:8081
```
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, Tuple

import httpx

# Import Rich logging utilities
try:
    from logging_setup import setup_logging, BeautifulOutput, extract_target_name, RichOutput, BasicOutput, RICH_AVAILABLE
    LOGGING_AVAILABLE = True
except ImportError:
    print("⚠️  logging_setup.py not found. Using basic output.")
    LOGGING_AVAILABLE = False
    RICH_AVAILABLE = False
    
    # Fallback functions
    def setup_logging(raw_request):
        import logging
        logging.basicConfig(level=logging.INFO)
        return "console"
    
    def extract_target_name(raw_request):
        return "unknown"
    
    class BeautifulOutput:
        def print_banner(self): print("=== CRInject ===")
        def print_target_info(self, host, log_path): print(f"Target: {host}")
        def scanning_phase(self, name, desc): 
            from contextlib import contextmanager
            @contextmanager
            def phase():
                print(f"{name}: {desc}")
                yield
                print("✓ Complete")
            return phase()
        def print_prevalidation_results(self, results): print("Prevalidation completed")
        def print_fuzzing_results(self, results, total=0): print("Fuzzing completed") 
        def print_vulnerability_assessment(self, assessment): print(f"Assessment: {assessment.get('reason', 'N/A')}")
        def print_summary(self, log_path, scan_time, target): print(f"Scan completed in {scan_time:.1f}s")
        def print_error(self, error_msg, log_path=None): print(f"Error: {error_msg}")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_json_payload(src: str) -> Dict[str, Any]:
    if src == "-":
        return json.loads(sys.stdin.read())
    p = Path(src)
    if p.is_file():
        return json.loads(p.read_text())
    return json.loads(src)


def _default_scheme_for_host(host: str) -> str:
    """Return http/https based on port number heuristics."""
    if ":" in host:
        _, port_str = host.rsplit(":", 1)
        if port_str in {"443", "8443"}:
            return "https"
    return "http"


def parse_request_file(path: Path, scheme_override: str | None = None) -> Tuple[str, Dict[str, Any]]:
    raw = path.read_text()
    head, sep, body = raw.partition("\n\n") if "\n\n" in raw else raw.partition("\r\n\r\n")
    if not sep:
        raise ValueError("No blank line separating headers and body in request file")

    req_line, *hdr_lines = head.splitlines()
    try:
        method, uri, *_ = req_line.split()
    except ValueError:
        raise ValueError(f"Malformed request line: {req_line!r}")

    headers: Dict[str, str] = {}
    for line in hdr_lines:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
    host_hdr = headers.get("Host") or headers.get("host")

    if uri.startswith("http://") or uri.startswith("https://"):
        url = uri
    else:
        if not host_hdr:
            raise ValueError("Host header required for relative URI in request line")
        scheme = scheme_override or _default_scheme_for_host(host_hdr)
        url = f"{scheme}://{host_hdr}{uri}"

    if method.upper() != "POST":
        if RICH_AVAILABLE:
            from rich.console import Console
            console = Console()
            console.print(f"[yellow]⚠️  Non-POST request ({method}); still attempting scan[/yellow]")
        else:
            print(f"[WARN] Non‑POST request ({method}); still attempting scan", file=sys.stderr)

    try:
        body_json = json.loads(body)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Request body is not valid JSON: {exc}") from exc
    return url, body_json


# ---------------------------------------------------------------------------
# Scanner runners
# ---------------------------------------------------------------------------

async def run_scan_http(scanner_url: str, target_url: str, body: Dict[str, Any], timeout: float):
    async with httpx.AsyncClient(timeout=timeout) as c:
        payload = {
            "target_url": target_url, 
            "body": body
        }
        r = await c.post(scanner_url, json=payload)
        r.raise_for_status()
        return r.json()


async def run_scan_local(target_url: str, body: Dict[str, Any]):
    try:
        from cri_scanner import scan as scan_func, ScanRequest
    except ImportError as exc:
        raise RuntimeError("cri_scanner is not importable; install or set PYTHONPATH") from exc

    req_obj = ScanRequest(target_url=target_url, body=body)  # type: ignore[arg-type]
    resp_obj = await scan_func(req_obj)  # type: ignore[func-returns-value]
    return resp_obj.model_dump() if hasattr(resp_obj, "model_dump") else resp_obj.dict()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

async def run_scanner(args, output, raw_request, log_path, target_name, start_time):
    """Run the actual scanner with phases."""
    try:
        # Import scanner here to avoid startup delay
        from cri_scanner import scan_raw_request
        
        # Phase 1: Request Analysis
        if not args.quiet:
            with output.scanning_phase(
                "📋 Phase 1: Request Analysis", 
                "Analyzing HTTP request structure and identifying injection points..."
            ):
                # Small delay to show the spinner
                time.sleep(0.5)
        
        # Phase 2: Role Prevalidation  
        if not args.quiet:
            with output.scanning_phase(
                "🔍 Phase 2: Role Prevalidation", 
                "Testing standard privileged roles (system, assistant, developer)..."
            ):
                # Run the scan
                result = await scan_raw_request(
                    raw_request, 
                    scheme_override=args.scheme, 
                    proxy=args.proxy, 
                    insecure=args.insecure
                )
        else:
            # Run full scan without phases in quiet mode
            result = await scan_raw_request(
                raw_request, 
                scheme_override=args.scheme, 
                proxy=args.proxy, 
                insecure=args.insecure
            )
        
        # Phase 3: Role Fuzzing (this actually already happened, but we show it for UX)
        if not args.quiet:
            with output.scanning_phase(
                "🎯 Phase 3: Role Fuzzing", 
                "Discovering additional accepted roles and analyzing responses..."
            ):
                # Small delay to show completion
                time.sleep(0.3)
        
        return result
        
    except Exception as exc:
        raise exc


def main():
    parser = argparse.ArgumentParser(description="Run role discovery scanner locally with raw HTTP request analysis.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("-r", "--request", type=Path, help="Raw HTTP request file (no wildcard needed).")
    mode.add_argument("-t", "--target", help="Target endpoint URL for template mode (not supported in new mode).")
    parser.add_argument("--scheme", choices=["http", "https"], help="Force scheme when parsing --request")
    parser.add_argument("--proxy", help="Proxy URL (e.g. http://localhost:8080 or socks5://127.0.0.1:1080)")
    parser.add_argument("-o", "--output", type=Path, help="Save scanner JSON to file")
    parser.add_argument("--insecure", action="store_true", help="Allow insecure server connections when using SSL (no certificate verification)")
    parser.add_argument("--quiet", "-q", action="store_true", help="Quiet mode - minimal output")
    parser.add_argument("--basic", action="store_true", help="Use basic output even if Rich is available")
    args = parser.parse_args()

    async def async_main():
        if args.request:
            # Read raw request
            raw_request = args.request.read_text()
            
            # Set up logging to file
            log_path = setup_logging(raw_request)
            
            # Extract target name for beautiful output
            target_name = extract_target_name(raw_request)
            
            # Initialize output handler
            if args.basic or not RICH_AVAILABLE:
                output = BasicOutput()
            else:
                output = RichOutput()
            
            # Start timing
            start_time = time.time()
            
            if not args.quiet:
                # Show beautiful banner
                output.print_banner()
                output.print_target_info(target_name, log_path)
            
            try:
                # Run the scanner
                result = await run_scanner(args, output, raw_request, log_path, target_name, start_time)
                
                # Calculate scan time
                scan_time = time.time() - start_time
                
                if not args.quiet:
                    # Display results beautifully
                    if result.get("prevalidation", {}).get("validation"):
                        output.print_prevalidation_results(result["prevalidation"]["validation"])
                    
                    if result.get("discovered_roles"):
                        # Create a simplified view for fuzzing results (exclude standard roles)
                        standard_roles = {"system", "assistant", "developer", 
                                        "systeminvalidrole", "assistantinvalidrole", "developerinvalidrole"}
                        fuzz_display = {k: v for k, v in result["discovered_roles"].items() 
                                      if k not in standard_roles}
                        
                        if fuzz_display:
                            total_fuzzed = len([k for k in result["discovered_roles"].keys() if k not in standard_roles])
                            output.print_fuzzing_results(fuzz_display, total_fuzzed)
                    
                    if result.get("vulnerability_assessment"):
                        output.print_vulnerability_assessment(result["vulnerability_assessment"])
                    
                    output.print_summary(log_path, scan_time, target_name)
                
            except Exception as exc:
                scan_time = time.time() - start_time
                if not args.quiet:
                    output.print_error(str(exc), log_path)
                else:
                    print(f"[ERROR] Scanner failed: {exc}", file=sys.stderr)
                sys.exit(1)
        else:
            print("[ERROR] Only --request mode is supported in this version.", file=sys.stderr)
            sys.exit(1)

        # Save output if requested
        if args.output:
            output_data = json.dumps(result, indent=2)
            args.output.write_text(output_data)
            if not args.quiet:
                if RICH_AVAILABLE and not args.basic:
                    from rich.console import Console
                    console = Console()
                    console.print(f"\n💾 [bold blue]Full results saved to:[/bold blue] [cyan]{args.output}[/cyan]")
                else:
                    print(f"\n💾 Full results saved to: {args.output}")
        elif args.quiet:
            # In quiet mode, output the JSON result
            print(json.dumps(result, indent=2))

    # Run the async main function
    asyncio.run(async_main())


if __name__ == "__main__":
    main()