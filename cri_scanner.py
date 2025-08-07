#!/usr/bin/env python3
"""
cri_scanner.py
Main module for role injection security scanning.
"""
from __future__ import annotations
import logging

# Import scanner functionality
from tools.scanner import scan_raw_request

# Set up basic logging - will be overridden by logging_setup.py
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)

# Suppress verbose HTTP logs by default
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("openai").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)

# Re-export main scanning function
__all__ = ['scan_raw_request']