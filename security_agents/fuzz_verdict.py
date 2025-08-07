"""Fuzz Verdict Agent for analyzing role fuzzing results."""
# Note: This file should be in security_agents/fuzz_verdict.py after renaming
from __future__ import annotations
import logging
from typing import Any, Dict, Optional

from .base import BaseAgent
from .agent_sdk import agent_runner
from models.pydantic_models import FuzzingVerdict, HTTPResult

logger = logging.getLogger(__name__)


class FuzzVerdictAgent(BaseAgent):
    """Analyzes role fuzzing results to determine which roles are truly accepted."""
    
    async def run(self, all_results: Dict[str, HTTPResult], prevalidation_context: Optional[Dict[str, Any]] = None):
        """Run the verdict analysis using the agent SDK."""
        verdict = await agent_runner.analyze_fuzzing_results(all_results, prevalidation_context)
        return verdict.model_dump()