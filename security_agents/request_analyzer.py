"""Request Analyzer Agent for analyzing HTTP requests and identifying injection points."""
# Note: This file should be in security_agents/request_analyzer.py after renaming
from __future__ import annotations
import logging

from .agent_sdk import agent_runner
from models.pydantic_models import RequestAnalysis

logger = logging.getLogger(__name__)


async def analyze_request_with_gpt(raw_request: str) -> dict:
    """Analyze a raw HTTP request to identify injection points for role parameters."""
    analysis = await agent_runner.analyze_request(raw_request)
    agent_output = analysis.model_dump()
    logger.info("[AGENT OUTPUT] %s", agent_output)
    return agent_output