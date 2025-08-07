"""Role Fuzz Agent for discovering non-standard role names."""
# Note: This file should be in security_agents/role_fuzz.py after renaming
from __future__ import annotations
import asyncio
import json
import logging
from typing import Any, Dict, List, Optional, Tuple, Union
import httpx

from .base import BaseAgent
from .agent_sdk import agent_runner
from .role_prevalidator import RolePrevalidator
from models.pydantic_models import HTTPResult, FuzzingVerdict

logger = logging.getLogger(__name__)


class RoleFuzzAgent(BaseAgent):
    """Discover non‑standard role names accepted by the target API."""

    def __init__(self, client: httpx.AsyncClient, max_rounds: int = 2, prevalidation_results: Optional[Dict[str, Any]] = None):
        super().__init__(client)
        self.max_rounds = max_rounds
        self.prevalidation_results = prevalidation_results

    async def _gen_roles(self, template_body: Dict[str, Any], tried: List[str], ctx_note: str | None = None, all_http_history: Dict[str, Union[HTTPResult, Dict[str, Any]]] = None) -> List[str]:
        """Ask agent SDK for a fresh set of role names."""
        return await agent_runner.generate_fuzz_roles(
            template_body=template_body,
            tried=tried,
            context=ctx_note,
            history=all_http_history
        )

    async def _probe_roles(self, url: str, body_tmpl: Dict[str, Any], roles: List[str], headers_from_request: Dict[str, str]) -> Dict[str, HTTPResult]:
        """Send the role‑variant payloads and collect HTTP responses."""
        results: Dict[str, HTTPResult] = {}
        tasks: List[Tuple[str, asyncio.Task]] = []
        
        for role in roles:
            payload = json.dumps(RolePrevalidator.insert_role(body_tmpl, role))
            task = asyncio.create_task(self.client.post(
                url,
                content=payload,
                headers={"Content-Type": headers_from_request.get("Content-Type", "application/json")},
                timeout=self.TIMEOUT,
            ))
            tasks.append((role, task))

        for role, task in tasks:
            try:
                resp = await task
                results[role] = HTTPResult(status=resp.status_code, body=resp.text[:1000])
                logger.info("[RoleFuzz] role=%s, status=%s", role, resp.status_code)
            except Exception as exc:
                logger.warning("[RoleFuzz] Request error for role %s: %s", role, exc)
                results[role] = HTTPResult(status="error", body=str(exc))
        return results

    async def run(self, url: str, body_template: Dict[str, Any], headers_from_request: Dict[str, str]):
        tried: List[str] = []
        all_results: Dict[str, Union[HTTPResult, Dict[str, Any]]] = {}
        ctx_note: str | None = None

        for round_no in range(1, self.max_rounds + 1):
            logger.info("[RoleFuzz] === Round %d/%d ===", round_no, self.max_rounds)
            new_roles = await self._gen_roles(body_template, tried, ctx_note, all_results)
            if not new_roles:
                logger.info("[RoleFuzz] No new roles generated; stopping.")
                break

            probe_results = await self._probe_roles(url, body_template, new_roles, headers_from_request)
            all_results.update(probe_results)
            tried.extend(new_roles)

            # Build context note from newest results for next generation step
            ctx_lines = []
            for r in new_roles:
                if r in probe_results:
                    result = probe_results[r]
                    if isinstance(result, HTTPResult):
                        ctx_lines.append(f"{r}: {result.status}")
                    else:
                        ctx_lines.append(f"{r}: unknown")
            ctx_note = "\n".join(ctx_lines)

        # Use the agent SDK to analyze results
        verdict = await agent_runner.analyze_fuzzing_results(all_results, self.prevalidation_results)
        
        # Build the final verdict map
        verdict_map: Dict[str, Any] = {}
        
        # Add individual role verdicts
        for role_info in verdict.roles:
            role_name = role_info.role_name
            verdict_map[role_name] = role_info.accepted
            # Store the detailed verdict info
            verdict_map[f"{role_name}_details"] = {
                "confidence": role_info.confidence.value,
                "reasoning": role_info.reasoning
            }
        
        # Add overall verdict and security implications
        verdict_map["verdict"] = verdict.overall_verdict
        verdict_map["security_implications"] = verdict.security_implications
        
        logger.info("[RoleFuzz] Verdict: %s", verdict_map.get("verdict"))
        return verdict_map