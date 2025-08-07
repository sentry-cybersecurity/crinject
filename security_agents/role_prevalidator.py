"""Role Prevalidator Agent for testing standard privileged roles."""
from __future__ import annotations
import json
import logging
from typing import Any, Dict, Optional
import httpx

from .base import BaseAgent
from .agent_sdk import agent_runner
from models.pydantic_models import RoleValidation, HTTPResult, VALID_ROLES, INVALID_ROLES

logger = logging.getLogger(__name__)


class RolePrevalidator(BaseAgent):
    """Send minimal requests with role variations and decide if we should proceed."""

    async def run(self, url: str, minimal_body: Dict[str, Any], headers_from_request: Dict[str, str]):
        results: Dict[str, HTTPResult] = {}
        
        for role in VALID_ROLES + INVALID_ROLES:
            payload = json.dumps(self.insert_role(minimal_body, role))
            try:
                resp = await self.client.post(
                    url,
                    content=payload,
                    headers={"Content-Type": headers_from_request.get("Content-Type", "application/json")},
                    timeout=self.TIMEOUT,
                )
                text = resp.text
                status = resp.status_code
                logger.info(f"[Prevalidate] role={role}, status={status}, body[:500]={text[:500]}")
                results[role] = HTTPResult(status=status, body=text[:1000])
            except Exception as exc:
                logger.warning(f"[Prevalidate] Error for role={role}: {exc}")
                results[role] = HTTPResult(status="error", body=str(exc))

        # Use the agent SDK to analyze results
        validation = await agent_runner.analyze_prevalidation_results(results)
        
        # Return combined result
        return {
            **validation.model_dump(),
            "raw_results": {k: v.model_dump() for k, v in results.items()}
        }

    @staticmethod
    def insert_role(body, role):
        import copy

        new_body = copy.deepcopy(body)
        found = False
        if "messages" in new_body:
            for m in new_body["messages"]:
                if m.get("role") == "*" or m.get("role") == "user":
                    m["role"] = role
                    found = True
                    break
        elif "input" in new_body:
            for m in new_body["input"]:
                if m.get("role") == "*" or m.get("role") == "user":
                    m["role"] = role
                    found = True
                    break
        if not found:
            # fallback
            if "messages" in new_body and new_body["messages"]:
                new_body["messages"][0]["role"] = role
            elif "input" in new_body and new_body["input"]:
                new_body["input"][0]["role"] = role
        return new_body