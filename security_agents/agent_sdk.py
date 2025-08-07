"""OpenAI Agents SDK implementation for security scanning."""
# Note: This file should be in security_agents/agent_sdk.py after renaming
from __future__ import annotations
import logging
from typing import Dict, Any, List, Optional, Union
from agents import Agent, Runner  # OpenAI Agents SDK (NOT the local package)
from pydantic import BaseModel

from models.pydantic_models import (
    RoleValidation,
    FuzzingVerdict,
    RoleFuzzList,
    RequestAnalysis,
    HTTPResult,
    VALID_ROLES,
    INVALID_ROLES
)
from prompts.prompts import (
    ROLE_PREVALIDATION_PROMPT,
    FUZZ_VERDICT_PROMPT,
    ROLE_GENERATION_PROMPT,
    INJECTION_ANALYSIS_PROMPT
)
from tools.config import OPENAI_MODEL

logger = logging.getLogger(__name__)


# Define all agents using OpenAI Agents SDK
role_prevalidator_agent = Agent(
    name="Role Prevalidator",
    instructions=ROLE_PREVALIDATION_PROMPT,
    output_type=RoleValidation,
    model=OPENAI_MODEL  # Use configured model
)

fuzz_verdict_agent = Agent(
    name="Fuzz Verdict Analyzer",
    instructions=FUZZ_VERDICT_PROMPT,
    output_type=FuzzingVerdict,
    model=OPENAI_MODEL  # Use configured model
)

role_generator_agent = Agent(
    name="Role Generator",
    instructions=ROLE_GENERATION_PROMPT,
    output_type=RoleFuzzList,
    model=OPENAI_MODEL  # Use configured model
)

request_analyzer_agent = Agent(
    name="Request Analyzer",
    instructions=INJECTION_ANALYSIS_PROMPT,
    output_type=RequestAnalysis,
    model=OPENAI_MODEL  # Use configured model
)


class SecurityAgentRunner:
    """Centralized runner for security scanning agents."""
    
    def __init__(self):
        self.agents = {
            "prevalidator": role_prevalidator_agent,
            "verdict": fuzz_verdict_agent,
            "generator": role_generator_agent,
            "analyzer": request_analyzer_agent
        }
    
    async def analyze_prevalidation_results(self, results: Dict[str, Union[HTTPResult, Dict[str, Any]]]) -> RoleValidation:
        """Analyze prevalidation results using the agent."""
        # Build prompt
        prompt_parts = ["Below are the HTTP responses for each role variant:\n"]
        for role, info in results.items():
            # Handle both HTTPResult objects and plain dicts
            if isinstance(info, HTTPResult):
                status = info.status
                body = info.body
            elif isinstance(info, dict):
                status = info.get('status', 'unknown')
                body = info.get('body', '')
            else:
                status = 'unknown'
                body = str(info)
            
            prompt_parts.append(
                f"\nROLE: {role}\nStatus: {status}\nResponse: {body}\n"
            )
        prompt_parts.append("\n\nAnalyze and answer as per system instructions.")
        
        try:
            result = await Runner.run(
                self.agents["prevalidator"],
                "\n".join(prompt_parts)
            )
            return result.final_output
        except Exception as e:
            logger.error(f"Prevalidation analysis failed: {e}")
            # Return fallback response
            return RoleValidation(
                system=False,
                systeminvalidrole=False,
                assistant=False,
                assistantinvalidrole=False,
                developer=False,
                developerinvalidrole=False,
                verdict=f"Analysis failed: {str(e)}"
            )
    
    async def analyze_fuzzing_results(
        self,
        all_results: Dict[str, Union[HTTPResult, Dict[str, Any]]],
        prevalidation_context: Optional[Dict[str, Any]] = None
    ) -> FuzzingVerdict:
        """Analyze fuzzing results using the verdict agent."""
        # Build analysis prompt
        analysis_parts = ["Role Testing Results:\n"]
        
        for role, result in all_results.items():
            # Handle both HTTPResult objects and plain dicts
            if isinstance(result, HTTPResult):
                status = result.status
                body = result.body[:500]
            elif isinstance(result, dict):
                status = result.get('status', 'unknown')
                body = result.get('body', '')[:500]
            else:
                status = 'unknown'
                body = str(result)[:500]
                
            analysis_parts.append(f"\nRole: {role}")
            analysis_parts.append(f"Status: {status}")
            analysis_parts.append(f"Response body (first 500 chars): {body}")
            analysis_parts.append("-" * 40)
        
        if prevalidation_context and prevalidation_context.get("raw_results"):
            analysis_parts.append("\n\nContext from Standard Role Testing:")
            for role, result in prevalidation_context["raw_results"].items():
                if role in ["system", "assistant", "developer"]:
                    # Handle both HTTPResult and dict
                    if isinstance(result, HTTPResult):
                        status = result.status
                        body = result.body[:200]
                    elif isinstance(result, dict):
                        status = result.get('status', 'unknown')
                        body = result.get('body', '')[:200]
                    else:
                        status = 'unknown'
                        body = str(result)[:200]
                        
                    analysis_parts.append(
                        f"\n{role}: Status={status}, Body={body}"
                    )
        
        user_content = "\n".join(analysis_parts)
        
        try:
            result = await Runner.run(
                self.agents["verdict"],
                user_content
            )
            return result.final_output
        except Exception as e:
            logger.error(f"Verdict analysis failed: {e}")
            # Return fallback response
            return FuzzingVerdict(
                roles=[],
                overall_verdict="Analysis error occurred",
                security_implications="Manual review required due to analysis failure."
            )
    
    async def generate_fuzz_roles(
        self,
        template_body: Dict[str, Any],
        tried: List[str],
        context: Optional[str] = None,
        history: Optional[Dict[str, Union[HTTPResult, Dict[str, Any]]]] = None
    ) -> List[str]:
        """Generate new role names for fuzzing."""
        # Build prompt
        prompt_parts = [
            "JSON template (truncated if long):",
            str(template_body)[:1500],
            "\nAlready tried roles:",
            ", ".join(tried) or "<none>",
        ]
        
        if history:
            prompt_parts.extend([
                "\n\n=== FUZZING HISTORY ===",
                "Previous fuzzing attempts in this session:"
            ])
            for role, result in history.items():
                # Handle both HTTPResult and dict
                if isinstance(result, HTTPResult):
                    status = result.status
                    body = result.body[:500]
                elif isinstance(result, dict):
                    status = result.get('status', 'unknown')
                    body = result.get('body', '')[:500]
                else:
                    status = 'unknown'
                    body = str(result)[:500]
                    
                prompt_parts.extend([
                    f"\nRole: {role}",
                    f"Status: {status}",
                    f"Response snippet: {body}"
                ])
        
        if context:
            prompt_parts.append(f"\nContext from previous attempt:\n{context[:1500]}")
        
        prompt_parts.extend([
            "\n\nAnalyze the responses above. Look for:",
            "- Error messages that might reveal valid role names",
            "- Lists of acceptable roles in error responses",
            "- Patterns in which roles are accepted vs rejected",
            "- Any hints about the API's role validation logic"
        ])
        
        try:
            result = await Runner.run(
                self.agents["generator"],
                "\n".join(prompt_parts)
            )
            return result.final_output.roles
        except Exception as e:
            logger.error(f"Role generation failed: {e}")
            # Return static fallback roles
            static_roles = [
                "admin", "moderator", "sysadmin", "root", "owner", "superuser",
                "devops", "support", "policy", "system2", "assistant2", "beta-tester",
                "randomrole123", "nonexistentrole", "fakeroletesting"
            ]
            return [r for r in static_roles if r not in tried][:10]
    
    async def analyze_request(self, raw_request: str) -> RequestAnalysis:
        """Analyze HTTP request to identify injection points."""
        try:
            result = await Runner.run(
                self.agents["analyzer"],
                raw_request
            )
            return result.final_output
        except Exception as e:
            logger.error(f"Request analysis failed: {e}")
            raise RuntimeError(f"Request analysis failed: {str(e)}")
    
    # Synchronous versions for compatibility
    def analyze_prevalidation_results_sync(self, results: Dict[str, Union[HTTPResult, Dict[str, Any]]]) -> RoleValidation:
        """Synchronous version of analyze_prevalidation_results."""
        prompt_parts = ["Below are the HTTP responses for each role variant:\n"]
        for role, info in results.items():
            # Handle both HTTPResult objects and plain dicts
            if isinstance(info, HTTPResult):
                status = info.status
                body = info.body
            elif isinstance(info, dict):
                status = info.get('status', 'unknown')
                body = info.get('body', '')
            else:
                status = 'unknown'
                body = str(info)
                
            prompt_parts.append(
                f"\nROLE: {role}\nStatus: {status}\nResponse: {body}\n"
            )
        prompt_parts.append("\n\nAnalyze and answer as per system instructions.")
        
        try:
            result = Runner.run_sync(
                self.agents["prevalidator"],
                "\n".join(prompt_parts)
            )
            return result.final_output
        except Exception as e:
            logger.error(f"Prevalidation analysis failed: {e}")
            return RoleValidation(
                system=False,
                systeminvalidrole=False,
                assistant=False,
                assistantinvalidrole=False,
                developer=False,
                developerinvalidrole=False,
                verdict=f"Analysis failed: {str(e)}"
            )
    
    def analyze_request_sync(self, raw_request: str) -> RequestAnalysis:
        """Synchronous version of analyze_request."""
        try:
            result = Runner.run_sync(
                self.agents["analyzer"],
                raw_request
            )
            return result.final_output
        except Exception as e:
            logger.error(f"Request analysis failed: {e}")
            raise RuntimeError(f"Request analysis failed: {str(e)}")


# Global agent runner instance
agent_runner = SecurityAgentRunner()