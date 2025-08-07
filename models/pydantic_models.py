"""Pydantic models for structured outputs."""
from __future__ import annotations
from pydantic import BaseModel, Field
from typing import List, Optional, Literal, Dict, Any, Union
from enum import Enum


# Constants
VALID_ROLES = ["system", "assistant", "developer"]
INVALID_ROLES = [r + "invalidrole" for r in VALID_ROLES]


class ConfidenceLevel(str, Enum):
    """Confidence levels for analysis."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# Role Prevalidation Models
class RoleValidation(BaseModel):
    """Individual role validation result."""
    system: bool = Field(description="Whether 'system' role is accepted")
    systeminvalidrole: bool = Field(description="Whether 'systeminvalidrole' is accepted")
    assistant: bool = Field(description="Whether 'assistant' role is accepted")
    assistantinvalidrole: bool = Field(description="Whether 'assistantinvalidrole' is accepted")
    developer: bool = Field(description="Whether 'developer' role is accepted")
    developerinvalidrole: bool = Field(description="Whether 'developerinvalidrole' is accepted")
    verdict: str = Field(description="Overall assessment of role validation behavior")


# Fuzzing Models
class RoleVerdict(BaseModel):
    """Verdict for a single role."""
    role_name: str = Field(description="Name of the tested role")
    accepted: bool = Field(description="Whether the role was accepted by the API")
    confidence: ConfidenceLevel = Field(description="Confidence level of the verdict")
    reasoning: str = Field(description="Explanation for the verdict")


class FuzzingVerdict(BaseModel):
    """Complete fuzzing analysis verdict."""
    roles: List[RoleVerdict] = Field(description="Individual role verdicts")
    overall_verdict: str = Field(description="Overall security assessment")
    security_implications: str = Field(description="Security implications of findings")


class RoleFuzzList(BaseModel):
    """List of roles to fuzz."""
    roles: List[str] = Field(
        description="New candidate role names to test",
        min_items=1,
        max_items=20
    )


# Request Analysis Models
class InjectionPoint(BaseModel):
    """Identified injection point in request."""
    path: str = Field(description="Path to injection point (e.g., 'messages[0].role')")
    parameter_type: Literal["json", "form", "query", "header", "multipart"] = Field(
        description="Type of parameter"
    )


class RequestAnalysis(BaseModel):
    """Analysis of HTTP request for role injection."""
    content_type: str = Field(description="Content-Type of the request")
    injection_points: List[InjectionPoint] = Field(description="Identified injection points")
    body_with_wildcard: str = Field(description="Request body with '*' at injection points")
    notes: str = Field(description="Additional notes about the analysis")


# Scan Results Models
class HTTPResult(BaseModel):
    """HTTP response information."""
    status: int | str = Field(description="HTTP status code or 'error'")
    body: str = Field(description="Response body (truncated)")


class PrevalidationResult(BaseModel):
    """Results from role prevalidation phase."""
    validation: RoleValidation
    raw_results: Dict[str, HTTPResult] = Field(description="Raw HTTP responses for each role")


class VulnerabilityAssessment(BaseModel):
    """Security vulnerability assessment."""
    is_vulnerable: bool = Field(description="Whether a vulnerability exists")
    reason: str = Field(description="Explanation of the assessment")
    confidence: ConfidenceLevel = Field(description="Confidence in the assessment")
    recommendation: str = Field(description="Recommended actions")
    manual_validation_recommended: bool = Field(
        description="Whether manual validation is recommended due to ambiguous responses",
        default=False
    )
    suspicious_patterns: List[str] = Field(
        description="List of suspicious response patterns detected",
        default_factory=list
    )


class ScanResult(BaseModel):
    """Complete scan results."""
    prevalidation: PrevalidationResult
    fuzzvalidation: FuzzingVerdict
    discovered_roles: Dict[str, bool] = Field(description="Map of role names to acceptance status")
    gpt_analysis: RequestAnalysis
    vulnerability_assessment: VulnerabilityAssessment


class AgentResponse(BaseModel):
    """Generic agent response wrapper."""
    success: bool = Field(description="Whether the agent completed successfully")
    data: Optional[Any] = Field(description="Agent output data", default=None)
    error: Optional[str] = Field(description="Error message if failed", default=None)
    refusal: Optional[str] = Field(description="Refusal message from model", default=None)