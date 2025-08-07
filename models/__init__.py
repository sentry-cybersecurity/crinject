"""Pydantic models for structured outputs."""
from .pydantic_models import (
    # Constants
    VALID_ROLES,
    INVALID_ROLES,
    
    # Enums
    ConfidenceLevel,
    
    # Models
    RoleValidation,
    RoleVerdict,
    FuzzingVerdict,
    RoleFuzzList,
    InjectionPoint,
    RequestAnalysis,
    HTTPResult,
    PrevalidationResult,
    VulnerabilityAssessment,
    ScanResult,
    AgentResponse
)

__all__ = [
    'VALID_ROLES',
    'INVALID_ROLES',
    'ConfidenceLevel',
    'RoleValidation',
    'RoleVerdict',
    'FuzzingVerdict',
    'RoleFuzzList',
    'InjectionPoint',
    'RequestAnalysis',
    'HTTPResult',
    'PrevalidationResult',
    'VulnerabilityAssessment',
    'ScanResult',
    'AgentResponse'
]
