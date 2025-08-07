"""Security testing agents for role discovery and validation."""

from .base import BaseAgent
from .role_prevalidator import RolePrevalidator
from .fuzz_verdict import FuzzVerdictAgent
from .role_fuzz import RoleFuzzAgent
from .request_analyzer import analyze_request_with_gpt
from .agent_sdk import agent_runner, SecurityAgentRunner
from .wildcard_handlers import (
    WildcardRolePrevalidator,
    WildcardRoleFuzzAgent,
    WildcardFormRolePrevalidator,
    WildcardFormRoleFuzzAgent,
    WildcardMultipartRolePrevalidator,
    WildcardMultipartRoleFuzzAgent,
    WildcardXMLRolePrevalidator,
    WildcardXMLRoleFuzzAgent,
    WildcardPlainTextRolePrevalidator,
    WildcardPlainTextRoleFuzzAgent
)

__all__ = [
    'BaseAgent',
    'RolePrevalidator',
    'FuzzVerdictAgent',
    'RoleFuzzAgent',
    'analyze_request_with_gpt',
    'agent_runner',
    'SecurityAgentRunner',
    'WildcardRolePrevalidator',
    'WildcardRoleFuzzAgent',
    'WildcardFormRolePrevalidator',
    'WildcardFormRoleFuzzAgent',
    'WildcardMultipartRolePrevalidator',
    'WildcardMultipartRoleFuzzAgent',
    'WildcardXMLRolePrevalidator',
    'WildcardXMLRoleFuzzAgent',
    'WildcardPlainTextRolePrevalidator',
    'WildcardPlainTextRoleFuzzAgent'
]