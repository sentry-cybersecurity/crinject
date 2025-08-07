"""JSON schemas for structured outputs from various agents."""

ROLE_SCHEMA = {
    "name": "RoleValidation",
    "schema": {
        "type": "object",
        "properties": {
            "system": {"type": "boolean"},
            "systeminvalidrole": {"type": "boolean"},
            "assistant": {"type": "boolean"},
            "assistantinvalidrole": {"type": "boolean"},
            "developer": {"type": "boolean"},
            "developerinvalidrole": {"type": "boolean"},
            "verdict": {"type": "string"}
        },
        "required": [
            "system", "systeminvalidrole", "assistant", "assistantinvalidrole",
            "developer", "developerinvalidrole", "verdict"
        ],
        "additionalProperties": False
    },
    "strict": True
}

VERDICT_SCHEMA = {
    "name": "FuzzVerdict",
    "schema": {
        "type": "object",
        "properties": {
            "roles": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "role_name": {"type": "string"},
                        "accepted": {"type": "boolean"},
                        "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
                        "reasoning": {"type": "string"}
                    },
                    "required": ["role_name", "accepted", "confidence", "reasoning"],
                    "additionalProperties": False
                }
            },
            "overall_verdict": {"type": "string"},
            "security_implications": {"type": "string"}
        },
        "required": ["roles", "overall_verdict", "security_implications"],
        "additionalProperties": False
    },
    "strict": True
}

FUZZ_SCHEMA = {
    "name": "RoleFuzzList",
    "schema": {
        "type": "object",
        "properties": {
            "roles": {
                "type": "array",
                "items": {"type": "string"},
                "minItems": 1,
                "maxItems": 20
            }
        },
        "required": ["roles"],
        "additionalProperties": False
    },
    "strict": True
}

INJECTION_SCHEMA = {
    "name": "RoleInjectionAnalysis",
    "schema": {
        "type": "object",
        "properties": {
            "content_type": {"type": "string"},
            "injection_points": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "parameter_type": {"type": "string", "enum": ["json", "form", "query", "header", "multipart"]}
                    },
                    "required": ["path", "parameter_type"],
                    "additionalProperties": False
                }
            },
            "body_with_wildcard": {"type": "string"},
            "notes": {"type": "string"}
        },
        "required": ["content_type", "injection_points", "body_with_wildcard", "notes"],
        "additionalProperties": False
    },
    "strict": True
}
