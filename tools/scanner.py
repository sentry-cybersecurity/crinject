"""Main scanner functionality for role discovery."""
from __future__ import annotations
import re
import random
import string
import logging
import json
from typing import Dict, Any
from urllib.parse import parse_qs
import httpx

from security_agents import (
    analyze_request_with_gpt,
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
from models.pydantic_models import (
    VALID_ROLES,
    INVALID_ROLES,
    VulnerabilityAssessment,
    PrevalidationResult,
    ScanResult,
    RequestAnalysis,
    RoleValidation,
    FuzzingVerdict,
    ConfidenceLevel
)
from .parsers import parse_raw_http_request, parse_multipart, normalize_content_type

logger = logging.getLogger(__name__)


async def scan_raw_request(raw_request: str, scheme_override: str | None = None, proxy: str | None = None, insecure: bool = False) -> Dict[str, Any]:
    """Scan a raw HTTP request for role injection vulnerabilities."""
    # Try to decode the body from urlencoding before passing to the agent
    method, url, headers_from_request, body = parse_raw_http_request(raw_request, scheme_override)
    
    # Heuristic: if body looks like urlencoded and not JSON, decode and pretty-print
    if body and ('=' in body and '&' in body) and not any(x in body for x in '{['):
        form_dict = parse_qs(body)
        form_dict = {k: v[0] if len(v) == 1 else v for k, v in form_dict.items()}
        import pprint
        pretty_form = pprint.pformat(form_dict, width=120)
        if '\n\n' in raw_request:
            head, sep, _ = raw_request.partition('\n\n')
            raw_request_for_agent = head + sep + pretty_form
        elif '\r\n\r\n' in raw_request:
            head, sep, _ = raw_request.partition('\r\n\r\n')
            raw_request_for_agent = head + sep + pretty_form
        else:
            raw_request_for_agent = raw_request
    else:
        raw_request_for_agent = raw_request
    
    # Analyze with agent
    analysis = await analyze_request_with_gpt(raw_request_for_agent)
    request_analysis = RequestAnalysis(**analysis)
    
    content_type = request_analysis.content_type
    injection_points = request_analysis.injection_points
    body_with_wildcard = request_analysis.body_with_wildcard
    
    # Extract base content type (remove parameters like charset)
    base_content_type = normalize_content_type(content_type)
    
    client_args = {}
    if proxy:
        client_args['proxy'] = proxy
    if insecure:
        client_args['verify'] = False
    headers_for_client = headers_from_request.copy()
    headers_for_client.pop('Content-Length', None)
    client_args['headers'] = headers_for_client
    
    async with httpx.AsyncClient(**client_args) as client:
        inj = injection_points[0] if injection_points else None
        if not inj:
            raise ValueError("No injection point found by GPT agent.")
        
        if base_content_type == "application/json":
            try:
                body_json = json.loads(body_with_wildcard)
            except Exception as exc:
                logger.error(f"Failed to parse body_with_wildcard as JSON: {body_with_wildcard}")
                raise ValueError(f"Failed to parse JSON body_with_wildcard: {exc}")
            
            prevalidator = WildcardRolePrevalidator(client)
            prevalid_result = await prevalidator.run(url, body_json, headers_from_request)
            role_fuzzer = WildcardRoleFuzzAgent(client, prevalidation_results=prevalid_result)
            fuzz_result = await role_fuzzer.run(url, body_json, headers_from_request)
            
        elif base_content_type == "application/x-www-form-urlencoded":
            form_body_template = body_with_wildcard
            is_dict_like = isinstance(form_body_template, str) and form_body_template.strip().startswith("{") and form_body_template.strip().endswith("}")
            logger.info(f"[DEBUG] Agent returned dict-like: {is_dict_like}")
            
            prevalidator = WildcardFormRolePrevalidator(client, is_dict_like)
            prevalid_result = await prevalidator.run(url, form_body_template, headers_from_request)
            role_fuzzer = WildcardFormRoleFuzzAgent(client, prevalidation_results=prevalid_result, is_dict_like=is_dict_like)
            fuzz_result = await role_fuzzer.run(url, form_body_template, headers_from_request)
            
        elif base_content_type.startswith("multipart/form-data"):
            # Parse multipart body from body_with_wildcard
            boundary_match = re.search(r'boundary=([^;\s]+)', content_type)
            if not boundary_match:
                # Try to extract from body (rare)
                possible_boundary = None
                if isinstance(body_with_wildcard, str):
                    lines = body_with_wildcard.splitlines()
                    for line in lines:
                        if line.startswith('--') and len(line) > 2:
                            possible_boundary = line[2:].strip()
                            break
                if possible_boundary:
                    boundary = possible_boundary
                    logger.info(f"[DEBUG] Extracted boundary from body: {boundary}")
                else:
                    # Generate a random boundary
                    boundary = '----crinject-boundary-' + ''.join(random.choices(string.ascii_letters + string.digits, k=12))
                    logger.info(f"[DEBUG] No boundary found in Content-Type, generated boundary: {boundary}")
                    # Fix Content-Type header
                    content_type = f"multipart/form-data; boundary={boundary}"
                    headers_for_client = headers_from_request.copy()
                    headers_for_client['Content-Type'] = content_type
            else:
                boundary = boundary_match.group(1)
                headers_for_client = headers_from_request.copy()
            
            # body_with_wildcard is a string, convert to bytes
            body_bytes = body_with_wildcard.encode() if isinstance(body_with_wildcard, str) else body_with_wildcard
            parts = parse_multipart(body_bytes, content_type)
            
            prevalidator = WildcardMultipartRolePrevalidator(client)
            prevalid_result = await prevalidator.run(url, parts, headers_for_client)
            role_fuzzer = WildcardMultipartRoleFuzzAgent(client, prevalidation_results=prevalid_result)
            fuzz_result = await role_fuzzer.run(url, parts, headers_for_client)
            
        elif "xml" in base_content_type:
            # XML/Soap/XML-based
            prevalidator = WildcardXMLRolePrevalidator(client)
            prevalid_result = await prevalidator.run(url, body_with_wildcard, headers_from_request)
            role_fuzzer = WildcardXMLRoleFuzzAgent(client, prevalidation_results=prevalid_result)
            fuzz_result = await role_fuzzer.run(url, body_with_wildcard, headers_from_request)
            
        elif base_content_type == "text/plain":
            # Plain text handling
            logger.info(f"[DEBUG] Processing plain text content: {body_with_wildcard[:200]}...")
            
            prevalidator = WildcardPlainTextRolePrevalidator(client)
            prevalid_result = await prevalidator.run(url, body_with_wildcard, headers_from_request)
            role_fuzzer = WildcardPlainTextRoleFuzzAgent(client, prevalidation_results=prevalid_result)
            fuzz_result = await role_fuzzer.run(url, body_with_wildcard, headers_from_request)
            
        else:
            raise NotImplementedError(f"Content type {base_content_type} not yet supported for injection.")
        
        # Convert results to Pydantic models
        validation = RoleValidation(**{k: v for k, v in prevalid_result.items() if k != "raw_results"})
        prevalidation = PrevalidationResult(
            validation=validation,
            raw_results=prevalid_result.get("raw_results", {})
        )
        
        # Extract FuzzingVerdict from fuzz_result
        roles = []
        for role, accepted in fuzz_result.items():
            if role not in ["verdict", "security_implications"] and not role.endswith("_details"):
                if f"{role}_details" in fuzz_result:
                    details = fuzz_result[f"{role}_details"]
                    roles.append({
                        "role_name": role,
                        "accepted": accepted,
                        "confidence": details.get("confidence", "medium"),
                        "reasoning": details.get("reasoning", "")
                    })
        
        fuzzing_verdict = FuzzingVerdict(
            roles=roles,
            overall_verdict=fuzz_result.get("verdict", ""),
            security_implications=fuzz_result.get("security_implications", "")
        )
        
        # Build discovered roles map
        discovered_roles = {}
        for role in VALID_ROLES:
            if hasattr(validation, role):
                discovered_roles[role] = getattr(validation, role)
        for role_verdict in fuzzing_verdict.roles:
            discovered_roles[role_verdict.role_name] = role_verdict.accepted
        
        # Assess vulnerability
        vulnerability_assessment = assess_vulnerability(prevalidation, discovered_roles)
        
        # Create final scan result
        result = ScanResult(
            prevalidation=prevalidation,
            fuzzvalidation=fuzzing_verdict,
            discovered_roles=discovered_roles,
            gpt_analysis=request_analysis,
            vulnerability_assessment=vulnerability_assessment
        )
    
    return result.model_dump()


def assess_vulnerability(prevalidation: PrevalidationResult, discovered_roles: Dict[str, bool]) -> VulnerabilityAssessment:
    """Assess if the discovered behavior represents a true vulnerability."""
    
    # Check if invalid role variants were accepted
    invalid_roles_accepted = []
    valid_roles_accepted = []
    
    validation = prevalidation.validation
    for role in VALID_ROLES:
        if getattr(validation, role, False):
            valid_roles_accepted.append(role)
        invalid_variant = role + "invalidrole"
        if getattr(validation, invalid_variant, False):
            invalid_roles_accepted.append(invalid_variant)
    
    # Check for suspicious patterns that might require manual validation
    raw_results = prevalidation.raw_results
    suspicious_patterns = []
    
    # Look for common error patterns in successful responses
    error_indicators = [
        "limit", "quota", "upgrade", "rate", "usage", "exceeded",
        "error", "failed", "invalid", "unauthorized", "forbidden",
        "authentication", "token", "login", "required",
        "exception", "internal", "server error", "bad request"
    ]
    
    for role, result in raw_results.items():
        if isinstance(result, dict):
            status = result.get('status', 'unknown')
            body = result.get('body', '').lower()
        else:
            status = getattr(result, 'status', 'unknown')
            body = getattr(result, 'body', '').lower()
        
        # Check for 200 responses with error content
        if str(status) == '200' and any(indicator in body for indicator in error_indicators):
            suspicious_patterns.append(f"Role '{role}' returned 200 but body contains error indicators")
    
    # Enhanced assessment logic
    total_roles_tested = len(VALID_ROLES) + len(INVALID_ROLES)
    acceptance_rate = (len(valid_roles_accepted) + len(invalid_roles_accepted)) / total_roles_tested
    
    # If suspicious patterns detected, recommend manual validation
    if suspicious_patterns:
        return VulnerabilityAssessment(
            is_vulnerable=False,
            reason=f"Ambiguous responses detected: {'; '.join(suspicious_patterns[:2])}. Manual validation recommended.",
            confidence=ConfidenceLevel.LOW,
            recommendation="Manual review required - API responses contain mixed signals (HTTP 200 with error content). Verify if roles are truly accepted by testing actual functionality.",
            manual_validation_recommended=True,
            suspicious_patterns=suspicious_patterns
        )
    
    # If both valid and invalid variants are accepted, API is likely ignoring the parameter
    if valid_roles_accepted and len(invalid_roles_accepted) >= len(valid_roles_accepted) - 1:
        return VulnerabilityAssessment(
            is_vulnerable=False,
            reason="API appears to ignore the role parameter entirely - both valid and invalid roles are accepted",
            confidence=ConfidenceLevel.HIGH,
            recommendation="No action needed - the API does not process role parameters",
            manual_validation_recommended=False,
            suspicious_patterns=[]
        )
    
    # If only valid privileged roles are accepted (but not invalid ones), it's a vulnerability
    if valid_roles_accepted and not invalid_roles_accepted:
        return VulnerabilityAssessment(
            is_vulnerable=True,
            reason=f"API accepts privileged roles ({', '.join(valid_roles_accepted)}) but rejects invalid variants",
            confidence=ConfidenceLevel.HIGH,
            recommendation="Implement proper role validation to reject unauthorized privileged roles",
            manual_validation_recommended=False,
            suspicious_patterns=[]
        )
    
    # If no privileged roles are accepted
    if not valid_roles_accepted and not invalid_roles_accepted:
        return VulnerabilityAssessment(
            is_vulnerable=False,
            reason="No privileged roles are accepted by the API",
            confidence=ConfidenceLevel.HIGH,
            recommendation="API properly rejects privileged roles",
            manual_validation_recommended=False,
            suspicious_patterns=[]
        )
    
    # High acceptance rate might indicate parameter is ignored
    if acceptance_rate > 0.8:
        return VulnerabilityAssessment(
            is_vulnerable=False,
            reason=f"High acceptance rate ({acceptance_rate:.0%}) suggests API may ignore role parameter",
            confidence=ConfidenceLevel.MEDIUM,
            recommendation="Manual validation recommended - verify if accepted roles actually grant different privileges",
            manual_validation_recommended=True,
            suspicious_patterns=[]
        )
    
    # Edge case: some valid accepted, some invalid accepted
    return VulnerabilityAssessment(
        is_vulnerable=False,
        reason="Mixed acceptance pattern suggests inconsistent role handling",
        confidence=ConfidenceLevel.MEDIUM,
        recommendation="Review API role handling logic for consistency. Manual testing recommended.",
        manual_validation_recommended=True,
        suspicious_patterns=[]
    )