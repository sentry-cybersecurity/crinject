"""Wildcard handlers for different content types in role injection."""
from __future__ import annotations
import json
import logging
import asyncio
from typing import Any, Dict, List, Tuple

# Note: This file should be in security_agents/wildcard_handlers.py after renaming
from .role_prevalidator import RolePrevalidator, VALID_ROLES, INVALID_ROLES
from .role_fuzz import RoleFuzzAgent
from .agent_sdk import agent_runner
from models.pydantic_models import HTTPResult
from tools.parsers import (
    replace_wildcard_json, 
    replace_wildcard_xml, 
    replace_wildcard_multipart,
    replace_wildcard_plaintext
)

logger = logging.getLogger(__name__)


class WildcardRolePrevalidator(RolePrevalidator):
    """JSON wildcard role prevalidator."""
    
    @staticmethod
    def insert_role(body, role):
        return replace_wildcard_json(body, role)
    
    async def run(self, url: str, body_tmpl: dict, headers_from_request=None):
        results: Dict[str, HTTPResult] = {}
        for role in VALID_ROLES + INVALID_ROLES:
            payload_dict = self.insert_role(body_tmpl, role)
            payload = json.dumps(payload_dict)
            logger.info(f"[OUTGOING JSON BODY for prevalidation role={role}] {payload}")
            logger.info(f"[OUTGOING HEADERS] {headers_from_request}")
            try:
                resp = await self.client.post(
                    url,
                    content=payload,
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


class WildcardRoleFuzzAgent(RoleFuzzAgent):
    """JSON wildcard role fuzzing agent."""
    
    async def _probe_roles(self, url: str, body_tmpl: dict, roles: list, headers_from_request=None):
        results = {}
        tasks = []
        for role in roles:
            payload_dict = WildcardRolePrevalidator.insert_role(body_tmpl, role)
            payload = json.dumps(payload_dict)
            logger.info(f"[OUTGOING JSON BODY for role={role}] {payload}")
            logger.info(f"[OUTGOING HEADERS] {headers_from_request}")
            task = asyncio.create_task(self.client.post(
                url,
                content=payload,
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


class WildcardFormRolePrevalidator(RolePrevalidator):
    """Form-encoded wildcard role prevalidator."""
    
    def __init__(self, client, is_dict_like=False):
        super().__init__(client)
        self.is_dict_like = is_dict_like
    
    def insert_role(self, body, role):
        if self.is_dict_like:
            try:
                json_like = body.replace("'", '"')
                import json
                form_dict = json.loads(json_like)
                # Replace wildcards in dict values
                for k, v in form_dict.items():
                    if isinstance(v, str) and '*' in v:
                        form_dict[k] = v.replace('*', role)
                import urllib.parse
                return urllib.parse.urlencode(form_dict)
            except Exception as e:
                logger.error(f"Failed to process dict-like form body: {e}")
                return body
        else:
            # Already urlencoded string, just replace first *
            return body.replace('*', role, 1)
    
    async def run(self, url: str, body_tmpl: str, headers_from_request=None):
        results: Dict[str, HTTPResult] = {}
        for role in VALID_ROLES + INVALID_ROLES:
            payload = self.insert_role(body_tmpl, role)
            logger.info(f"[DEBUG] Form body after wildcard for role={role}: {payload}")
            # Remove Content-Length from headers
            headers = {**(headers_from_request or {})}
            headers.pop('Content-Length', None)
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
            try:
                resp = await self.client.post(
                    url,
                    data=payload,
                    headers=headers,
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


class WildcardFormRoleFuzzAgent(RoleFuzzAgent):
    """Form-encoded wildcard role fuzzing agent."""
    
    def __init__(self, client, prevalidation_results=None, is_dict_like=False):
        super().__init__(client, prevalidation_results=prevalidation_results)
        self.is_dict_like = is_dict_like
    
    async def _probe_roles(self, url: str, body_tmpl: str, roles: list, headers_from_request=None):
        results = {}
        tasks = []
        prevalidator = WildcardFormRolePrevalidator(self.client, self.is_dict_like)
        for role in roles:
            payload = prevalidator.insert_role(body_tmpl, role)
            logger.info(f"[DEBUG] Form body after wildcard for role={role}: {payload}")
            # Remove Content-Length from headers
            headers = {**(headers_from_request or {})}
            headers.pop('Content-Length', None)
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
            task = asyncio.create_task(self.client.post(
                url,
                data=payload,
                headers=headers,
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


class WildcardMultipartRolePrevalidator(RolePrevalidator):
    """Multipart wildcard role prevalidator."""
    
    @staticmethod
    def insert_role(parts, role):
        return replace_wildcard_multipart(parts, role)
    
    async def run(self, url: str, parts_tmpl: dict, headers_from_request=None):
        results: Dict[str, HTTPResult] = {}
        for role in VALID_ROLES + INVALID_ROLES:
            payload_parts = self.insert_role(parts_tmpl, role)
            files = {k: (None, v) for k, v in payload_parts.items()}
            logger.info(f"[OUTGOING MULTIPART for prevalidation role={role}] {files}")
            logger.info(f"[OUTGOING HEADERS] {headers_from_request}")
            try:
                resp = await self.client.post(
                    url,
                    files=files,
                    headers={k: v for k, v in headers_from_request.items() if k.lower() != 'content-length'},
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


class WildcardMultipartRoleFuzzAgent(RoleFuzzAgent):
    """Multipart wildcard role fuzzing agent."""
    
    async def _probe_roles(self, url: str, parts_tmpl: dict, roles: list, headers_from_request=None):
        results = {}
        tasks = []
        for role in roles:
            payload_parts = WildcardMultipartRolePrevalidator.insert_role(parts_tmpl, role)
            files = {k: (None, v) for k, v in payload_parts.items()}
            logger.info(f"[OUTGOING MULTIPART for role={role}] {files}")
            logger.info(f"[OUTGOING HEADERS] {headers_from_request}")
            task = asyncio.create_task(self.client.post(
                url,
                files=files,
                headers={k: v for k, v in headers_from_request.items() if k.lower() != 'content-length'},
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


class WildcardXMLRolePrevalidator(RolePrevalidator):
    """XML wildcard role prevalidator."""
    
    @staticmethod
    def insert_role(xml_str, role):
        return replace_wildcard_xml(xml_str, role)
    
    async def run(self, url: str, xml_tmpl: str, headers_from_request=None):
        results: Dict[str, HTTPResult] = {}
        for role in VALID_ROLES + INVALID_ROLES:
            payload_xml = self.insert_role(xml_tmpl, role)
            logger.info(f"[OUTGOING XML BODY for prevalidation role={role}] {payload_xml}")
            logger.info(f"[OUTGOING HEADERS] {headers_from_request}")
            try:
                resp = await self.client.post(
                    url,
                    content=payload_xml,
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


class WildcardXMLRoleFuzzAgent(RoleFuzzAgent):
    """XML wildcard role fuzzing agent."""
    
    async def _probe_roles(self, url: str, xml_tmpl: str, roles: list, headers_from_request=None):
        results = {}
        tasks = []
        for role in roles:
            payload_xml = WildcardXMLRolePrevalidator.insert_role(xml_tmpl, role)
            logger.info(f"[OUTGOING XML BODY for role={role}] {payload_xml}")
            logger.info(f"[OUTGOING HEADERS] {headers_from_request}")
            task = asyncio.create_task(self.client.post(
                url,
                content=payload_xml,
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


class WildcardPlainTextRolePrevalidator(RolePrevalidator):
    """Plain text wildcard role prevalidator."""
    
    @staticmethod
    def insert_role(body_text, role):
        return replace_wildcard_plaintext(body_text, role)
    
    async def run(self, url: str, body_tmpl: str, headers_from_request=None):
        results: Dict[str, HTTPResult] = {}
        for role in VALID_ROLES + INVALID_ROLES:
            payload = self.insert_role(body_tmpl, role)
            logger.info(f"[OUTGOING PLAIN TEXT BODY for prevalidation role={role}] {payload}")
            logger.info(f"[OUTGOING HEADERS] {headers_from_request}")
            
            # Prepare headers for plain text
            headers = {**(headers_from_request or {})}
            headers.pop('Content-Length', None)
            headers['Content-Type'] = 'text/plain'
            
            try:
                resp = await self.client.post(
                    url,
                    content=payload,
                    headers=headers,
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


class WildcardPlainTextRoleFuzzAgent(RoleFuzzAgent):
    """Plain text wildcard role fuzzing agent."""
    
    async def _probe_roles(self, url: str, body_tmpl: str, roles: list, headers_from_request=None):
        results = {}
        tasks = []
        
        for role in roles:
            payload = WildcardPlainTextRolePrevalidator.insert_role(body_tmpl, role)
            logger.info(f"[OUTGOING PLAIN TEXT BODY for role={role}] {payload}")
            logger.info(f"[OUTGOING HEADERS] {headers_from_request}")
            
            # Prepare headers for plain text
            headers = {**(headers_from_request or {})}
            headers.pop('Content-Length', None)
            headers['Content-Type'] = 'text/plain'
            
            task = asyncio.create_task(self.client.post(
                url,
                content=payload,
                headers=headers,
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