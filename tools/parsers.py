"""Parsing utilities for various content types and HTTP requests."""
from __future__ import annotations
import json
import re
import urllib.parse
import xml.etree.ElementTree as ET
from email.parser import BytesParser
from email.policy import default
from typing import Dict, Tuple, Any
from urllib.parse import parse_qs, urlencode


def parse_raw_http_request(raw: str, scheme_override: str | None = None):
    """Parse raw HTTP request into method, url, headers, body."""
    head, sep, body = raw.partition("\n\n") if "\n\n" in raw else raw.partition("\r\n\r\n")
    if not sep:
        raise ValueError("No blank line separating headers and body in request file")
    req_line, *hdr_lines = head.splitlines()
    try:
        method, uri, *_ = req_line.split()
    except ValueError:
        raise ValueError(f"Malformed request line: {req_line!r}")
    headers: Dict[str, str] = {}
    for line in hdr_lines:
        if ":" in line:
            k, v = line.split(":", 1)
            k = k.strip()
            v = v.strip()
            # Normalize to Title-Case for HTTP headers
            k = "-".join([part.capitalize() for part in k.split("-")])
            headers[k] = v
    host_hdr = headers.get("Host") or headers.get("host")
    if uri.startswith("http://") or uri.startswith("https://"):
        url = uri
    else:
        if not host_hdr:
            raise ValueError("Host header required for relative URI in request line")
        scheme = scheme_override or ("https" if headers.get("X-Forwarded-Proto") == "https" else "http")
        url = f"{scheme}://{host_hdr}{uri}"
    return method, url, headers, body


def replace_wildcard_json(obj, role):
    """Replace wildcard (*) in JSON objects with the specified role."""
    if isinstance(obj, dict):
        return {k: replace_wildcard_json(v, role) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [replace_wildcard_json(v, role) for v in obj]
    elif isinstance(obj, str):
        # If the string contains wildcards, replace them
        if '*' in obj:
            # First try simple replacement
            if obj == '*':
                return role
            
            # Check if this string contains JSON that we need to parse and process
            if obj.strip().startswith(('[', '{')):
                try:
                    # Try to parse as JSON
                    parsed = json.loads(obj)
                    # Recursively replace wildcards in the parsed JSON
                    replaced = replace_wildcard_json(parsed, role)
                    # Convert back to JSON string
                    return json.dumps(replaced, separators=(',', ':'))
                except (json.JSONDecodeError, TypeError):
                    # If JSON parsing fails, fall back to simple string replacement
                    return obj.replace('*', role)
            else:
                # Simple string replacement for non-JSON strings
                return obj.replace('*', role)
        else:
            return obj
    elif obj == '*':
        return role
    else:
        return obj


def replace_wildcard_form(form_dict, role):
    """Replace wildcard (*) in form data with the specified role."""
    new_form = {}
    for k, v in form_dict.items():
        if isinstance(v, str) and v == '*':
            new_form[k] = role
        elif isinstance(v, str) and '*' in v:
            # If this is a JSON array in a string, decode, replace, re-encode
            try:
                decoded = urllib.parse.unquote_plus(v)
                arr = json.loads(decoded)
                # Replace all wildcards in all objects
                for item in arr:
                    for key in item:
                        if item[key] == '*':
                            item[key] = role
                new_form[k] = json.dumps(arr, separators=(',', ':'))  # compact encoding
            except Exception:
                # fallback: just replace
                new_form[k] = v.replace('*', role)
        else:
            new_form[k] = v
    return new_form


def parse_multipart(body: bytes, content_type: str):
    """Parse multipart form data."""
    match = re.search(r'boundary=(.*)', content_type)
    if not match:
        raise ValueError("No boundary found in Content-Type")
    boundary = match.group(1)
    msg = BytesParser(policy=default).parsebytes(
        b'Content-Type: ' + content_type.encode() + b'\r\n\r\n' + body
    )
    parts = {}
    for part in msg.iter_parts():
        name = part.get_param('name', header='content-disposition')
        parts[name] = part.get_content()
    return parts


def replace_wildcard_multipart(parts: dict, role: str):
    """Replace wildcard (*) in multipart data with the specified role."""
    new_parts = {}
    for k, v in parts.items():
        if isinstance(v, str) and '*' in v:
            new_parts[k] = v.replace('*', role)
        else:
            new_parts[k] = v
    return new_parts


def replace_wildcard_xml(xml_str, role):
    """Replace wildcard (*) in XML data with the specified role."""
    tree = ET.ElementTree(ET.fromstring(xml_str))
    root = tree.getroot()
    replaced = False
    for elem in root.iter():
        if elem.text and '*' in elem.text:
            elem.text = elem.text.replace('*', role)
            replaced = True
        for k, v in elem.attrib.items():
            if '*' in v:
                elem.attrib[k] = v.replace('*', role)
                replaced = True
    if not replaced:
        # fallback: replace in the whole string (for edge cases)
        return xml_str.replace('*', role)
    return ET.tostring(root, encoding='unicode')


def replace_wildcard_plaintext(text_str, role):
    """Replace wildcard (*) in plain text with the specified role."""
    if not isinstance(text_str, str):
        text_str = str(text_str)
    return text_str.replace('*', role)


def parse_content_type(content_type_header):
    """Parse Content-Type header and return base type and parameters.
    
    Args:
        content_type_header: Content-Type header value (e.g., 'text/plain;charset=UTF-8')
        
    Returns:
        tuple: (base_type, parameters_dict)
        
    Example:
        >>> parse_content_type('text/plain;charset=UTF-8')
        ('text/plain', {'charset': 'UTF-8'})
    """
    if not content_type_header:
        return '', {}
    
    parts = content_type_header.split(';')
    base_type = parts[0].strip().lower()
    
    params = {}
    for part in parts[1:]:
        if '=' in part:
            key, value = part.split('=', 1)
            params[key.strip().lower()] = value.strip()
    
    return base_type, params


def normalize_content_type(content_type_header):
    """Extract just the base media type from a Content-Type header.
    
    Args:
        content_type_header: Content-Type header value
        
    Returns:
        str: Base media type in lowercase (e.g., 'text/plain')
        
    Example:
        >>> normalize_content_type('text/plain;charset=UTF-8')
        'text/plain'
    """
    base_type, _ = parse_content_type(content_type_header)
    return base_type