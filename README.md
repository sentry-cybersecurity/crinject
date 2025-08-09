# CRInject - LLM Role Injection Vulnerability Scanner

## Overview

CRInject is a specialized security scanner designed to detect role injection vulnerabilities in GenAI/LLM applications that expose chat completion APIs. It identifies whether applications properly validate and restrict user-supplied role parameters, preventing potential prompt injection and privilege escalation attacks.

## How CRInject Works

### Detection Methodology

CRInject employs a multi-phase approach to identify role injection vulnerabilities:

1. **Endpoint Analysis**: Identifies role parameter injection points in API requests
2. **Role Enumeration**: Tests standard and custom LLM roles
3. **Response Analysis**: Differentiates between accepted and rejected roles
4. **Vulnerability Assessment**: Determines security impact and exploitability

### Tested Role Categories

#### Standard LLM Roles
- `system` - System prompts and behavioral instructions
- `assistant` - Model response context
- `developer` - Development and debug access
- `user` - Standard user messages

#### Extended Roles (Fuzzing)
- `admin`, `root`, `superuser`
- `tool`, `function`, `function_call`
- `moderator`, `reviewer`
- `debug`, `test`, `internal`
- Custom roles discovered through intelligent fuzzing

## Installation

### Prerequisites
- Python 3.8 or higher (Tested on Python 3.13.2)
- OpenAI API key for intelligent analysis
- Target API endpoint for testing

### Quick Setup
```bash
# Install dependencies
pip install -r requirements.txt

# Set OpenAI API key
export OPENAI_API_KEY="your-api-key-here"

# Run a scan
python crinject.py --request request.txt
```

## Usage Examples

### Basic LLM API Scan

Create a request file (`request.txt`) with your LLM API call:
```http
POST /v1/chat/completions HTTP/1.1
Host: api.example-llm.com
Content-Type: application/json
Authorization: Bearer <Token>

{
  "messages": [
    {
      "role": "user",
      "content": "Hello, how are you?"
    }
  ]
}
```

Run the scanner:
```bash
python crinject.py --request request.txt
```

### Testing Custom LLM Endpoints

For internal or custom LLM implementations:
```bash
# Force HTTPS for endpoints
python crinject.py --request request.txt --scheme https

# Test through proxy
python crinject.py --request request.txt --proxy http://proxy:8080

# Save detailed results
python crinject.py --request request.txt --output scan_results.json
```
## Understanding Results

### Vulnerability Classifications

#### CRITICAL - Confirmed Vulnerable
```
Status: VULNERABLE
Reason: API accepts 'system' role but rejects 'systeminvalidrole'
Impact: Attackers can inject system-level prompts
```

#### SAFE - Properly Secured
```
Status: SECURE
Reason: All privileged roles rejected
Impact: No role injection possible
```

#### WARNING - Manual Review Needed
```
Status: REQUIRES REVIEW
Reason: Ambiguous responses detected
Impact: Potential vulnerability requiring manual validation
```

#### INFO - Parameter Ignored
```
Status: PARAMETER IGNORED
Reason: API accepts both valid and invalid roles
Impact: Role field not processed, likely safe but verify
```

### Interpreting Role Test Results

| Role Test | Valid Role | Invalid Variant | Interpretation |
|-----------|------------|-----------------|----------------|
| System | Accepted | Rejected | VULNERABLE - Role validation exists but allows system |
| System | Accepted | Accepted | SAFE - Parameter ignored entirely |
| System | Rejected | Rejected | SAFE - Proper validation |
| System | Rejected | Accepted | ANOMALY - Inverse logic, manual review |

## Advanced Features

### Multi-Format Support

CRInject handles various API formats:
- **JSON** - Standard OpenAI/Anthropic format
- **Form-encoded** - Legacy or custom implementations
- **Multipart** - File upload with completions
- **XML/SOAP** - Enterprise LLM services
- **Plain text** - Custom protocols

### Response Pattern Analysis

The scanner detects subtle rejection patterns:
- HTTP 200 with error messages in body
- Rate limiting masquerading as success
- Quota exceeded responses
- Authentication failures
- Model safety refusals

### Intelligent Fuzzing

Dynamic role generation based on:
- API response patterns
- Common LLM providers (OpenAI, Anthropic, Cohere, etc.)

## Troubleshooting

### No Vulnerability Found But Expected

Some APIs may:
- Silently strip role fields
- Default to 'user' regardless of input
- Use different and custom parameter names (e.g., 'speaker', 'author')

## License and Legal

### Disclaimer
This tool is designed for authorized security testing of LLM applications. Users must:
- Obtain explicit permission before testing
- Comply with all applicable laws and regulations
- Respect API rate limits and terms of service
- Use findings responsibly and ethically

### Intended Use Cases
- Pre-production security testing
- Compliance audits
- Penetration testing (with authorization)
- Security research (with permission)
