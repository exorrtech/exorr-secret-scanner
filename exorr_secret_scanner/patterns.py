"""Secret detection patterns — regex rules for API keys, tokens, and credentials."""

import re
from typing import Any, Dict, List

# Each pattern: id, name, severity, regex, description, false_positive_hints
SECRET_PATTERNS: List[Dict[str, Any]] = [
    {
        "id": "aws-access-key",
        "name": "AWS Access Key ID",
        "severity": "critical",
        "pattern": r"(?<![A-Za-z0-9/+=])AKIA[0-9A-Z]{16}(?![A-Za-z0-9/+=])",
        "description": "AWS IAM access key ID — grants access to AWS resources",
        "fp_hints": ["example", "test", "dummy", "placeholder", "your-access-key"],
    },
    {
        "id": "aws-secret-key",
        "name": "AWS Secret Access Key",
        "severity": "critical",
        "pattern": r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?",
        "description": "AWS secret access key — full authentication to AWS",
        "fp_hints": ["example", "test", "dummy", "placeholder", "your-secret"],
    },
    {
        "id": "github-token",
        "name": "GitHub Personal Access Token",
        "severity": "critical",
        "pattern": r"gh[pousr]_[A-Za-z0-9_]{36,255}",
        "description": "GitHub PAT — grants access to repositories and actions",
        "fp_hints": ["example", "test", "dummy", "your-token"],
    },
    {
        "id": "slack-token",
        "name": "Slack Token",
        "severity": "high",
        "pattern": r"xox[baprs]-[0-9a-zA-Z\-]{10,255}",
        "description": "Slack bot/user/token — access to Slack workspace",
        "fp_hints": ["example", "test", "dummy"],
    },
    {
        "id": "github-oauth",
        "name": "GitHub OAuth Access Token",
        "severity": "high",
        "pattern": r"gho_[A-Za-z0-9]{36}",
        "description": "GitHub OAuth token — user-level GitHub access",
        "fp_hints": ["example", "test"],
    },
    {
        "id": "private-key",
        "name": "Private Key Block",
        "severity": "critical",
        "pattern": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "description": "Private key in code — can be used for authentication",
        "fp_hints": ["example", "test-key", "dummy"],
    },
    {
        "id": "azure-connection-string",
        "name": "Azure Storage Connection String",
        "severity": "critical",
        "pattern": r"(?i)DefaultEndpointsProtocol=https?;AccountName=[a-z0-9]{3,24};AccountKey=[A-Za-z0-9+/=]{88}",
        "description": "Azure storage account key — full access to storage",
        "fp_hints": ["example", "your-account", "placeholder"],
    },
    {
        "id": "azure-tenant-secret",
        "name": "Azure Client Secret",
        "severity": "critical",
        "pattern": r"(?i)(?:azure|tenant|client)[_-]?(?:secret|key|password)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{20,}['\"]?",
        "description": "Azure service principal secret — tenant-level access",
        "fp_hints": ["example", "test", "dummy", "your-client-secret"],
    },
    {
        "id": "openai-key",
        "name": "OpenAI API Key",
        "severity": "high",
        "pattern": r"sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20,}",
        "description": "OpenAI API key — access to GPT models and usage",
        "fp_hints": ["example", "test"],
    },
    {
        "id": "generic-api-key",
        "name": "Generic API Key",
        "severity": "medium",
        "pattern": r"(?i)(?:api[_\-]?key|apikey|api[_\-]?secret)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{20,}['\"]?",
        "description": "Generic API key in code — potential credential leak",
        "fp_hints": ["example", "test", "dummy", "your-api-key", "placeholder", "xxx", "changeme"],
    },
    {
        "id": "password-in-code",
        "name": "Hardcoded Password",
        "severity": "high",
        "pattern": r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"](?!=.{0,5}$)[^'\"]{6,128}['\"]",
        "description": "Hardcoded password — credential in source code",
        "fp_hints": ["example", "test", "dummy", "changeme", "your-password", "xxx", "placeholder"],
    },
    {
        "id": "jwt-secret",
        "name": "JWT Secret Key",
        "severity": "high",
        "pattern": r"(?i)jwt[_\-]?(?:secret|key|signing[_\-]?key)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{16,}['\"]?",
        "description": "JWT signing key — can forge authentication tokens",
        "fp_hints": ["example", "test", "your-secret", "changeme"],
    },
    {
        "id": "database-url",
        "name": "Database Connection URL",
        "severity": "high",
        "pattern": r"(?i)(?:mysql|postgres|mongodb|redis)://[^\s'\"<>]{10,}",
        "description": "Database connection string with credentials",
        "fp_hints": ["localhost", "127.0.0.1", "example", "test"],
    },
    {
        "id": "sendgrid-key",
        "name": "SendGrid API Key",
        "severity": "high",
        "pattern": r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}",
        "description": "SendGrid API key — email sending capability",
        "fp_hints": ["example", "test"],
    },
    {
        "id": "stripe-key",
        "name": "Stripe API Key",
        "severity": "critical",
        "pattern": r"[sr]k_live_[A-Za-z0-9]{24,}",
        "description": "Stripe live key — payment processing access",
        "fp_hints": ["example", "test", "sk_test_"],
    },
    {
        "id": "heroku-key",
        "name": "Heroku API Key",
        "severity": "high",
        "pattern": r"(?i)heroku[_\-]?api[_\-]?key\s*[=:]\s*['\"]?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]?",
        "description": "Heroku API key — access to Heroku apps",
        "fp_hints": ["example", "test"],
    },
]


def get_patterns() -> List[Dict[str, Any]]:
    """Return all compiled secret detection patterns."""
    compiled = []
    for p in SECRET_PATTERNS:
        compiled.append({
            **p,
            "compiled": re.compile(p["pattern"]),
        })
    return compiled
