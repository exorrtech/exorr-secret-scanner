# 🔒 EXORR Secret Scanner

![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)
![MIT License](https://img.shields.io/badge/license-MIT-green.svg)
![Version](https://img.shields.io/badge/version-1.0.0-orange.svg)
![Tests](https://img.shields.io/badge/tests-8%20passing-brightgreen.svg)

**Detect leaked secrets in Git repositories and directories.**

EXORR Secret Scanner is a lightweight, zero-dependency Python CLI tool that recursively scans your codebase for accidentally committed credentials — API keys, tokens, passwords, private keys, and more. It ships with 16 battle-tested regex patterns, intelligent false-positive detection, and JSON/Markdown report generation.

Built by **[EXORR Security](https://github.com/exorrtech)**.

---

## ✨ Features

- **16 detection patterns** — AWS, GitHub, Azure, OpenAI, Stripe, SendGrid, Heroku, and more
- **False positive detection** — automatically flags placeholder/example values (`your-api-key`, `changeme`, `xxx`, etc.)
- **File type filtering** — skips binaries, images, archives, fonts, and compiled files
- **Directory skipping** — ignores `.git`, `node_modules`, `__pycache__`, `venv`, `vendor`, and more
- **Severity levels** — findings classified as `critical`, `high`, `medium`, or `low`
- **JSON & Markdown reports** — export structured results for CI/CD integration
- **Zero dependencies** — pure Python, no external packages required
- **Pattern filtering** — scan only the pattern categories you care about
- **Verbose mode** — detailed output for debugging and audits

---

## 📦 Installation

```bash
# Install from source
git clone https://github.com/exorrtech/exorr-secret-scanner.git
cd exorr-secret-scanner
pip install .

# Or install directly from GitHub
pip install git+https://github.com/exorrtech/exorr-secret-scanner.git
```

Requires **Python 3.9+**. No external dependencies.

---

## 🚀 Usage

### Scan the current directory

```bash
exorr-secret-scanner
```

### Scan a specific directory

```bash
exorr-secret-scanner /path/to/project
```

### List all detection patterns

```bash
exorr-secret-scanner --list-patterns
```

### Verbose output

```bash
exorr-secret-scanner --verbose
```

### Generate a JSON report

```bash
exorr-secret-scanner -o report.json --format json
```

### Generate a Markdown report

```bash
exorr-secret-scanner -o report.md --format markdown
```

### Filter by specific patterns

```bash
exorr-secret-scanner -p aws-access-key,github-token,private-key
```

### Set minimum severity threshold

```bash
exorr-secret-scanner --severity-threshold high
```

### Show likely false positives

```bash
exorr-secret-scanner --show-fp
```

---

## 🔍 Detection Patterns

| # | Pattern ID | Name | Severity | Detects |
|---|-----------|------|----------|---------|
| 1 | `aws-access-key` | AWS Access Key ID | Critical | `AKIA...` access key prefixes |
| 2 | `aws-secret-key` | AWS Secret Access Key | Critical | `aws_secret_access_key = ...` assignments |
| 3 | `github-token` | GitHub Personal Access Token | Critical | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` tokens |
| 4 | `github-oauth` | GitHub OAuth Access Token | High | `gho_` OAuth tokens |
| 5 | `slack-token` | Slack Token | High | `xoxb-`, `xoxp-`, `xoxa-`, `xoxk-` tokens |
| 6 | `private-key` | Private Key Block | Critical | `-----BEGIN RSA/EC/DSA/OPENSSH PRIVATE KEY-----` |
| 7 | `azure-connection-string` | Azure Storage Connection String | Critical | `DefaultEndpointsProtocol=...;AccountKey=...` |
| 8 | `azure-tenant-secret` | Azure Client Secret | Critical | `azure_secret = ...`, `tenant_key = ...` |
| 9 | `openai-key` | OpenAI API Key | High | `sk-...T3BlbkFJ...` key format |
| 10 | `generic-api-key` | Generic API Key | Medium | `api_key = "..."`, `apikey = "..."` |
| 11 | `password-in-code` | Hardcoded Password | High | `password = "..."`, `passwd = "..."` |
| 12 | `jwt-secret` | JWT Secret Key | High | `jwt_secret = "..."`, `jwt_signing_key = "..."` |
| 13 | `database-url` | Database Connection URL | High | `mysql://`, `postgres://`, `mongodb://`, `redis://` |
| 14 | `sendgrid-key` | SendGrid API Key | High | `SG.xxxx.yyyy` key format |
| 15 | `stripe-key` | Stripe API Key | Critical | `sk_live_...`, `rk_live_...` live keys |
| 16 | `heroku-key` | Heroku API Key | High | `heroku_api_key = "UUID"` |

---

## 🛡️ False Positive Detection

EXORR Secret Scanner automatically identifies likely false positives by checking the surrounding line context against known placeholder patterns. For example:

```python
# Flagged as FALSE POSITIVE (contains "your-api-key" hint)
api_key = "your-api-key-here-really-long-value"

# Flagged as REAL FINDING
api_key = "sk-proj-abc123def456ghi789jkl012"
```

**Default behavior:** false positives are hidden from output. Use `--show-fp` to include them with a `[FP]` tag.

Common false-positive hints checked: `example`, `test`, `dummy`, `placeholder`, `changeme`, `xxx`, `your-api-key`, `your-password`, `localhost`, `127.0.0.1`.

---

## 📁 Project Structure

```
exorr-secret-scanner/
├── README.md
├── LICENSE
├── pyproject.toml
├── exorr_secret_scanner/
│   ├── __init__.py          # Package metadata
│   ├── __main__.py          # python -m entry point
│   ├── cli.py               # CLI argument parsing & main loop
│   ├── scanner.py           # Core scanner engine & data models
│   ├── patterns.py          # 16 regex detection pattern definitions
│   └── report.py            # JSON & Markdown report generator
└── tests/
    ├── __init__.py
    └── test_scanner.py      # 8 unit tests
```

---

## 🧪 Running Tests

```bash
pip install -e ".[dev]"
pytest -v
```

---

## ⚙️ CLI Reference

```
exorr-secret-scanner [target] [options]

Positional:
  target                  Directory or repo to scan (default: .)

Options:
  -p, --patterns          Comma-separated pattern IDs to scan
  --severity-threshold    Minimum severity: low, medium, high, critical
  --show-fp               Show likely false positives
  -o, --output            Output report file path
  --format                Report format: json or markdown (default: json)
  --list-patterns         List all detection patterns and exit
  --verbose               Verbose output
  -v, --version           Show version
  -h, --help              Show help
```

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

**Walk with the void.** EXORR Security
