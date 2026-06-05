"""Tests for the secret scanner."""
import tempfile
from pathlib import Path

from exorr_secret_scanner.scanner import SecretScanner
from exorr_secret_scanner.patterns import SECRET_PATTERNS


def test_detects_aws_key():
    """Scanner should detect AWS access keys."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = Path(tmpdir)
        key_str = "AKIA" + "A" * 16
        (repo / "aws_config.py").write_text(f"key = {repr(key_str)}\n")
        scanner = SecretScanner(target=str(repo))
        result = scanner.scan()
        aws = [f for f in result.findings if f.pattern_id == "aws-access-key" and not f.is_false_positive]
        assert len(aws) >= 1


def test_detects_private_key():
    """Scanner should detect private key blocks."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = Path(tmpdir)
        # Use realistic PEM header that the regex matches
        (repo / "id_rsa").write_text("-----BEGIN RSA PRIVATE KEY-----\nFAKEDATA\n-----END RSA PRIVATE KEY-----\n")
        scanner = SecretScanner(target=str(repo))
        result = scanner.scan()
        pk = [f for f in result.findings if f.pattern_id == "private-key"]
        assert len(pk) >= 1


def test_detects_github_token():
    """Scanner should detect GitHub PAT tokens."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = Path(tmpdir)
        token = "ghp_" + "A" * 36
        (repo / "config.yml").write_text(f"token: {token}\n")
        scanner = SecretScanner(target=str(repo))
        result = scanner.scan()
        gh = [f for f in result.findings if f.pattern_id == "github-token"]
        assert len(gh) >= 1


def test_skips_binary_files():
    """Scanner should skip binary/skipped file types."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = Path(tmpdir)
        (repo / "main.py").write_text("print hello\n")
        (repo / "image.png").write_bytes(b"\x89PNG" + b"\x00" * 100)
        scanner = SecretScanner(target=str(repo))
        result = scanner.scan()
        assert result.files_skipped >= 1


def test_skips_node_modules():
    """Scanner should skip node_modules directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = Path(tmpdir)
        nm = repo / "node_modules" / "pkg"
        nm.mkdir(parents=True)
        (nm / "index.js").write_text("var x = 1\n")
        (repo / "app.py").write_text("print hello\n")
        scanner = SecretScanner(target=str(repo))
        result = scanner.scan()
        nm_findings = [f for f in result.findings if "node_modules" in f.file]
        assert len(nm_findings) == 0


def test_false_positive_detection():
    """Scanner should flag example/placeholder patterns as FP."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = Path(tmpdir)
        (repo / "example.py").write_text('api_key = "your-api-key-here-really-long-value-xxxx"\n')
        scanner = SecretScanner(target=str(repo))
        result = scanner.scan()
        fp = [f for f in result.findings if f.is_false_positive]
        assert len(fp) >= 1


def test_detects_hardcoded_password():
    """Scanner should detect hardcoded passwords."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = Path(tmpdir)
        (repo / "auth.py").write_text('password = "SuperSecret123!"\n')
        scanner = SecretScanner(target=str(repo))
        result = scanner.scan()
        pw = [f for f in result.findings if f.pattern_id == "password-in-code"]
        assert len(pw) >= 1


def test_list_patterns():
    """All patterns should have required fields."""
    for p in SECRET_PATTERNS:
        assert "id" in p
        assert "name" in p
        assert "severity" in p
        assert "pattern" in p
        assert "description" in p
