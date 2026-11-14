"""``secrets.scan``: scan your own source tree for hardcoded credentials.

Walks a file or directory target (read-only, never following symlinks),
detects likely secrets with the scanner engine, and raises one finding per
detected secret. The secret value is masked everywhere — finding title,
component, evidence — so running this never writes a credential anywhere.

Skips common vendored/build directories and files that look binary or exceed
a size cap, so a scan stays fast and quiet.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping
from pathlib import Path

from nxtsec.core.errors import PluginError
from nxtsec.core.models import Confidence, Finding, Severity, Target, TargetType
from nxtsec.plugins.base import (
    ModuleContext,
    ModuleResult,
    Permission,
    Plugin,
    PluginManifest,
    RiskLevel,
    option_lookup,
    parse_int_option,
)
from nxtsec.scanners.secrets import SecretMatch, scan_text

NAME = "secrets.scan"

SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        "dist",
        "build",
        ".tox",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        "vendor",
        "target",
        ".next",
        ".cache",
        "site-packages",
    }
)
SKIP_SUFFIXES = frozenset(
    {
        ".min.js",
        ".map",
        ".lock",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".ico",
        ".pdf",
        ".zip",
        ".gz",
        ".tar",
        ".tgz",
        ".bz2",
        ".xz",
        ".7z",
        ".jar",
        ".war",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".mp3",
        ".mp4",
        ".mov",
        ".avi",
        ".bin",
        ".so",
        ".dll",
        ".dylib",
        ".exe",
        ".class",
        ".pyc",
        ".o",
        ".a",
        ".wasm",
    }
)
DEFAULT_MAX_BYTES = 2 * 1024 * 1024
_SEVERITY = {s.value: s for s in Severity}


def looks_binary(chunk: bytes) -> bool:
    if b"\x00" in chunk:
        return True
    if not chunk:
        return False
    # high proportion of non-text bytes
    text = bytes(range(32, 127)) + b"\t\n\r\f\b"
    nontext = sum(b not in text for b in chunk)
    return nontext / len(chunk) > 0.30


class SecretsScan(Plugin):
    manifest = PluginManifest(
        name=NAME,
        version="0.1.0",
        description="Scan a file or source tree for hardcoded secrets (values masked)",
        category="secrets",
        author="NXT-Security",
        permissions=frozenset({Permission.READ_ONLY, Permission.LOCAL_FILES}),
        risk_level=RiskLevel.PASSIVE,
        target_types=frozenset({TargetType.FILE}),
    )

    @classmethod
    def validate_options(cls, options: Mapping[str, str]) -> None:
        mf = option_lookup(options, NAME, "max_files")
        if mf is not None:
            parse_int_option(mf, "max_files", 10000, 1, 1_000_000)

    def run(self, target: Target | None, ctx: ModuleContext) -> ModuleResult:
        ctx.require(Permission.LOCAL_FILES)
        assert target is not None
        max_files = ctx.option_int("max_files", 10000, 1, 1_000_000)
        max_bytes = ctx.option_int("max_bytes", DEFAULT_MAX_BYTES, 1024, 64 * 1024 * 1024)
        root = Path(target.value)
        res = ModuleResult()

        try:
            st = root.lstat()
        except OSError as exc:
            raise PluginError(f"cannot access {root}: {exc}") from exc
        if stat.S_ISLNK(st.st_mode):
            res.errors.append(f"{root} is a symlink; not following")
            return res

        scanned = 0
        if stat.S_ISREG(st.st_mode):
            self._scan_file(root, root, res, max_bytes)
        elif stat.S_ISDIR(st.st_mode):
            for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
                dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
                ctx.check_cancelled()
                for fname in sorted(filenames):
                    if scanned >= max_files:
                        res.errors.append(f"stopped after max_files={max_files}")
                        return self._finalize(res, scanned, ctx)
                    p = Path(dirpath) / fname
                    if p.is_symlink() or p.suffix.lower() in SKIP_SUFFIXES:
                        continue
                    if any(fname.endswith(sfx) for sfx in (".min.js", ".map")):
                        continue
                    self._scan_file(p, root, res, max_bytes)
                    scanned += 1
        else:
            raise PluginError(f"{root} is not a regular file or directory")
        return self._finalize(res, scanned, ctx)

    def _finalize(self, res: ModuleResult, scanned: int, ctx: ModuleContext) -> ModuleResult:
        ctx.logger.info(f"scanned {scanned} file(s), {len(res.findings)} secret finding(s)")
        return res

    def _scan_file(self, path: Path, root: Path, res: ModuleResult, max_bytes: int) -> None:
        try:
            if path.stat().st_size > max_bytes:
                return
            raw = path.read_bytes()
        except OSError as exc:
            res.errors.append(f"{path}: {exc.strerror or exc}")
            return
        if looks_binary(raw[:4096]):
            return
        text = raw.decode("utf-8", errors="replace")
        try:
            rel = str(path.relative_to(root)) if root.is_dir() else path.name
        except ValueError:
            rel = str(path)
        for match in scan_text(text):
            res.findings.append(self._finding(match, path, rel))

    @staticmethod
    def _finding(match: SecretMatch, path: Path, rel: str) -> Finding:
        severity = _SEVERITY.get(match.severity, Severity.MEDIUM)
        where = f"{rel}:{match.line}"
        return Finding(
            title=f"{match.description} in {where}",
            severity=severity,
            target=str(path),
            detection_module="",
            confidence=Confidence.FIRM if match.rule != "high_entropy" else Confidence.TENTATIVE,
            component=f"{match.rule} {match.masked}",
            cwe="CWE-798",
            description=f"A likely hardcoded secret ({match.rule}) was found at {where}. "
            f"Masked context: {match.context}",
            impact="A credential committed to source can be read by anyone with repository "
            "access and may grant access to production systems.",
            remediation="Remove the secret from source, rotate it immediately, and load it from "
            "an environment variable or a secrets manager at runtime. Add a pre-commit "
            "secret scan to prevent recurrence.",
            references=[
                "https://cwe.mitre.org/data/definitions/798.html",
                "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
            ],
        )
