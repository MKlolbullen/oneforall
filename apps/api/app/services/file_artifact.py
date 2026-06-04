"""Classify discovered URLs into file-artifact kinds.

Many recon tools surface URLs that aren't just "an endpoint" but a
specific kind of file the operator probably wants to look at — a
sourcemap (often leaks the original TS source), a backup archive, an
exposed env file, a keystore. Calling them out as `file` artifacts lets
the Artifacts tab group them and lets the Loot pipeline elevate the
juicy ones.

The classification is conservative: each kind has a regex that matches
the URL path. We don't fetch the content here — the artifact ledger
records the *reference* (URL + kind + heuristic) so the operator (or a
follow-up tool) can decide whether to download.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

# Map kind -> (severity hint, path regex). Severity is a *suggestion* —
# the normalizer can still escalate based on context.
_FILE_KIND_RULES: list[tuple[str, str, re.Pattern[str]]] = [
    # (kind, severity_hint, path-matching regex applied case-insensitively)
    ("env_file", "critical", re.compile(r"(^|/)(\.env(\.[a-z0-9_-]+)?|environment\.json)$", re.IGNORECASE)),
    ("private_key", "critical", re.compile(r"\.(pem|key|p12|pfx|jks|asc)$", re.IGNORECASE)),
    ("ssh_key", "critical", re.compile(r"(^|/)(id_rsa|id_ed25519|id_ecdsa|id_dsa|authorized_keys)(\.pub)?$", re.IGNORECASE)),
    ("git_metadata", "high", re.compile(r"(^|/)\.git/(config|HEAD|index|packed-refs|logs/HEAD)$", re.IGNORECASE)),
    ("git_directory", "high", re.compile(r"(^|/)\.git/?$", re.IGNORECASE)),
    ("svn_metadata", "high", re.compile(r"(^|/)\.svn/(entries|wc\.db)$", re.IGNORECASE)),
    ("ds_store", "medium", re.compile(r"(^|/)\.DS_Store$", re.IGNORECASE)),
    ("source_map", "high", re.compile(r"\.(map)(\?|$)", re.IGNORECASE)),
    ("js_bundle", "info", re.compile(r"\.(bundle|chunk|min)\.js(\?|$)", re.IGNORECASE)),
    ("aws_credentials", "critical", re.compile(r"(^|/)(\.aws/credentials|aws-credentials\.[a-z]+)$", re.IGNORECASE)),
    ("kubeconfig", "critical", re.compile(r"(^|/)(\.kube/config|kubeconfig(\.[a-z]+)?)$", re.IGNORECASE)),
    ("docker_config", "high", re.compile(r"(^|/)(\.docker/config\.json|docker-compose\.ya?ml|Dockerfile)$", re.IGNORECASE)),
    ("terraform_state", "critical", re.compile(r"\.tfstate(\.backup)?$", re.IGNORECASE)),
    ("ci_config", "medium", re.compile(r"(^|/)(\.github/workflows/.+\.ya?ml|\.gitlab-ci\.ya?ml|\.circleci/config\.ya?ml|Jenkinsfile|bitbucket-pipelines\.ya?ml)$", re.IGNORECASE)),
    ("npm_lock", "info", re.compile(r"(^|/)(package-lock\.json|pnpm-lock\.ya?ml|yarn\.lock)$", re.IGNORECASE)),
    ("npm_manifest", "low", re.compile(r"(^|/)package\.json$", re.IGNORECASE)),
    ("python_lock", "info", re.compile(r"(^|/)(poetry\.lock|Pipfile\.lock|requirements(-[a-z]+)?\.txt|pyproject\.toml)$", re.IGNORECASE)),
    ("go_module", "low", re.compile(r"(^|/)(go\.mod|go\.sum)$", re.IGNORECASE)),
    ("rust_manifest", "low", re.compile(r"(^|/)(Cargo\.toml|Cargo\.lock)$", re.IGNORECASE)),
    ("config_xml", "low", re.compile(r"(^|/)(web\.config|app\.config|server\.xml|context\.xml)$", re.IGNORECASE)),
    ("config_yaml", "low", re.compile(r"(^|/)(application\.ya?ml|config\.ya?ml|settings\.ya?ml)$", re.IGNORECASE)),
    ("dotfile", "low", re.compile(r"(^|/)(\.htpasswd|\.htaccess|\.npmrc|\.netrc|\.bash_history|\.zsh_history)$", re.IGNORECASE)),
    ("archive", "medium", re.compile(r"\.(zip|tar|tar\.gz|tgz|tar\.bz2|7z|rar)(\?|$)", re.IGNORECASE)),
    ("database_dump", "critical", re.compile(r"\.(sql|sqlite|db|mdb|bak|sql\.gz)(\?|$)", re.IGNORECASE)),
    ("backup_file", "high", re.compile(r"\.(bak|backup|old|orig|copy|swp|swo|tmp)(\?|$)", re.IGNORECASE)),
    ("log_file", "low", re.compile(r"\.(log|log\.\d+|log\.gz)(\?|$)", re.IGNORECASE)),
    ("certificate", "high", re.compile(r"\.(crt|cer|der|p7b|p7c)(\?|$)", re.IGNORECASE)),
    ("apk", "medium", re.compile(r"\.(apk|aab|ipa)(\?|$)", re.IGNORECASE)),
    ("source_archive", "high", re.compile(r"\.(tar\.gz|tgz|zip)$", re.IGNORECASE)),
    ("office_doc", "low", re.compile(r"\.(docx?|xlsx?|pptx?|odt|ods|odp)(\?|$)", re.IGNORECASE)),
    ("pdf", "low", re.compile(r"\.pdf(\?|$)", re.IGNORECASE)),
]


@dataclass(frozen=True)
class FileArtifactHint:
    """A discovered URL classified as some kind of interesting file."""
    kind: str
    severity_hint: str
    url: str
    path: str

    def as_meta(self) -> dict[str, str]:
        return {
            "kind": self.kind,
            "severity_hint": self.severity_hint,
            "url": self.url,
            "path": self.path,
        }


def classify_file_url(url: str) -> FileArtifactHint | None:
    """Return a hint when the URL's path matches a known file pattern."""
    if not isinstance(url, str) or not url:
        return None
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    path = parsed.path or ""
    # Strip trailing slash for cleaner matching except where the kind
    # specifically wants directory-style paths (.git/).
    target = path
    for kind, severity, pattern in _FILE_KIND_RULES:
        if pattern.search(target):
            return FileArtifactHint(kind=kind, severity_hint=severity, url=url, path=path)
    return None
