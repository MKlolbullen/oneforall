from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from app.core.config import get_settings


def _read_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open('r', encoding='utf-8') as handle:
        return yaml.safe_load(handle) or {}


def _truthy(value: str | None) -> bool | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    if normalized in {'1', 'true', 'yes', 'on', 'enabled'}:
        return True
    if normalized in {'0', 'false', 'no', 'off', 'disabled'}:
        return False
    return None


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _apply_env_overrides(config: dict[str, Any]) -> dict[str, Any]:
    """Apply Sn1per-style environment overrides without making env vars the canonical config layer."""
    override: dict[str, Any] = {}

    runtime_map = {
        'ENABLE_AUTO_UPDATES': 'enable_auto_updates',
        'REPORT': 'report_enabled',
        'LOOT': 'loot_enabled',
        'MAX_HOSTS': 'max_hosts',
        'THREADS': 'threads',
        'MAX_JAVASCRIPT_FILES': 'max_javascript_files',
    }
    for env_name, key in runtime_map.items():
        raw = os.getenv(env_name)
        if raw is None:
            continue
        val_bool = _truthy(raw)
        if val_bool is not None:
            override.setdefault('runtime', {})[key] = val_bool
        else:
            try:
                override.setdefault('runtime', {})[key] = int(raw)
            except ValueError:
                override.setdefault('runtime', {})[key] = raw

    plugin_env_map = {
        'NUCLEI': ('plugins', 'active_web', 'nuclei'),
        'DIRSEARCH': ('plugins', 'active_web', 'dirsearch'),
        'NIKTO': ('plugins', 'active_web', 'nikto'),
        'WPSCAN': ('plugins', 'active_web', 'wpscan'),
        'BURP_SCAN': ('plugins', 'dynamic_application_scanners', 'burp_scan'),
        'ZAP_SCAN': ('plugins', 'dynamic_application_scanners', 'zap_scan'),
        'OPENVAS': ('integrations', 'openvas', 'enabled'),
        'NESSUS': ('integrations', 'nessus', 'enabled'),
        'SUBFINDER': ('plugins', 'recon', 'subfinder'),
        'AMASS': ('plugins', 'recon', 'amass'),
        'SUBLIST3R': ('plugins', 'recon', 'sublist3r'),
        'CRTSH': ('plugins', 'recon', 'crtsh'),
        'SHODAN': ('plugins', 'recon', 'shodan'),
        'GITHUB_SUBDOMAINS': ('plugins', 'recon', 'github_subdomains'),
        'THEHARVESTER': ('plugins', 'osint', 'theharvester'),
        'METAGOOFIL': ('plugins', 'osint', 'metagoofil'),
        'URLSCANIO': ('plugins', 'osint', 'urlscanio'),
        'SLACK_NOTIFICATIONS': ('integrations', 'slack', 'enabled'),
    }
    for env_name, path in plugin_env_map.items():
        value = _truthy(os.getenv(env_name))
        if value is None:
            continue
        cursor = override
        for part in path[:-1]:
            cursor = cursor.setdefault(part, {})
        cursor[path[-1]] = value

    oos = os.getenv('OUT_OF_SCOPE')
    if oos:
        override.setdefault('scope', {})['default_out_of_scope'] = [item.strip() for item in oos.split(',') if item.strip()]

    return _deep_merge(config, override)


@lru_cache
def load_platform_config() -> dict[str, Any]:
    settings = get_settings()
    return _apply_env_overrides(_read_yaml(settings.platform_config_path))


@lru_cache
def load_grep_patterns() -> dict[str, Any]:
    return _read_yaml(get_settings().grep_patterns_path)


def list_wordlists() -> list[dict[str, Any]]:
    root = get_settings().wordlists_dir
    items: list[dict[str, Any]] = []
    if not root.exists():
        return items
    for path in sorted(root.glob('*.txt')):
        try:
            lines = [line.strip() for line in path.read_text(encoding='utf-8').splitlines() if line.strip() and not line.strip().startswith('#')]
            size = path.stat().st_size
        except OSError:
            continue
        items.append({
            'name': path.name,
            'path': str(path),
            'entries': len(lines),
            'size_bytes': size,
            'sample': lines[:8],
        })
    return items


def plugin_matrix() -> list[dict[str, Any]]:
    config = load_platform_config()
    rows: list[dict[str, Any]] = []
    for group, plugins in (config.get('plugins') or {}).items():
        if not isinstance(plugins, dict):
            continue
        for plugin, enabled in plugins.items():
            rows.append({'group': group, 'plugin': plugin, 'enabled': bool(enabled)})
    return sorted(rows, key=lambda item: (item['group'], item['plugin']))


def clear_platform_config_cache() -> None:
    load_platform_config.cache_clear()
    load_grep_patterns.cache_clear()
