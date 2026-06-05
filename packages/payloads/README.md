# oneforall/payloads

Catalogued, machine-readable payload library for the OneForAll security platform.
Each YAML file in this directory holds a curated set of payloads for one bug class
(XSS, SQLi, SSRF, SSTI, command injection, deserialisation, smuggling, etc.) so
the runner can serve them as templated arguments to tools like `nuclei`, `dalfox`,
`xsstrike`, `sqlmap`, `tplmap`, and similar consumers.

## Authorised use only

Payloads are for use **only** on targets where the operator has written
authorization. The Rules-of-Engagement (ROE) engine still gates which tools may
consume them; this library does not weaken scope checks. Loading a payload
pack is not the same as having permission to fire it: every consumer must pass
through `oneforall.engine.roe` first.

## Package layout

```
packages/payloads/
  README.md          # this file
  _schema.yaml       # canonical schema reference
  <category>.yaml    # one bug class per file
```

Each `<category>.yaml` follows the same schema. See `_schema.yaml` for the
canonical reference, or look at any existing pack for an example.

## Schema (summary)

Top-level fields:

| Field           | Type   | Notes |
|-----------------|--------|-------|
| `id`            | string | Slug. Matches filename without `.yaml`. |
| `name`          | string | Human-readable name. |
| `version`       | string | SemVer. Bump when payloads change. |
| `category`      | string | One of: `injection`, `traversal`, `ssrf`, `deserialisation`, `smuggling`, `misconfiguration`, `auth`, `recon`. |
| `description`   | string | 2-3 sentences describing the bug class. |
| `mitre`         | list   | MITRE ATT&CK technique IDs. |
| `owasp_top10`   | list   | OWASP Top 10 (2021) or API Top 10 categories. |
| `references`    | list   | 2-5 authoritative URLs. |
| `related_tools` | list   | Tool IDs from `packages/tool-registry/tools/` that consume these. |
| `chains`        | list   | Workflow chain profile IDs this pack fits into. |
| `payloads`      | list   | The actual payloads (see below). |

Each entry in `payloads`:

| Field                 | Type   | Notes |
|-----------------------|--------|-------|
| `id`                  | string | Slug unique within the file. |
| `name`                | string | One-line title. |
| `subcategory`         | string | e.g. `reflected`, `blind`, `dom`, `csp_bypass`, `filter_bypass`. |
| `encoding`            | string | `raw`, `url`, `base64`, `unicode`, `mixed`, `html_entities`. |
| `tech_targets`        | list   | Lowercase tech stack tags (`php`, `aspnet`, `node`, ...). |
| `severity_when_works` | string | `critical`, `high`, `medium`, `low`. |
| `payload`             | string | Verbatim payload. Use `|` literal block for multi-line. |
| `notes`               | string | One-line note or `null`. |
| `source`              | string | URL or `"common knowledge"`. |

## Adding a new payload pack

1. Pick a category slug (e.g. `mass_assignment`).
2. Create `<slug>.yaml` and populate the top-level metadata.
3. Add 15-35 payloads. Use the `|` literal block for multi-line.
4. Validate:
   ```bash
   python3 -c "import yaml; yaml.safe_load(open('<slug>.yaml'))"
   ```
5. Wire it up in any chains/profiles that should reference it.

## Consuming a pack from Python

```python
import yaml
from pathlib import Path

pack = yaml.safe_load(Path("packages/payloads/xss.yaml").read_text())
for p in pack["payloads"]:
    if p["subcategory"] == "reflected" and "node" in p["tech_targets"]:
        fire(p["payload"], encoding=p["encoding"])
```

## Encoding semantics

* `raw` - send the string as-is.
* `url` - percent-encode before sending.
* `base64` - base64-encode the payload, then send.
* `unicode` - send the unicode-escaped variant (e.g. `<script>`).
* `html_entities` - HTML-entity-encode (`&lt;script&gt;`).
* `mixed` - the payload already contains a documented mix; do not re-encode.
