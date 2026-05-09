"""OneForAll v2 — 10-stage bug bounty / pentest automation."""

__version__ = "2.0.0"

STAGES = [
    "s01_passive",
    "s02_active",
    "s03_techscan",
    "s04_crawl",
    "s05_secrets",
    "s06_fuzz",
    "s07_api",
    "s08_urlsort",
    "s09_vuln",
    "s10_report",
]

GATED_STAGES = {"s07_api", "s09_vuln"}
