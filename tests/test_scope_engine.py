from app.services.scope_engine import ScopeEngine, ScopeAction


POLICY = {
    "allowed": {
        "domains": ["example.com", "*.example.com"],
        "cidrs": ["10.10.0.0/16"],
        "ports": [80, 443, 8080],
    },
    "denied": {
        "domains": ["admin.example.com"],
        "cidrs": ["10.10.50.0/24"],
        "paths": ["/delete", "/logout"],
        "methods": ["DELETE", "TRACE"],
    },
    "limits": {"max_rps": 5},
    "approval": {
        "require_for_risk": ["high_active", "destructive"],
        "require_for_tools": ["sqlmap", "commix", "metasploit"],
    },
}


def engine():
    return ScopeEngine(POLICY)


def test_exact_domain_allowed():
    assert engine().evaluate_action(ScopeAction(target="example.com", port=443)).decision == "allow"


def test_wildcard_domain_allowed():
    assert engine().evaluate_action(ScopeAction(target="api.example.com", port=443)).decision == "allow"


def test_denied_domain_wins():
    assert engine().evaluate_action(ScopeAction(target="admin.example.com", port=443)).decision == "deny"


def test_cidr_allowed():
    assert engine().evaluate_action(ScopeAction(target="10.10.10.5", port=443)).decision == "allow"


def test_denied_cidr_wins():
    assert engine().evaluate_action(ScopeAction(target="10.10.50.5", port=443)).decision == "deny"


def test_path_denied():
    assert engine().evaluate_action(ScopeAction(target="https://api.example.com/delete", method="GET")).decision == "deny"


def test_method_denied():
    assert engine().evaluate_action(ScopeAction(target="api.example.com", method="DELETE")).decision == "deny"


def test_port_denied_if_not_in_allowlist():
    assert engine().evaluate_action(ScopeAction(target="api.example.com", port=22)).decision == "deny"


def test_high_risk_requires_approval():
    assert engine().evaluate_action(ScopeAction(target="api.example.com", risk="high_active")).decision == "require_approval"


def test_high_risk_allowed_with_approval():
    assert engine().evaluate_action(ScopeAction(target="api.example.com", risk="high_active", manual_approval=True)).decision == "allow"


def test_rate_limit():
    assert engine().evaluate_action(ScopeAction(target="api.example.com", requested_rps=50)).decision == "rate_limit"
