import pytest

from mcp_hub.policy import PolicyEngine, Principal, load_default_policy


@pytest.fixture
def engine(clock):
    return PolicyEngine(load_default_policy(), clock=clock)


def P(*roles, tenant="acme"):
    return Principal(id="u", tenant=tenant, roles=frozenset(roles))


def test_viewer_can_read_not_write(engine):
    assert engine.evaluate(P("viewer"), "github_list_issues", {"repo": "acme/app"}).allowed
    d = engine.evaluate(P("viewer"), "slack_post_message", {"channel": "#eng", "text": "hi"})
    assert not d.allowed and d.reason == "role_not_permitted"


def test_operator_inherits_viewer(engine):
    assert engine.evaluate(P("operator"), "slack_list_channels", {}).allowed
    assert engine.evaluate(P("operator"), "slack_post_message", {"channel": "#eng", "text": "hi"}).allowed


def test_unknown_tool_default_deny(engine):
    d = engine.evaluate(P("admin"), "drop_database", {})
    assert not d.allowed and d.reason == "unknown_tool"


def test_no_roles_denied(engine):
    assert not engine.evaluate(P(), "github_list_issues", {"repo": "acme/app"}).allowed


def test_arg_allowlist_applies_even_to_admin(engine):
    d = engine.evaluate(P("admin"), "slack_post_message", {"channel": "#random", "text": "hi"})
    assert not d.allowed and d.reason == "arg_not_allowed:channel"


def test_arg_pattern(engine):
    assert engine.evaluate(P("operator"), "github_create_issue", {"repo": "acme/app", "title": "t"}).allowed
    d = engine.evaluate(P("operator"), "github_create_issue", {"repo": "evil/app", "title": "t"})
    assert not d.allowed and d.reason == "arg_not_allowed:repo"


def test_missing_constrained_arg_denied(engine):
    d = engine.evaluate(P("operator"), "github_create_issue", {"title": "t"})
    assert not d.allowed and d.reason == "arg_not_allowed:repo"


def test_rate_limit_per_principal_and_tool(engine, clock):
    args = {"repo": "acme/app", "title": "t"}
    results = [engine.evaluate(P("operator"), "github_create_issue", args).allowed for _ in range(6)]
    assert results == [True] * 5 + [False]
    assert engine.evaluate(P("operator"), "github_create_issue", args).reason == "rate_limited"
    other = Principal(id="someone-else", tenant="acme", roles=frozenset({"operator"}))
    assert engine.evaluate(other, "github_create_issue", args).allowed
    clock.advance(61)
    assert engine.evaluate(P("operator"), "github_create_issue", args).allowed


def test_denied_calls_do_not_consume_rate_limit(engine):
    bad = {"repo": "evil/app", "title": "t"}
    for _ in range(10):
        engine.evaluate(P("operator"), "github_create_issue", bad)
    assert engine.evaluate(P("operator"), "github_create_issue", {"repo": "acme/app", "title": "t"}).allowed


def test_policy_validation_rejects_unknown_inherit():
    with pytest.raises(ValueError):
        PolicyEngine({"roles": {"a": {"inherits": ["missing"], "tools": []}}, "tools": {}})


def test_tools_for_role_listing(engine):
    assert "slack_post_message" not in engine.tools_for(P("viewer"))
    assert "slack_post_message" in engine.tools_for(P("operator"))
