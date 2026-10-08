import pytest

from mcp_hub.webhooks import Event
from mcp_hub.workflows import Step, Workflow, render


def test_render_paths_and_types():
    ctx = {"event": {"payload": {"issue": {"title": "Bug", "number": 7}}}, "steps": [{"result": {"count": 3}}]}
    assert render("New: {event.payload.issue.title} #{event.payload.issue.number}", ctx) == "New: Bug #7"
    assert render({"a": ["{steps.0.result.count} open"]}, ctx) == {"a": ["3 open"]}
    assert render("{event.payload.missing}", ctx) == ""
    assert render("{{literal}}", ctx) == "{literal}"


async def test_github_issue_opened_posts_to_slack(hub, http, connect_all, alice, sandbox):
    await connect_all(alice)
    ev = Event("github", "github.issues.opened", "github:1",
               {"action": "opened", "issue": {"title": "Login broken", "html_url": "https://gh/1"}})
    runs = await hub.workflows.handle_event(ev)
    assert [r.workflow for r in runs] == ["github-issue-to-slack"]
    assert runs[0].status == "succeeded"
    assert sandbox.slack_messages[-1] == {"channel": "#eng", "text": "New issue: Login broken https://gh/1",
                                          "ts": "1.000"}


async def test_hubspot_contact_creates_followup_issue(hub, http, connect_all, alice, sandbox):
    await connect_all(alice)
    ev = Event("hubspot", "hubspot.contact.creation", "hubspot:9", {"objectId": 55})
    runs = await hub.workflows.handle_event(ev)
    assert runs[0].status == "succeeded"
    assert sandbox.issues["acme/crm-followups"][0]["title"] == "Follow up with HubSpot contact 55"


async def test_unmatched_event_runs_nothing(hub):
    assert await hub.workflows.handle_event(Event("slack", "slack.reaction_added", "s:1", {})) == []


async def test_scheduled_digest_chains_steps(hub, http, connect_all, alice, sandbox, clock):
    await connect_all(alice)
    await hub.gateway.call(alice, "github_create_issue", {"repo": "acme/app", "title": "a"})
    await hub.gateway.call(alice, "github_create_issue", {"repo": "acme/app", "title": "b"})
    assert await hub.workflows.tick() == []  # not due yet: first run is one interval after start
    clock.advance(86400)
    runs = await hub.workflows.tick()
    assert [r.workflow for r in runs] == ["daily-open-issues-digest"]
    assert sandbox.slack_messages[-1]["text"] == "Daily digest: 2 open issues in acme/app"
    assert await hub.workflows.tick() == []  # not due again until the next interval


async def test_workflow_is_subject_to_policy_and_audited(hub, http, connect_all, alice, sandbox):
    await connect_all(alice)
    hub.workflows.register(Workflow(
        name="bad", trigger="event:github.push", run_as="automation",
        steps=[Step("slack_post_message", {"channel": "#random", "text": "nope"})]))
    runs = await hub.workflows.handle_event(Event("github", "github.push", "g:2", {}))
    assert runs[0].status == "failed" and "arg_not_allowed:channel" in runs[0].error
    assert sandbox.slack_messages == []
    assert any(e.get("workflow") == "bad" and e["decision"] == "deny" for e in hub.audit.tail())


async def test_failed_step_stops_later_steps(hub, http, alice, sandbox):
    # Slack connected but GitHub not: step 1 fails, step 2 must not run.
    from conftest import connect
    await connect(hub, http, alice, "slack")
    hub.workflows.register(Workflow(
        name="two-step", trigger="event:custom.go", run_as="automation",
        steps=[Step("github_list_issues", {"repo": "acme/app"}),
               Step("slack_post_message", {"channel": "#eng", "text": "should not send"})]))
    runs = await hub.workflows.handle_event(Event("custom", "custom.go", "c:1", {}))
    assert runs[0].status == "failed" and runs[0].completed_steps == 0
    assert sandbox.slack_messages == []


def test_invalid_trigger_rejected():
    with pytest.raises(ValueError):
        Workflow(name="x", trigger="cron:* * *", run_as="automation", steps=[])
