"""Event-driven and scheduled workflows.

A workflow is a list of tool calls run as a service principal, so every step
goes through the same policy, token refresh and audit path as a direct tool
call. Step arguments are templates: `{event.payload.issue.title}` reads the
triggering event, `{steps.0.result.0.number}` reads an earlier step's result.

Triggers: `event:<event.type>` or `interval:<seconds>`.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

from .gateway import ToolGateway
from .policy import Principal
from .webhooks import Event

def _lookup(ctx: dict, path: str):
    cur: object = ctx
    for part in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list) and part.isdigit():
            cur = cur[int(part)] if int(part) < len(cur) else None
        elif isinstance(cur, list) and part == "length":
            cur = len(cur)
        else:
            return None
        if cur is None:
            return None
    return cur


def render(value, ctx: dict):
    """Fill `{a.b.0.c}` placeholders from ctx; `{{x}}` is a literal `{x}`; missing paths render as ""."""
    if isinstance(value, str):
        def repl(m: re.Match) -> str:
            if m.group(1):
                return "{" + m.group(1) + "}"
            found = _lookup(ctx, m.group(2))
            return "" if found is None else str(found)
        return re.sub(r"\{\{([A-Za-z0-9_.]+)\}\}|\{([A-Za-z0-9_.]+)\}", repl, value)
    if isinstance(value, dict):
        return {k: render(v, ctx) for k, v in value.items()}
    if isinstance(value, list):
        return [render(v, ctx) for v in value]
    return value


@dataclass
class Step:
    tool: str
    args: dict


@dataclass
class Workflow:
    name: str
    trigger: str
    run_as: str
    steps: list[Step]
    tenant: str = "acme"

    def __post_init__(self):
        kind, _, arg = self.trigger.partition(":")
        if kind not in ("event", "interval") or not arg or (kind == "interval" and not arg.isdigit()):
            raise ValueError(f"bad trigger {self.trigger!r}; use 'event:<type>' or 'interval:<seconds>'")


@dataclass
class WorkflowRun:
    workflow: str
    status: str  # succeeded | failed
    completed_steps: int
    error: str | None = None
    results: list = field(default_factory=list)


class WorkflowEngine:
    def __init__(self, gateway: ToolGateway, role: str = "operator", clock=time.time):
        self.gateway, self.role, self.clock = gateway, role, clock
        self.workflows: list[Workflow] = []
        self.last_run: dict[str, float] = {}

    def register(self, wf: Workflow) -> None:
        self.workflows.append(wf)
        if wf.trigger.startswith("interval:"):
            self.last_run[wf.name] = self.clock()  # first run is one interval after registration

    def _principal(self, wf: Workflow) -> Principal:
        return Principal(id=wf.run_as, tenant=wf.tenant, roles=frozenset({self.role}))

    async def _run(self, wf: Workflow, event: Event | None) -> WorkflowRun:
        ctx: dict = {"event": {"type": event.type, "payload": event.payload} if event else {}, "steps": []}
        results = []
        for i, step in enumerate(wf.steps):
            args = render(step.args, ctx)
            try:
                result = await self.gateway.call(self._principal(wf), step.tool, args, workflow=wf.name)
            except Exception as e:
                return WorkflowRun(wf.name, "failed", i, f"{type(e).__name__}: {e}", results)
            results.append(result)
            ctx["steps"].append({"result": result})
        return WorkflowRun(wf.name, "succeeded", len(wf.steps), None, results)

    async def handle_event(self, event: Event) -> list[WorkflowRun]:
        runs = []
        for wf in self.workflows:
            if wf.trigger == f"event:{event.type}":
                runs.append(await self._run(wf, event))
        return runs

    async def tick(self) -> list[WorkflowRun]:
        now = self.clock()
        runs = []
        for wf in self.workflows:
            if not wf.trigger.startswith("interval:"):
                continue
            every = int(wf.trigger.split(":")[1])
            if now - self.last_run[wf.name] < every:
                continue
            self.last_run[wf.name] = now
            runs.append(await self._run(wf, None))
        return runs


def default_workflows() -> list[Workflow]:
    return [
        Workflow("github-issue-to-slack", "event:github.issues.opened", "automation", [
            Step("slack_post_message", {"channel": "#eng",
                                        "text": "New issue: {event.payload.issue.title} {event.payload.issue.html_url}"}),
        ]),
        Workflow("hubspot-contact-to-github", "event:hubspot.contact.creation", "automation", [
            Step("github_create_issue", {"repo": "acme/crm-followups",
                                         "title": "Follow up with HubSpot contact {event.payload.objectId}",
                                         "body": "Created from webhook {event.type}."}),
        ]),
        Workflow("daily-open-issues-digest", "interval:86400", "automation", [
            Step("github_list_issues", {"repo": "acme/app", "state": "open"}),
            Step("slack_post_message", {"channel": "#eng",
                                        "text": "Daily digest: {steps.0.result.length} open issues in acme/app"}),
        ]),
    ]
