"""Microsoft Teams via Workflows ("Post to a channel when a webhook request is received").

Legacy Office 365 connectors are retired: we send an Adaptive Card wrapped in a
'message' envelope, which is the payload shape the Workflows trigger accepts.
"""

from __future__ import annotations

import logging

import httpx

from cti.notifiers.message import T, AlertMessage, exploit_lines

log = logging.getLogger(__name__)

PRIORITY_STYLE = {"P1": "attention", "P2": "warning", "P3": "accent"}


def adaptive_card(msg: AlertMessage) -> dict:
    t = T[msg.lang]

    def section(title: str, lines: list[str]) -> list[dict]:
        if not lines:
            return []
        return [
            {"type": "TextBlock", "text": title, "weight": "Bolder", "spacing": "Medium"},
            {"type": "TextBlock", "text": "\n".join(f"- {line}" for line in lines), "wrap": True},
        ]

    body: list[dict] = [
        {
            "type": "Container",
            "style": PRIORITY_STYLE.get(msg.priority, "default"),
            "items": [
                {"type": "TextBlock", "text": f"{msg.priority} · {msg.title}", "weight": "Bolder", "size": "Medium", "wrap": True},
                {"type": "TextBlock", "text": f"{t['sla']}: {msg.sla}" if msg.sla else "", "isSubtle": True, "spacing": "None"},
            ],
        },
        {"type": "TextBlock", "text": msg.summary, "wrap": True},
        *section(t["why"], msg.why),
        *section(t["clients"], msg.clients or [t["none"]]),
        *section(t["action"], msg.actions),
        {"type": "FactSet", "facts": [{"title": t["evidence"], "value": msg.evidence}, {"title": t["changes"], "value": ", ".join(msg.changes)}]},
        *section(t["exploits"], exploit_lines(msg.exploit_sources, msg.lang)),
        *section(t["conflict"], msg.conflicts),
        *section(t["sources"], [f"[{s['label']}]({s['url']})" for s in msg.sources]),
    ]
    return {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": None,
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "msteams": {"width": "Full"},
                    "body": body,
                    "actions": [
                        {"type": "Action.OpenUrl", "title": s["label"][:40], "url": s["url"]} for s in msg.sources[:3]
                    ],
                },
            }
        ],
    }


def send_teams(webhook_url: str, msg: AlertMessage, *, client: httpx.Client | None = None) -> tuple[bool, str | None]:
    payload = adaptive_card(msg)
    own = client is None
    client = client or httpx.Client(timeout=20)
    try:
        r = client.post(webhook_url, json=payload)
        if r.status_code >= 300:
            # Never log the webhook URL (it is a secret).
            return False, f"HTTP {r.status_code}: {r.text[:300]}"
        return True, None
    except httpx.HTTPError as e:
        return False, f"{type(e).__name__}"
    finally:
        if own:
            client.close()
