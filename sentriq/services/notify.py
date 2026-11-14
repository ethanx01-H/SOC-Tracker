"""Outbound notifications: email and Microsoft Teams.

Two rules shape this module:

* A notification must never fail a ticket action. Sending happens on a daemon
  thread and every error is logged, not raised — an SMTP outage must not stop an
  analyst from assigning a ticket.
* Nothing is sent unless it is configured. With no SMTP host and no Teams
  webhook the module is inert, which is what the pilot needs.
"""

import logging
import smtplib
import threading
from email.message import EmailMessage

import httpx

from ..config import (
    NOTIFY_EMAIL_FROM,
    NOTIFY_EMAIL_TO,
    NOTIFY_MIN_SEVERITY,
    NOTIFY_ON_ASSIGN,
    NOTIFY_ON_ESCALATE,
    NOTIFY_TEAMS_WEBHOOK,
    SMTP_HOST,
    SMTP_PASSWORD,
    SMTP_PORT,
    SMTP_STARTTLS,
    SMTP_USER,
)

logger = logging.getLogger("sentriq.notify")

SEVERITY_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}


def enabled() -> dict:
    return {
        "email": bool(SMTP_HOST and NOTIFY_EMAIL_TO),
        "teams": bool(NOTIFY_TEAMS_WEBHOOK),
        "on_assign": NOTIFY_ON_ASSIGN,
        "on_escalate": NOTIFY_ON_ESCALATE,
        "min_severity": NOTIFY_MIN_SEVERITY,
    }


def _should_send(alert, event: str) -> bool:
    if event == "assign" and not NOTIFY_ON_ASSIGN:
        return False
    if event == "escalate" and not NOTIFY_ON_ESCALATE:
        return False
    if event == "created":
        # Only the loud ones: a mailbox full of Informational alerts gets muted.
        return SEVERITY_RANK.get(alert.severity, 4) <= SEVERITY_RANK.get(NOTIFY_MIN_SEVERITY, 1)
    return True


def compose(alert, event: str, actor: str | None, base_url: str | None = None) -> tuple[str, str]:
    subject = f"[{alert.severity}] {alert.alert_id} {alert.title}"
    link = f"{base_url.rstrip('/')}{alert.get_absolute_url()}" if base_url else alert.get_absolute_url()
    lines = [
        f"Ticket:   {alert.alert_id} — {alert.title}",
        f"Severity: {alert.severity}",
        f"Status:   {alert.status}",
        f"Asset:    {alert.asset}",
        f"Analyst:  {alert.analyst}",
        f"Event:    {event}" + (f" by {actor}" if actor else ""),
        "",
        alert.description or "(no description)",
        "",
        f"Open: {link}",
    ]
    return subject, "\n".join(lines)


def _send_email(subject: str, body: str) -> None:
    message = EmailMessage()
    message["From"] = NOTIFY_EMAIL_FROM or SMTP_USER
    message["To"] = ", ".join(NOTIFY_EMAIL_TO)
    message["Subject"] = subject
    message.set_content(body)
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
        if SMTP_STARTTLS:
            server.starttls()
        if SMTP_USER:
            server.login(SMTP_USER, SMTP_PASSWORD or "")
        server.send_message(message)


def _send_teams(subject: str, body: str) -> None:
    # MessageCard shape, which Teams incoming webhooks accept without extra setup.
    payload = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": subject,
        "title": subject,
        "text": body.replace("\n", "\n\n"),
    }
    response = httpx.post(NOTIFY_TEAMS_WEBHOOK, json=payload, timeout=10)
    response.raise_for_status()


def _deliver(subject: str, body: str) -> None:
    if SMTP_HOST and NOTIFY_EMAIL_TO:
        try:
            _send_email(subject, body)
        except Exception as error:
            logger.error("Email notification failed: %s", error)
    if NOTIFY_TEAMS_WEBHOOK:
        try:
            _send_teams(subject, body)
        except Exception as error:
            logger.error("Teams notification failed: %s", error)


def notify(alert, event: str, actor: str | None = None, base_url: str | None = None) -> None:
    """Queue a notification. Never blocks the request and never raises."""
    if not (SMTP_HOST and NOTIFY_EMAIL_TO) and not NOTIFY_TEAMS_WEBHOOK:
        return
    if not _should_send(alert, event):
        return
    subject, body = compose(alert, event, actor, base_url)
    threading.Thread(
        target=_deliver, args=(subject, body), name="soc-notify", daemon=True
    ).start()
