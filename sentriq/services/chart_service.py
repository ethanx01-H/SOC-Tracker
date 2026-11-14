"""Chart generation for dashboard pie charts.

The panels need counts per severity, source, analyst and tactic over the whole
filtered queue. That is four GROUP BY queries; building the same counts from a
list of every ticket was the expensive half of the dashboard.
"""

import math
from urllib.parse import urlencode

from sqlalchemy import func, select

COLORS = ["#1f6feb", "#0f766e", "#b7791f", "#b42318", "#6f42c1", "#475569", "#0891b2", "#be123c"]


def pie_path(cx: int, cy: int, radius: int, start_angle: float, end_angle: float) -> str:
    """Generate SVG path for a pie chart slice."""
    if end_angle - start_angle >= 359.99:
        return (
            f"M {cx} {cy - radius} "
            f"A {radius} {radius} 0 1 1 {cx - 0.01} {cy - radius} "
            f"A {radius} {radius} 0 1 1 {cx} {cy - radius} Z"
        )
    start = math.radians(start_angle - 90)
    end = math.radians(end_angle - 90)
    x1 = cx + radius * math.cos(start)
    y1 = cy + radius * math.sin(start)
    x2 = cx + radius * math.cos(end)
    y2 = cy + radius * math.sin(end)
    large_arc = 1 if end_angle - start_angle > 180 else 0
    return f"M {cx} {cy} L {x1:.2f} {y1:.2f} A {radius} {radius} 0 {large_arc} 1 {x2:.2f} {y2:.2f} Z"


def alerts_url(**params: str) -> str:
    return f"/alerts/?{urlencode({key: value for key, value in params.items() if value})}"


def _slices(counts: dict[str, int], href) -> dict[str, object]:
    total = sum(counts.values())
    start = 0.0
    slices = []
    for index, (label, count) in enumerate(sorted(counts.items())):
        end = start + (count / total * 360 if total else 0)
        slices.append({
            "label": label,
            "count": count,
            "percent": round(count / total * 100) if total else 0,
            "path": pie_path(50, 50, 46, start, end),
            "color": COLORS[index % len(COLORS)],
            "href": href(label),
        })
        start = end
    return {"total": total, "slices": slices}


def _count(labels) -> dict[str, int]:
    counts: dict[str, int] = {}
    for label in labels:
        label = label or "Unknown"
        counts[label] = counts.get(label, 0) + 1
    return counts


def chart_counts(alerts) -> dict[str, dict[str, object]]:
    """Chart data from a list of tickets (used where the list already exists)."""
    return {
        "severity": _slices(_count(a.severity for a in alerts), lambda label: alerts_url(severity=label)),
        "source": _slices(_count(a.source for a in alerts), lambda label: alerts_url(source=label)),
        "analyst": _slices(_count(a.analyst for a in alerts), lambda label: alerts_url(analyst=label)),
        "tactic": _slices(_count(a.tactic for a in alerts), lambda label: alerts_url(q=label)),
    }


def chart_counts_for_query(db, base) -> dict[str, dict[str, object]]:
    """Chart data straight from the database, one GROUP BY per panel.

    `base` is the filtered subquery the rest of the dashboard already built, so
    the panels describe exactly the rows the tiles count.
    """

    def grouped(column) -> dict[str, int]:
        counts: dict[str, int] = {}
        for label, count in db.execute(select(column, func.count()).select_from(base).group_by(column)):
            key = label or "Unknown"
            counts[key] = counts.get(key, 0) + int(count)
        return counts

    return {
        "severity": _slices(grouped(base.c.severity), lambda label: alerts_url(severity=label)),
        "source": _slices(grouped(base.c.source), lambda label: alerts_url(source=label)),
        "analyst": _slices(grouped(base.c.analyst), lambda label: alerts_url(analyst=label)),
        "tactic": _slices(grouped(base.c.tactic), lambda label: alerts_url(q=label)),
    }
