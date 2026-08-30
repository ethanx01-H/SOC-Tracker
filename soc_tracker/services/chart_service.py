"""Chart generation for dashboard pie charts."""

import math
from urllib.parse import urlencode


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


def chart_counts(alerts) -> dict[str, dict[str, object]]:
    """Generate chart data for dashboard pie charts."""
    colors = ["#1f6feb", "#0f766e", "#b7791f", "#b42318", "#6f42c1", "#475569", "#0891b2", "#be123c"]

    def group(items: list[tuple[str, str]]) -> dict[str, object]:
        counts: dict[str, int] = {}
        hrefs: dict[str, str] = {}
        for label, href in items:
            label = label or "Unknown"
            counts[label] = counts.get(label, 0) + 1
            hrefs[label] = href
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
                "color": colors[index % len(colors)],
                "href": hrefs[label],
            })
            start = end
        return {"total": total, "slices": slices}

    def alerts_url(**params: str) -> str:
        return f"/alerts/?{urlencode({key: value for key, value in params.items() if value})}"

    return {
        "severity": group([(a.severity, alerts_url(severity=a.severity)) for a in alerts]),
        "source": group([(a.source, alerts_url(source=a.source)) for a in alerts]),
        "analyst": group([(a.analyst, alerts_url(analyst=a.analyst)) for a in alerts]),
        "tactic": group([(a.tactic, alerts_url(q=a.tactic)) for a in alerts]),
    }
