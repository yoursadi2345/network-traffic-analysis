"""
report.py
----------
Turns a list of engine.Alert objects (plus basic capture stats) into a
Markdown report and an HTML report. No external dependencies.
"""
from datetime import datetime
from collections import Counter

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def _fmt_ts(ts):
    try:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except (OSError, OverflowError, ValueError):
        return str(ts)


def build_summary(packets, alerts):
    proto_counts = Counter(p.get("proto", "OTHER") for p in packets)
    category_counts = Counter(a.category for a in alerts)
    severity_counts = Counter(a.severity for a in alerts)
    return {
        "total_packets": len(packets),
        "protocol_breakdown": dict(proto_counts),
        "total_alerts": len(alerts),
        "alerts_by_category": dict(category_counts),
        "alerts_by_severity": dict(severity_counts),
    }


def to_markdown(packets, alerts, title="Network Traffic Analysis Report"):
    summary = build_summary(packets, alerts)
    lines = [f"# {title}", "", f"_Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}_", ""]

    lines += ["## Summary", ""]
    lines.append(f"- Total packets analyzed: **{summary['total_packets']}**")
    lines.append(f"- Total alerts raised: **{summary['total_alerts']}**")
    lines.append("")
    lines.append("**Protocol breakdown:**")
    for proto, count in sorted(summary["protocol_breakdown"].items(), key=lambda x: -x[1]):
        lines.append(f"- {proto}: {count}")
    lines.append("")
    lines.append("**Alerts by severity:**")
    for sev in ("HIGH", "MEDIUM", "LOW"):
        if sev in summary["alerts_by_severity"]:
            lines.append(f"- {sev}: {summary['alerts_by_severity'][sev]}")
    lines.append("")

    lines += ["## Findings", ""]
    if not alerts:
        lines.append("No suspicious activity detected in this capture.")
    else:
        sorted_alerts = sorted(alerts, key=lambda a: (SEVERITY_ORDER.get(a.severity, 9), -a.timestamp))
        for i, a in enumerate(sorted_alerts, 1):
            lines.append(f"### {i}. [{a.severity}] {a.category.replace('_', ' ').title()}")
            lines.append(f"- **Time:** {_fmt_ts(a.timestamp)}")
            if a.src_ip:
                lines.append(f"- **Source IP:** {a.src_ip}")
            if a.dst_ip:
                lines.append(f"- **Target IP:** {a.dst_ip}")
            lines.append(f"- **Details:** {a.message}")
            if a.evidence:
                lines.append(f"- **Evidence:** `{a.evidence}`")
            lines.append("")

    lines += ["## Recommendations", ""]
    recs = []
    if summary["alerts_by_category"].get("PORT_SCAN"):
        recs.append("Rate-limit or block source IPs performing rapid multi-port connection attempts; "
                     "review firewall rules for unnecessary open ports.")
    if summary["alerts_by_category"].get("DOS_FLOOD"):
        recs.append("Deploy SYN-cookie protection and rate-limiting at the edge/firewall; consider "
                     "upstream DDoS scrubbing if distributed sources are involved.")
    if summary["alerts_by_category"].get("ARP_SPOOF"):
        recs.append("Enable Dynamic ARP Inspection (DAI) on switches, or use static ARP entries for "
                     "critical hosts; investigate the conflicting MAC address immediately.")
    if summary["alerts_by_category"].get("DNS_TUNNEL"):
        recs.append("Inspect the flagged domain(s) for data exfiltration; consider blocking uncommon "
                     "record types and enforcing DNS query logging/allow-listing at the resolver.")
    if not recs:
        recs.append("No action required based on this capture. Continue periodic monitoring.")
    for r in recs:
        lines.append(f"- {r}")

    return "\n".join(lines)


def to_html(packets, alerts, title="Network Traffic Analysis Report"):
    md_based_body = to_markdown(packets, alerts, title)
    # Minimal, dependency-free markdown -> HTML (headings, bullets, bold, code)
    import re
    html_lines = []
    for line in md_based_body.split("\n"):
        if line.startswith("### "):
            html_lines.append(f"<h3>{line[4:]}</h3>")
        elif line.startswith("## "):
            html_lines.append(f"<h2>{line[3:]}</h2>")
        elif line.startswith("# "):
            html_lines.append(f"<h1>{line[2:]}</h1>")
        elif line.startswith("- "):
            html_lines.append(f"<li>{line[2:]}</li>")
        elif line.strip() == "":
            html_lines.append("<br/>")
        else:
            html_lines.append(f"<p>{line}</p>")
    body = "\n".join(html_lines)
    body = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", body)
    body = re.sub(r"_(.+?)_", r"<i>\1</i>", body)
    body = re.sub(r"`(.+?)`", r"<code>\1</code>", body)

    severity_colors = {"HIGH": "#d9363e", "MEDIUM": "#d97706", "LOW": "#2563eb"}
    css = """
    body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; max-width: 900px; margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; }
    h1 { border-bottom: 3px solid #1a1a1a; padding-bottom: .5rem; }
    h2 { margin-top: 2rem; color: #1a1a1a; }
    h3 { margin-top: 1.5rem; }
    li { margin: .25rem 0; }
    code { background: #f1f1f1; padding: 2px 6px; border-radius: 4px; font-size: .85em; }
    """
    return f"<!DOCTYPE html><html><head><meta charset='utf-8'><title>{title}</title><style>{css}</style></head><body>{body}</body></html>"
