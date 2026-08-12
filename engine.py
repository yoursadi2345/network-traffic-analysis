"""
engine.py
----------
Core, dependency-free detection engine for the Network Traffic Analyzer.

This module never touches scapy or raw sockets directly. It works on a
normalized "packet record" (a plain dict), which makes the detection
logic easy to unit test and easy to reuse whether the data came from a
live capture, a .pcap file, or a unit test fixture.

Expected packet record shape (fields may be None if not applicable):
{
    "timestamp": float,          # epoch seconds
    "src_ip":    str | None,
    "dst_ip":    str | None,
    "src_port":  int | None,
    "dst_port":  int | None,
    "proto":     str,            # "TCP" | "UDP" | "ARP" | "DNS" | "ICMP" | "OTHER"
    "flags":     set[str] | None,  # e.g. {"S"}, {"S","A"}, {"A"} for TCP
    "length":    int,
    "src_mac":   str | None,
    "dns_query": str | None,     # queried hostname, only for DNS packets
}
"""

from __future__ import annotations
import math
from collections import defaultdict, deque
from dataclasses import dataclass, field


@dataclass
class Alert:
    category: str          # "PORT_SCAN" | "DOS_FLOOD" | "ARP_SPOOF" | "DNS_TUNNEL"
    severity: str           # "LOW" | "MEDIUM" | "HIGH"
    src_ip: str | None
    dst_ip: str | None
    timestamp: float
    message: str
    evidence: dict = field(default_factory=dict)

    def to_dict(self):
        return {
            "category": self.category,
            "severity": self.severity,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "timestamp": self.timestamp,
            "message": self.message,
            "evidence": self.evidence,
        }


# ---------------------------------------------------------------------------
# 1. Port scan detection
# ---------------------------------------------------------------------------
def detect_port_scans(packets, port_threshold=15, time_window=5.0):
    """
    Flags a source IP as a port-scanner if it sends bare SYN packets
    (SYN set, ACK not set) to >= port_threshold *distinct* destination
    ports on the same target within a sliding time_window (seconds).
    """
    alerts = []
    # (src_ip, dst_ip) -> list of (timestamp, dst_port), sorted by time
    syn_events = defaultdict(list)

    for p in packets:
        if p.get("proto") != "TCP" or not p.get("flags"):
            continue
        flags = p["flags"]
        if "S" in flags and "A" not in flags:
            key = (p["src_ip"], p["dst_ip"])
            syn_events[key].append((p["timestamp"], p["dst_port"]))

    for (src_ip, dst_ip), events in syn_events.items():
        events.sort(key=lambda e: e[0])
        window = deque()  # holds (timestamp, port) within current window
        ports_in_window = defaultdict(int)
        flagged_already = False

        for ts, port in events:
            window.append((ts, port))
            ports_in_window[port] += 1

            # slide window: drop events older than time_window
            while window and ts - window[0][0] > time_window:
                old_ts, old_port = window.popleft()
                ports_in_window[old_port] -= 1
                if ports_in_window[old_port] == 0:
                    del ports_in_window[old_port]

            unique_ports = len(ports_in_window)
            if unique_ports >= port_threshold and not flagged_already:
                flagged_already = True
                severity = "HIGH" if unique_ports >= port_threshold * 2 else "MEDIUM"
                alerts.append(Alert(
                    category="PORT_SCAN",
                    severity=severity,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    timestamp=ts,
                    message=(f"Possible port scan: {src_ip} touched {unique_ports} "
                              f"distinct ports on {dst_ip} within {time_window}s"),
                    evidence={"unique_ports": unique_ports, "sample_ports": sorted(ports_in_window)[:20]},
                ))
    return alerts


# ---------------------------------------------------------------------------
# 2. DoS / SYN-flood detection
# ---------------------------------------------------------------------------
def detect_dos_flood(packets, syn_threshold=100, time_window=5.0):
    """
    Flags a destination IP as being flooded if the number of SYN packets
    arriving at it (from any source) exceeds syn_threshold within a
    sliding time_window. Also reports the single biggest contributing
    source IP, useful for telling single-source DoS apart from
    distributed (many-source) DDoS.
    """
    alerts = []
    dst_events = defaultdict(list)  # dst_ip -> [(timestamp, src_ip), ...]

    for p in packets:
        if p.get("proto") != "TCP" or not p.get("flags"):
            continue
        if "S" in p["flags"] and "A" not in p["flags"]:
            dst_events[p["dst_ip"]].append((p["timestamp"], p["src_ip"]))

    for dst_ip, events in dst_events.items():
        events.sort(key=lambda e: e[0])
        window = deque()
        src_counts = defaultdict(int)
        flagged_already = False

        for ts, src_ip in events:
            window.append((ts, src_ip))
            src_counts[src_ip] += 1

            while window and ts - window[0][0] > time_window:
                old_ts, old_src = window.popleft()
                src_counts[old_src] -= 1
                if src_counts[old_src] == 0:
                    del src_counts[old_src]

            total_in_window = len(window)
            if total_in_window >= syn_threshold and not flagged_already:
                flagged_already = True
                unique_sources = len(src_counts)
                top_src = max(src_counts, key=src_counts.get)
                flood_type = "Distributed (DDoS-like)" if unique_sources > 5 else "Single-source (DoS)"
                alerts.append(Alert(
                    category="DOS_FLOOD",
                    severity="HIGH",
                    src_ip=top_src,
                    dst_ip=dst_ip,
                    timestamp=ts,
                    message=(f"Possible {flood_type} SYN flood against {dst_ip}: "
                              f"{total_in_window} SYNs in {time_window}s from "
                              f"{unique_sources} unique source(s)"),
                    evidence={"total_syns": total_in_window, "unique_sources": unique_sources,
                              "top_source": top_src, "top_source_count": src_counts[top_src]},
                ))
    return alerts


# ---------------------------------------------------------------------------
# 3. ARP spoofing detection
# ---------------------------------------------------------------------------
def detect_arp_spoofing(packets):
    """
    Flags IP addresses that are seen mapped to more than one MAC address
    in ARP traffic — the classic signature of ARP cache poisoning.
    """
    alerts = []
    ip_to_macs = defaultdict(set)
    ip_last_seen = {}

    for p in packets:
        if p.get("proto") != "ARP" or not p.get("src_ip") or not p.get("src_mac"):
            continue
        ip_to_macs[p["src_ip"]].add(p["src_mac"])
        ip_last_seen[p["src_ip"]] = p["timestamp"]

    for ip, macs in ip_to_macs.items():
        if len(macs) > 1:
            alerts.append(Alert(
                category="ARP_SPOOF",
                severity="HIGH",
                src_ip=ip,
                dst_ip=None,
                timestamp=ip_last_seen[ip],
                message=(f"Possible ARP spoofing: IP {ip} is claimed by "
                          f"{len(macs)} different MAC addresses"),
                evidence={"macs": sorted(macs)},
            ))
    return alerts


# ---------------------------------------------------------------------------
# 4. DNS tunneling detection
# ---------------------------------------------------------------------------
def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = defaultdict(int)
    for ch in s:
        freq[ch] += 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def detect_dns_tunneling(packets, length_threshold=50, entropy_threshold=3.5,
                          unique_subdomain_threshold=30, time_window=60.0):
    """
    Flags likely DNS tunneling using two independent signals:
      (a) individual queries that are unusually long AND high-entropy
          (looks like base32/base64-encoded data, not a real hostname)
      (b) a single source IP making an unusually large number of
          *distinct* subdomain queries in a short window (typical of
          tunneling tools drip-feeding data through DNS)
    """
    alerts = []
    per_src_queries = defaultdict(list)  # src_ip -> [(timestamp, query), ...]

    for p in packets:
        if p.get("proto") != "DNS" or not p.get("dns_query"):
            continue
        query = p["dns_query"]
        per_src_queries[p["src_ip"]].append((p["timestamp"], query))

        entropy = _shannon_entropy(query.replace(".", ""))
        if len(query) >= length_threshold and entropy >= entropy_threshold:
            alerts.append(Alert(
                category="DNS_TUNNEL",
                severity="MEDIUM",
                src_ip=p["src_ip"],
                dst_ip=p.get("dst_ip"),
                timestamp=p["timestamp"],
                message=(f"Suspicious DNS query from {p['src_ip']}: length={len(query)}, "
                          f"entropy={entropy:.2f} (looks encoded, not a normal hostname)"),
                evidence={"query": query, "length": len(query), "entropy": round(entropy, 2)},
            ))

    # Signal (b): volume of distinct subdomains per source in a window
    for src_ip, events in per_src_queries.items():
        events.sort(key=lambda e: e[0])
        window = deque()
        seen_in_window = defaultdict(int)
        flagged_already = False

        for ts, query in events:
            window.append((ts, query))
            seen_in_window[query] += 1
            while window and ts - window[0][0] > time_window:
                old_ts, old_q = window.popleft()
                seen_in_window[old_q] -= 1
                if seen_in_window[old_q] == 0:
                    del seen_in_window[old_q]

            unique_count = len(seen_in_window)
            if unique_count >= unique_subdomain_threshold and not flagged_already:
                flagged_already = True
                alerts.append(Alert(
                    category="DNS_TUNNEL",
                    severity="MEDIUM",
                    src_ip=src_ip,
                    dst_ip=None,
                    timestamp=ts,
                    message=(f"Possible DNS tunneling: {src_ip} made {unique_count} distinct "
                              f"DNS queries within {time_window}s"),
                    evidence={"unique_queries": unique_count},
                ))
    return alerts


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------
def run_all_detectors(packets, config=None):
    """
    Runs every detector over the same packet list and returns a single,
    time-sorted list of Alert objects. `config` lets callers override
    thresholds without touching this file, e.g.:
        config = {"port_scan": {"port_threshold": 10}}
    """
    config = config or {}
    alerts = []
    alerts += detect_port_scans(packets, **config.get("port_scan", {}))
    alerts += detect_dos_flood(packets, **config.get("dos_flood", {}))
    alerts += detect_arp_spoofing(packets)
    alerts += detect_dns_tunneling(packets, **config.get("dns_tunnel", {}))
    alerts.sort(key=lambda a: a.timestamp)
    return alerts
