#!/usr/bin/env python3
"""
Network Traffic Analyzer — CLI entry point.

Usage:
    python3 main.py gen-test-data [output.pcap]
        Generate a synthetic .pcap with mixed normal + attack traffic.

    python3 main.py analyze --pcap path/to/file.pcap [--format md|html] [--out report.md]
        Analyze a capture file and produce a report.

    python3 main.py live --interface eth0 [--duration 30] [--save capture.pcap]
        Sniff live traffic (needs root) and analyze it in real time.

See README.md for full setup instructions.
"""
import argparse
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from engine import run_all_detectors           # noqa: E402
import report as report_mod                     # noqa: E402


def cmd_gen_test_data(args):
    import generate_test_pcap
    out = args.output or "sample_data/demo_traffic.pcap"
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    generate_test_pcap.main(out)


def cmd_analyze(args):
    import capture
    print(f"[*] Loading packets from {args.pcap} ...")
    packets = capture.load_pcap(args.pcap)
    print(f"[*] Loaded {len(packets)} packets. Running detectors ...")
    alerts = run_all_detectors(packets)
    print(f"[*] {len(alerts)} alert(s) raised.")

    for a in alerts:
        print(f"  [{a.severity}] {a.category}: {a.message}")

    if args.format == "html":
        content = report_mod.to_html(packets, alerts)
    else:
        content = report_mod.to_markdown(packets, alerts)

    out_path = args.out or (f"report.{ 'html' if args.format == 'html' else 'md' }")
    with open(out_path, "w") as f:
        f.write(content)
    print(f"[*] Report written to {out_path}")


def cmd_live(args):
    import capture
    from scapy.all import wrpcap
    print(f"[*] Sniffing on {args.interface} for {args.duration}s (Ctrl+C to stop early) ...")
    print("[*] NOTE: live capture requires root/administrator privileges.")
    records, raw_packets = capture.capture_live(args.interface, duration=args.duration,
                                                  bpf_filter=args.bpf_filter)
    print(f"[*] Captured {len(records)} packets. Running detectors ...")
    alerts = run_all_detectors(records)
    print(f"[*] {len(alerts)} alert(s) raised.")
    for a in alerts:
        print(f"  [{a.severity}] {a.category}: {a.message}")

    if args.save:
        wrpcap(args.save, raw_packets)
        print(f"[*] Raw capture saved to {args.save}")

    content = report_mod.to_markdown(records, alerts)
    out_path = args.out or "live_report.md"
    with open(out_path, "w") as f:
        f.write(content)
    print(f"[*] Report written to {out_path}")


def main():
    parser = argparse.ArgumentParser(description="Network Traffic Analyzer")
    sub = parser.add_subparsers(dest="command", required=True)

    p_gen = sub.add_parser("gen-test-data", help="Generate a synthetic demo .pcap file")
    p_gen.add_argument("output", nargs="?", help="Output .pcap path")
    p_gen.set_defaults(func=cmd_gen_test_data)

    p_analyze = sub.add_parser("analyze", help="Analyze an existing .pcap file")
    p_analyze.add_argument("--pcap", required=True, help="Path to .pcap/.pcapng file")
    p_analyze.add_argument("--format", choices=["md", "html"], default="md")
    p_analyze.add_argument("--out", help="Output report path")
    p_analyze.set_defaults(func=cmd_analyze)

    p_live = sub.add_parser("live", help="Capture live traffic and analyze it (needs root)")
    p_live.add_argument("--interface", required=True, help="Network interface, e.g. eth0")
    p_live.add_argument("--duration", type=int, default=30, help="Seconds to capture")
    p_live.add_argument("--bpf-filter", dest="bpf_filter", default=None,
                         help="Optional BPF filter, e.g. 'tcp or arp or udp port 53'")
    p_live.add_argument("--save", help="Also save raw capture to this .pcap path")
    p_live.add_argument("--out", help="Output report path")
    p_live.set_defaults(func=cmd_live)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
