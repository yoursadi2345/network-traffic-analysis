# 🛡️ Network Traffic Analyzer

Capture and analyze network traffic to identify unusual patterns, malware behavior, or signs of an attack — combining a custom Python detection engine with industry-standard tools (**Wireshark**, **tcpdump**, **Snort**).

Detects:
- 🔍 **Port scans** (rapid connections to many distinct ports)
- 🌊 **DoS / DDoS SYN floods** (single-source and distributed)
- 🎭 **ARP spoofing** (one IP claimed by multiple MAC addresses)
- 🕳️ **DNS tunneling** (encoded / high-entropy or high-volume DNS queries)

Includes: a pure-Python detection engine (unit-tested), a CLI, a Flask web dashboard, a synthetic traffic generator (no root needed to try it out), and matching Snort rules.

---

## Project Structure

```
network-traffic-analyzer/
├── main.py                    # CLI entry point
├── dashboard.py                # Flask web dashboard
├── requirements.txt
├── src/
│   ├── engine.py               # Core detection logic (no dependencies, unit-tested)
│   ├── test_engine.py          # Sanity tests for engine.py
│   ├── capture.py              # scapy adapter: pcap / live capture -> normalized records
│   ├── generate_test_pcap.py   # Builds a synthetic demo .pcap (no root needed)
│   └── report.py               # Markdown / HTML report generation
├── templates/                  # Flask HTML templates
│   ├── index.html
│   └── results.html
├── snort_rules/
│   └── local.rules             # Custom Snort IDS rules matching the same attack types
├── sample_data/                # Generated demo pcap goes here
└── docs/                       # Screenshots for your report/README
```

---

## 1. Setup

```bash
git clone https://github.com/<your-username>/network-traffic-analyzer.git
cd network-traffic-analyzer

python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt
```

**Also install (for the traditional tools side of the project):**
- **Wireshark**: https://www.wireshark.org/download.html
- **tcpdump**: `sudo apt install tcpdump` (Linux) — usually preinstalled on macOS
- **Snort**: `sudo apt install snort` (Linux)

---

## 2. Quick Start — No Root Needed

Generate a synthetic capture with normal traffic mixed in with a port scan, a SYN flood, an ARP spoof pair, and DNS-tunneling-style queries, then analyze it:

```bash
python3 main.py gen-test-data sample_data/demo_traffic.pcap
python3 main.py analyze --pcap sample_data/demo_traffic.pcap --format html --out report.html
```

Open `report.html` in your browser — you should see 4+ alerts.

You can also open `sample_data/demo_traffic.pcap` directly in **Wireshark** to inspect it visually.

---

## 3. Web Dashboard

```bash
python3 dashboard.py
```

Then open **http://127.0.0.1:5000**, upload any `.pcap` file (your generated demo file, or a real capture), and view the alert dashboard in-browser. Download the full HTML report from there.

---

## 4. Analyzing Real Traffic

**Option A — capture with tcpdump, analyze with this tool:**
```bash
sudo tcpdump -i eth0 -w capture.pcap
# Ctrl+C to stop after a while, then:
python3 main.py analyze --pcap capture.pcap --format html
```

**Option B — live capture directly (needs root):**
```bash
sudo python3 main.py live --interface eth0 --duration 30 --save capture.pcap
```

**Option C — inspect visually first in Wireshark**, then export/save as `.pcap` and feed it to `main.py analyze`.

> ⚠️ Only capture traffic on networks/systems you own or have explicit permission to monitor. Run attack simulations (port scans, floods) only inside an isolated lab (e.g. two VMs on a NAT/host-only network in VirtualBox/VMware) — never against systems you don't control.

---

## 5. Using Snort Alongside This Tool

```bash
sudo cp snort_rules/local.rules /etc/snort/rules/local.rules
# make sure /etc/snort/snort.conf includes: include $RULE_PATH/local.rules
sudo snort -c /etc/snort/snort.conf -A console -q -i eth0
```

The rules in `snort_rules/local.rules` mirror the same four attack categories the Python engine detects (port scan, SYN flood, ARP-related notes, DNS tunneling heuristics), plus a few classic scan fingerprints (NULL/FIN/XMAS scans).

---

## 6. Running the Tests

```bash
cd src
python3 test_engine.py
```

This validates the detection engine against synthetic packet data (no scapy/network needed) — 9 test cases covering normal traffic, port scans, single-source DoS, distributed DDoS, ARP spoofing, and DNS tunneling (both signal types).

---

## 7. Tuning Detection Thresholds

All thresholds are adjustable per-call in `src/engine.py` (`run_all_detectors(packets, config=...)`), e.g.:

```python
config = {
    "port_scan": {"port_threshold": 10, "time_window": 3.0},
    "dos_flood": {"syn_threshold": 50},
    "dns_tunnel": {"length_threshold": 40, "entropy_threshold": 3.2},
}
alerts = run_all_detectors(packets, config=config)
```

---

## 8. How It Works (for your project report)

1. **Capture** — `tcpdump`/Wireshark/`scapy` capture raw packets from an interface or read a `.pcap` file.
2. **Normalize** — `src/capture.py` converts each raw packet into a simple dict (protocol, IPs, ports, flags, DNS query, etc.), decoupling the detection logic from any specific capture library.
3. **Detect** — `src/engine.py` runs sliding-time-window algorithms over the normalized records:
   - *Port scan*: counts distinct destination ports touched by one source within a time window.
   - *DoS/DDoS*: counts SYN packets hitting one destination within a time window, and distinguishes single-source vs. multi-source floods.
   - *ARP spoofing*: flags any IP address seen mapped to more than one MAC address.
   - *DNS tunneling*: flags individual queries that are long + high-entropy (looks like encoded data), and flags sources making an unusually high volume of distinct subdomain queries.
4. **Report** — `src/report.py` turns the alerts into a Markdown/HTML report with a summary, findings, and recommendations.
5. **Cross-check with Snort** — the matching `local.rules` file lets you validate the same findings using a mature, signature-based IDS.

---

## 9. Publishing This to GitHub

```bash
cd network-traffic-analyzer
git init
git add .
git commit -m "Initial commit: Network Traffic Analyzer"

# Create a new empty repo on GitHub first (github.com/new), then:
git branch -M main
git remote add origin https://github.com/<your-username>/network-traffic-analyzer.git
git push -u origin main
```

Suggested repo description: *"Python + Snort based network traffic analyzer — detects port scans, DoS/DDoS floods, ARP spoofing, and DNS tunneling from pcap or live capture."*

Suggested GitHub topics: `cybersecurity`, `network-security`, `wireshark`, `tcpdump`, `snort`, `intrusion-detection`, `scapy`, `python`

---

## Disclaimer

This project is for **educational purposes** and use in **authorized lab/test environments only**. Do not capture or analyze traffic on networks you do not own or do not have explicit permission to test.

## License

MIT — see [LICENSE](LICENSE).
