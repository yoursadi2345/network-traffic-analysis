"""
generate_test_pcap.py
-----------------------
Builds a synthetic .pcap file containing a mix of normal traffic and
four attack patterns (port scan, SYN flood, ARP spoofing, DNS
tunneling), so you can demo/test the analyzer WITHOUT needing root
privileges or a real network to capture from.

Usage:
    python3 generate_test_pcap.py [output_path]

Requires: pip install scapy
"""
import random
import string
import sys
import time

from scapy.all import wrpcap
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.layers.dns import DNS, DNSQR


def random_label(n=10):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))


def build_normal_traffic(start_ts, count=20):
    pkts = []
    t = start_ts
    for i in range(count):
        sport = random.randint(40000, 60000)
        # simple handshake to a web server
        pkts.append(IP(src="10.0.0.5", dst="10.0.0.1") / TCP(sport=sport, dport=443, flags="S"))
        pkts.append(IP(src="10.0.0.1", dst="10.0.0.5") / TCP(sport=443, dport=sport, flags="SA"))
        pkts.append(IP(src="10.0.0.5", dst="10.0.0.1") / TCP(sport=sport, dport=443, flags="A"))
        for p in pkts[-3:]:
            p.time = t
            t += 0.02
        t += random.uniform(0.1, 0.5)
    return pkts, t


def build_port_scan(start_ts, attacker="192.168.1.50", victim="192.168.1.10", num_ports=30):
    pkts = []
    t = start_ts
    ports = random.sample(range(1, 1024), num_ports)
    for port in ports:
        pkt = IP(src=attacker, dst=victim) / TCP(sport=random.randint(40000, 60000), dport=port, flags="S")
        pkt.time = t
        pkts.append(pkt)
        t += 0.05  # fast scan
    return pkts, t


def build_syn_flood(start_ts, attacker="172.16.0.99", victim="172.16.0.1", port=80, count=200):
    pkts = []
    t = start_ts
    for _ in range(count):
        pkt = IP(src=attacker, dst=victim) / TCP(sport=random.randint(40000, 60000), dport=port, flags="S")
        pkt.time = t
        pkts.append(pkt)
        t += 0.01
    return pkts, t


def build_arp_spoof(start_ts, victim_ip="10.0.0.1"):
    pkts = []
    t = start_ts
    legit_mac = "aa:aa:aa:aa:aa:aa"
    attacker_mac = "bb:bb:bb:bb:bb:bb"
    pkt1 = Ether(src=legit_mac) / ARP(psrc=victim_ip, hwsrc=legit_mac, pdst="10.0.0.2")
    pkt1.time = t
    t += 0.5
    pkt2 = Ether(src=attacker_mac) / ARP(psrc=victim_ip, hwsrc=attacker_mac, pdst="10.0.0.2")
    pkt2.time = t
    t += 0.5
    return [pkt1, pkt2], t


def build_dns_tunneling(start_ts, src_ip="10.0.0.7", count=35):
    pkts = []
    t = start_ts
    # a handful of "encoded" long/high-entropy queries
    for _ in range(count):
        label = random_label(random.randint(40, 55))
        qname = f"{label}.exfil-tunnel.example"
        pkt = IP(src=src_ip, dst="8.8.8.8") / UDP(sport=random.randint(40000, 60000), dport=53) / \
            DNS(rd=1, qd=DNSQR(qname=qname))
        pkt.time = t
        pkts.append(pkt)
        t += 0.3
    return pkts, t


def main(output_path="sample_data/demo_traffic.pcap"):
    random.seed(42)
    t0 = time.time()
    all_pkts = []

    normal, t0 = build_normal_traffic(t0)
    all_pkts += normal

    scan, t0 = build_port_scan(t0 + 2)
    all_pkts += scan

    flood, t0 = build_syn_flood(t0 + 2)
    all_pkts += flood

    arp, t0 = build_arp_spoof(t0 + 2)
    all_pkts += arp

    dns_tun, t0 = build_dns_tunneling(t0 + 2)
    all_pkts += dns_tun

    all_pkts.sort(key=lambda p: p.time)
    wrpcap(output_path, all_pkts)
    print(f"Wrote {len(all_pkts)} synthetic packets to {output_path}")
    print("Mix: normal handshakes, 1 port scan, 1 SYN flood, 1 ARP spoof pair, 35 DNS-tunnel-like queries")


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "sample_data/demo_traffic.pcap"
    main(out)
