"""
test_engine.py
---------------
Sanity tests for engine.py using hand-built synthetic packet records
(no scapy / pcap needed). Run: python3 test_engine.py
"""
import sys
import random
import string
from engine import run_all_detectors, detect_port_scans, detect_dos_flood, \
    detect_arp_spoofing, detect_dns_tunneling


def make_pkt(ts, src_ip=None, dst_ip=None, src_port=None, dst_port=None,
             proto="TCP", flags=None, length=60, src_mac=None, dns_query=None):
    return {
        "timestamp": ts, "src_ip": src_ip, "dst_ip": dst_ip,
        "src_port": src_port, "dst_port": dst_port, "proto": proto,
        "flags": flags, "length": length, "src_mac": src_mac, "dns_query": dns_query,
    }


def test_normal_traffic_no_alerts():
    packets = []
    t = 1000.0
    # a normal 3-way handshake + a few requests to one server
    packets.append(make_pkt(t, "10.0.0.5", "10.0.0.1", 51000, 443, "TCP", {"S"}))
    packets.append(make_pkt(t + 0.01, "10.0.0.1", "10.0.0.5", 443, 51000, "TCP", {"S", "A"}))
    packets.append(make_pkt(t + 0.02, "10.0.0.5", "10.0.0.1", 51000, 443, "TCP", {"A"}))
    alerts = run_all_detectors(packets)
    assert len(alerts) == 0, f"Expected no alerts on normal traffic, got {alerts}"
    print("PASS: normal traffic -> 0 alerts")


def test_port_scan_detected():
    packets = []
    t = 2000.0
    # attacker hits 25 distinct ports on victim within 2 seconds
    for i, port in enumerate(range(20, 45)):
        packets.append(make_pkt(t + i * 0.05, "192.168.1.50", "192.168.1.10",
                                 40000 + i, port, "TCP", {"S"}))
    alerts = detect_port_scans(packets, port_threshold=15, time_window=5.0)
    assert len(alerts) == 1, f"Expected 1 port scan alert, got {len(alerts)}"
    assert alerts[0].src_ip == "192.168.1.50"
    print(f"PASS: port scan detected -> {alerts[0].message}")


def test_dos_flood_detected():
    packets = []
    t = 3000.0
    # single attacker floods victim:80 with 150 SYNs in 3 seconds
    for i in range(150):
        packets.append(make_pkt(t + i * 0.02, "172.16.0.99", "172.16.0.1",
                                 30000 + i, 80, "TCP", {"S"}))
    alerts = detect_dos_flood(packets, syn_threshold=100, time_window=5.0)
    assert len(alerts) == 1, f"Expected 1 flood alert, got {len(alerts)}"
    assert "Single-source" in alerts[0].message
    print(f"PASS: DoS flood detected -> {alerts[0].message}")


def test_ddos_multi_source_detected():
    packets = []
    t = 3500.0
    # 10 different sources each send 15 SYNs to same victim:80 -> 150 total, >5 sources
    i = 0
    for src_n in range(10):
        for _ in range(15):
            packets.append(make_pkt(t + i * 0.01, f"203.0.113.{src_n}", "172.16.0.1",
                                     30000 + i, 80, "TCP", {"S"}))
            i += 1
    alerts = detect_dos_flood(packets, syn_threshold=100, time_window=5.0)
    assert len(alerts) == 1
    assert "Distributed" in alerts[0].message
    print(f"PASS: DDoS (multi-source) detected -> {alerts[0].message}")


def test_arp_spoof_detected():
    packets = [
        make_pkt(4000.0, src_ip="10.0.0.1", proto="ARP", src_mac="AA:AA:AA:AA:AA:AA"),
        make_pkt(4001.0, src_ip="10.0.0.1", proto="ARP", src_mac="BB:BB:BB:BB:BB:BB"),
    ]
    alerts = detect_arp_spoofing(packets)
    assert len(alerts) == 1
    assert alerts[0].src_ip == "10.0.0.1"
    print(f"PASS: ARP spoofing detected -> {alerts[0].message}")


def test_arp_normal_no_alert():
    packets = [
        make_pkt(4000.0, src_ip="10.0.0.1", proto="ARP", src_mac="AA:AA:AA:AA:AA:AA"),
        make_pkt(4001.0, src_ip="10.0.0.1", proto="ARP", src_mac="AA:AA:AA:AA:AA:AA"),
        make_pkt(4002.0, src_ip="10.0.0.2", proto="ARP", src_mac="CC:CC:CC:CC:CC:CC"),
    ]
    alerts = detect_arp_spoofing(packets)
    assert len(alerts) == 0
    print("PASS: normal ARP traffic -> 0 alerts")


def test_dns_tunneling_long_entropy_query():
    random_label = ''.join(random.choices(string.ascii_lowercase + string.digits, k=60))
    packets = [
        make_pkt(5000.0, src_ip="10.0.0.7", dst_ip="8.8.8.8", proto="DNS",
                  dns_query=f"{random_label}.evil-tunnel.com"),
    ]
    alerts = detect_dns_tunneling(packets, length_threshold=50, entropy_threshold=3.5)
    assert len(alerts) == 1
    print(f"PASS: DNS tunneling (encoded query) detected -> {alerts[0].message}")


def test_dns_tunneling_high_volume():
    packets = []
    t = 6000.0
    for i in range(40):
        label = ''.join(random.choices(string.ascii_lowercase, k=8))
        packets.append(make_pkt(t + i * 0.5, src_ip="10.0.0.8", dst_ip="8.8.8.8",
                                 proto="DNS", dns_query=f"{label}.normal-looking.com"))
    alerts = detect_dns_tunneling(packets, unique_subdomain_threshold=30, time_window=60.0)
    volume_alerts = [a for a in alerts if "distinct DNS queries" in a.message]
    assert len(volume_alerts) == 1, f"Expected 1 volume alert, got {volume_alerts}"
    print(f"PASS: DNS tunneling (high volume) detected -> {volume_alerts[0].message}")


def test_dns_normal_no_alert():
    packets = [
        make_pkt(7000.0, src_ip="10.0.0.9", dst_ip="8.8.8.8", proto="DNS",
                  dns_query="www.google.com"),
        make_pkt(7001.0, src_ip="10.0.0.9", dst_ip="8.8.8.8", proto="DNS",
                  dns_query="mail.google.com"),
    ]
    alerts = detect_dns_tunneling(packets)
    assert len(alerts) == 0
    print("PASS: normal DNS traffic -> 0 alerts")


if __name__ == "__main__":
    tests = [v for k, v in list(globals().items()) if k.startswith("test_")]
    failed = 0
    for t in tests:
        try:
            t()
        except AssertionError as e:
            failed += 1
            print(f"FAIL: {t.__name__} -> {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} tests passed")
    sys.exit(1 if failed else 0)
