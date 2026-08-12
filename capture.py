"""
capture.py
-----------
Bridges real packets (from a .pcap file or a live interface) into the
plain-dict format that engine.py understands. This is the ONLY file
that imports scapy — keeping the dependency isolated here means
engine.py stays pure-Python and unit-testable without scapy installed.

Requires: pip install scapy
Live capture requires root/administrator privileges.
"""

from scapy.all import rdpcap, sniff, wrpcap  # noqa: F401
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether
from scapy.layers.dns import DNS, DNSQR


def packet_to_dict(pkt):
    """
    Convert one scapy packet into the normalized record used by engine.py.
    Returns None for packets we don't care about (keeps the pipeline lean).
    """
    ts = float(pkt.time)
    record = {
        "timestamp": ts, "src_ip": None, "dst_ip": None,
        "src_port": None, "dst_port": None, "proto": "OTHER",
        "flags": None, "length": len(pkt), "src_mac": None, "dns_query": None,
    }

    # --- ARP (operates at L2, no IP layer) ---
    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        record["proto"] = "ARP"
        record["src_ip"] = arp.psrc
        record["dst_ip"] = arp.pdst
        record["src_mac"] = arp.hwsrc
        return record

    if not pkt.haslayer(IP):
        return None  # skip non-IP, non-ARP noise (STP, LLDP, etc.)

    ip = pkt[IP]
    record["src_ip"] = ip.src
    record["dst_ip"] = ip.dst
    if pkt.haslayer(Ether):
        record["src_mac"] = pkt[Ether].src

    # --- DNS (rides on UDP, check first so we tag proto="DNS") ---
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
        record["proto"] = "DNS"
        record["src_port"] = pkt[UDP].sport if pkt.haslayer(UDP) else None
        record["dst_port"] = pkt[UDP].dport if pkt.haslayer(UDP) else None
        try:
            qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
        except AttributeError:
            qname = str(pkt[DNSQR].qname).rstrip(".")
        record["dns_query"] = qname
        return record

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        record["proto"] = "TCP"
        record["src_port"] = tcp.sport
        record["dst_port"] = tcp.dport
        flag_map = {"S": "S", "A": "A", "F": "F", "R": "R", "P": "P", "U": "U"}
        flags = set()
        for bit, name in flag_map.items():
            if bit in str(tcp.flags):
                flags.add(name)
        record["flags"] = flags
        return record

    if pkt.haslayer(UDP):
        udp = pkt[UDP]
        record["proto"] = "UDP"
        record["src_port"] = udp.sport
        record["dst_port"] = udp.dport
        return record

    if pkt.haslayer(ICMP):
        record["proto"] = "ICMP"
        return record

    return record  # generic IP packet, proto stays "OTHER"


def load_pcap(path):
    """Read a .pcap/.pcapng file and return a list of normalized records."""
    packets = rdpcap(path)
    records = []
    for pkt in packets:
        rec = packet_to_dict(pkt)
        if rec is not None:
            records.append(rec)
    return records


def capture_live(interface, duration=30, packet_count=0, bpf_filter=None):
    """
    Sniff live traffic for `duration` seconds (or until `packet_count`
    packets are captured, whichever comes first — 0 means no limit).
    Requires root/administrator privileges. Returns normalized records.

    NOTE: run this from an account with capture privileges, e.g.:
        sudo python3 main.py live --interface eth0 --duration 30
    """
    kwargs = {"timeout": duration, "store": True}
    if packet_count:
        kwargs["count"] = packet_count
    if bpf_filter:
        kwargs["filter"] = bpf_filter

    captured = sniff(iface=interface, **kwargs)
    records = []
    for pkt in captured:
        rec = packet_to_dict(pkt)
        if rec is not None:
            records.append(rec)
    return records, captured  # also return raw scapy packets so caller can wrpcap()
