"""
=============================================================
  Network Intrusion Detection System (NIDS) — Single File
  Snort-style rules | Packet inspection | Auto-response
  Usage: python nids_single.py
=============================================================
"""

import re, json, time, random, hashlib, datetime, os
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from typing import Optional


# ─────────────────────────────────────────────────────────────
# DATA MODELS
# ─────────────────────────────────────────────────────────────

@dataclass
class Packet:
    src_ip:    str
    dst_ip:    str
    src_port:  int
    dst_port:  int
    protocol:  str
    payload:   str
    size:      int
    flags:     str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self):
        return {
            "src":       f"{self.src_ip}:{self.src_port}",
            "dst":       f"{self.dst_ip}:{self.dst_port}",
            "protocol":  self.protocol,
            "payload":   self.payload[:80] + "..." if len(self.payload) > 80 else self.payload,
            "size":      self.size,
            "flags":     self.flags,
            "timestamp": datetime.datetime.fromtimestamp(self.timestamp).strftime("%H:%M:%S"),
        }


@dataclass
class Rule:
    rule_id:   int
    action:    str
    protocol:  str
    src_ip:    str
    src_port:  str
    dst_ip:    str
    dst_port:  str
    message:   str
    content:   Optional[str] = None
    flags:     Optional[str] = None
    severity:  str = "MEDIUM"
    category:  str = "General"
    threshold: int = 1

    def matches(self, packet: Packet) -> bool:
        if self.protocol != "any" and self.protocol.upper() != packet.protocol.upper():
            return False
        if self.dst_port != "any":
            if "-" in str(self.dst_port):
                lo, hi = map(int, str(self.dst_port).split("-"))
                if not (lo <= packet.dst_port <= hi):
                    return False
            elif str(packet.dst_port) != str(self.dst_port):
                return False
        if self.src_port != "any":
            if str(packet.src_port) != str(self.src_port):
                return False
        if self.content and self.content.lower() not in packet.payload.lower():
            return False
        if self.flags and self.flags not in packet.flags:
            return False
        return True


@dataclass
class Alert:
    alert_id:     str
    rule_id:      int
    severity:     str
    category:     str
    message:      str
    packet:       dict
    action_taken: str = "LOGGED"
    timestamp:    str = field(default_factory=lambda: datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    def to_dict(self):
        return asdict(self)


# ─────────────────────────────────────────────────────────────
# RULES  (Snort-style, defined inline)
# ─────────────────────────────────────────────────────────────

RULES = [
    Rule(1001,"alert","tcp","any","any","any","22",   "SSH Brute Force Attempt",          content="SSH",                         severity="HIGH",     category="Brute Force",       threshold=5),
    Rule(1002,"alert","tcp","any","any","any","80",   "SQL Injection Attempt",             content="' OR '1'='1",                 severity="CRITICAL", category="Web Attack"),
    Rule(1003,"alert","tcp","any","any","any","80",   "XSS Attack Detected",               content="<script>",                    severity="HIGH",     category="Web Attack"),
    Rule(1004,"alert","tcp","any","any","any","445",  "SMB Exploit Attempt (EternalBlue)", content="\x00\x00\x00\x85\xff\x53\x4d\x42", severity="CRITICAL", category="Exploit"),
    Rule(1005,"alert","icmp","any","any","any","any", "ICMP Ping Sweep / Flood",                                                  severity="LOW",      category="Reconnaissance",    threshold=20),
    Rule(1006,"alert","tcp","any","any","any","23",   "Telnet Connection (Unencrypted)",                                          severity="MEDIUM",   category="Policy Violation"),
    Rule(1007,"alert","tcp","any","any","any","3389", "RDP Brute Force Attempt",           content="NTLMSSP",                     severity="HIGH",     category="Brute Force",       threshold=3),
    Rule(1008,"alert","tcp","any","any","any","4444", "Metasploit Default Port Activity",                                         severity="CRITICAL", category="Exploit"),
    Rule(1009,"alert","tcp","any","any","any","80",   "Directory Traversal Attack",        content="../etc/passwd",               severity="HIGH",     category="Web Attack"),
    Rule(1010,"alert","tcp","any","any","any","1-1024","Port Scan Detected (SYN)",         flags="SYN",                           severity="MEDIUM",   category="Reconnaissance",    threshold=10),
    Rule(1011,"alert","udp","any","any","any","53",   "DNS Amplification Attack",                                                 severity="HIGH",     category="DDoS",              threshold=50),
    Rule(1012,"alert","tcp","any","any","any","21",   "FTP Anonymous Login Attempt",       content="anonymous",                   severity="MEDIUM",   category="Policy Violation"),
    Rule(1013,"alert","tcp","any","any","any","80",   "Command Injection Attempt",         content="; cat /etc/passwd",           severity="CRITICAL", category="Web Attack"),
    Rule(1014,"alert","tcp","any","any","any","6667", "IRC Botnet C2 Communication",                                             severity="CRITICAL", category="Malware"),
    Rule(1015,"alert","tcp","any","any","any","443",  "Suspicious HTTPS C2 Beacon",        content="User-Agent: python-requests", severity="HIGH",     category="Malware"),
]


# ─────────────────────────────────────────────────────────────
# TRAFFIC SIMULATOR
# ─────────────────────────────────────────────────────────────

INTERNAL = ["192.168.1.10","192.168.1.20","192.168.1.30","10.0.0.5"]
EXTERNAL = ["203.0.113.45","198.51.100.22","45.33.32.156","185.220.101.5","77.247.181.163","194.165.16.11"]

NORMAL = [
    dict(protocol="tcp", dst_port=80,  payload="GET /index.html HTTP/1.1\r\nHost: example.com", flags="ACK", size=256),
    dict(protocol="tcp", dst_port=443, payload="TLS ClientHello v1.3",                           flags="ACK", size=512),
    dict(protocol="udp", dst_port=53,  payload="DNS Query: example.com A",                       flags="",    size=64),
    dict(protocol="tcp", dst_port=25,  payload="EHLO mailserver.local",                           flags="ACK", size=128),
    dict(protocol="tcp", dst_port=80,  payload="GET /api/v1/status HTTP/1.1",                    flags="ACK", size=200),
]

ATTACKS = [
    dict(protocol="tcp",  dst_port=80,   payload="GET /?id=' OR '1'='1 HTTP/1.1",                          flags="ACK", size=180),
    dict(protocol="tcp",  dst_port=80,   payload="GET /?q=<script>alert(1)</script> HTTP/1.1",              flags="ACK", size=160),
    dict(protocol="tcp",  dst_port=22,   payload="SSH-2.0-libssh_0.1",                                      flags="ACK", size=64),
    dict(protocol="tcp",  dst_port=4444, payload="\x90\x90\x90SHELLCODE\x00",                               flags="ACK", size=300),
    dict(protocol="icmp", dst_port=0,    payload="PING PING PING",                                          flags="",    size=64),
    dict(protocol="tcp",  dst_port=3389, payload="NTLMSSP\x00\x01\x00\x00\x00",                             flags="ACK", size=200),
    dict(protocol="tcp",  dst_port=80,   payload="GET /../etc/passwd HTTP/1.1",                             flags="ACK", size=128),
    dict(protocol="tcp",  dst_port=1,    payload="",                                                        flags="SYN", size=40),
    dict(protocol="tcp",  dst_port=6667, payload="JOIN #botnet PRIVMSG C2",                                 flags="ACK", size=120),
    dict(protocol="tcp",  dst_port=80,   payload="GET /cmd?exec=; cat /etc/passwd HTTP/1.1",                flags="ACK", size=150),
    dict(protocol="tcp",  dst_port=445,  payload="\x00\x00\x00\x85\xff\x53\x4d\x42exploit",                flags="ACK", size=400),
    dict(protocol="udp",  dst_port=53,   payload="DNS ANY record amplification request",                    flags="",    size=512),
    dict(protocol="tcp",  dst_port=21,   payload="USER anonymous PASS guest@",                              flags="ACK", size=80),
    dict(protocol="tcp",  dst_port=443,  payload="GET /beacon HTTP/1.1\r\nUser-Agent: python-requests/2.28",flags="ACK", size=200),
    dict(protocol="tcp",  dst_port=23,   payload="telnet login attempt admin:admin",                        flags="ACK", size=64),
]

def generate_packet(attack_ratio: float = 0.30) -> Packet:
    src = random.choice(EXTERNAL)
    dst = random.choice(INTERNAL)
    t   = random.choice(ATTACKS) if random.random() < attack_ratio else random.choice(NORMAL)
    return Packet(
        src_ip=src, dst_ip=dst,
        src_port=random.randint(1024, 65535),
        dst_port=t["dst_port"], protocol=t["protocol"],
        payload=t["payload"], size=t["size"], flags=t.get("flags",""),
    )


# ─────────────────────────────────────────────────────────────
# DETECTION ENGINE
# ─────────────────────────────────────────────────────────────

class DetectionEngine:
    def __init__(self, rules):
        self.rules       = rules
        self.alerts      = []
        self.stats       = defaultdict(int)
        self.hit_counts  = defaultdict(int)
        self.blocked_ips: set = set()

    def inspect(self, packet: Packet) -> list:
        self.stats["total_packets"] += 1
        self.stats[f"proto_{packet.protocol.lower()}"] += 1
        triggered = []
        if packet.src_ip in self.blocked_ips:
            self.stats["blocked_packets"] += 1
            return []
        for rule in self.rules:
            if rule.matches(packet):
                self.hit_counts[rule.rule_id] += 1
                if self.hit_counts[rule.rule_id] >= rule.threshold:
                    self.hit_counts[rule.rule_id] = 0
                    alert = self._make_alert(rule, packet)
                    self.alerts.append(alert)
                    triggered.append(alert)
                    self.stats["total_alerts"] += 1
                    self.stats[f"sev_{rule.severity}"] += 1
                    self.stats[f"cat_{rule.category}"] += 1
        if not triggered:
            self.stats["clean_packets"] += 1
        return triggered

    def _make_alert(self, rule: Rule, packet: Packet) -> Alert:
        uid    = hashlib.md5(f"{rule.rule_id}{packet.src_ip}{time.time()}".encode()).hexdigest()[:8].upper()
        action = self._respond(rule, packet)
        return Alert(
            alert_id=f"NIDS-{uid}", rule_id=rule.rule_id,
            severity=rule.severity, category=rule.category,
            message=rule.message, packet=packet.to_dict(), action_taken=action,
        )

    def _respond(self, rule: Rule, packet: Packet) -> str:
        s = rule.severity.upper()
        if s == "CRITICAL":
            self.blocked_ips.add(packet.src_ip)
            return f"BLOCKED {packet.src_ip}"
        if s == "HIGH":   return "RATE_LIMITED + LOGGED"
        if s == "MEDIUM": return "LOGGED + ADMIN_NOTIFIED"
        return "LOGGED"

    def summary(self) -> dict:
        return {
            "total_packets":  self.stats["total_packets"],
            "total_alerts":   self.stats["total_alerts"],
            "clean_packets":  self.stats["clean_packets"],
            "blocked_ips":    list(self.blocked_ips),
            "severity": {s: self.stats[f"sev_{s}"] for s in ("CRITICAL","HIGH","MEDIUM","LOW")},
            "categories": {k[4:]: v for k, v in self.stats.items() if k.startswith("cat_")},
            "protocols":  {p.upper(): self.stats[f"proto_{p}"] for p in ("tcp","udp","icmp")},
        }


# ─────────────────────────────────────────────────────────────
# MAIN — run everything
# ─────────────────────────────────────────────────────────────

def run(packet_count: int = 200, log_file: str = "nids_alerts.json"):
    SEV_ICON = {"CRITICAL":"[!!!]","HIGH":"[!! ]","MEDIUM":"[!  ]","LOW":"[.  ]"}

    print("=" * 62)
    print("  NETWORK INTRUSION DETECTION SYSTEM")
    print("  Python | Snort-style Rules | Auto-Response Engine")
    print("=" * 62)
    print(f"\n  Rules loaded : {len(RULES)}")
    print(f"  Packets scan : {packet_count}")
    print(f"  Alert log    : {log_file}\n")
    print("-" * 62)

    engine = DetectionEngine(RULES)
    start  = time.time()

    for _ in range(packet_count):
        alerts = engine.inspect(generate_packet())
        for a in alerts:
            icon = SEV_ICON.get(a.severity, "[?  ]")
            print(f"{icon} [{a.severity:<8}] {a.message}")
            print(f"         SRC {a.packet['src']}  →  DST {a.packet['dst']}")
            print(f"         {a.action_taken}  |  ID {a.alert_id}")
            print()
        time.sleep(0.005)

    elapsed = round(time.time() - start, 2)
    smry    = engine.summary()

    # ── save JSON log ──────────────────────────────────────
    with open(log_file, "w") as f:
        json.dump({
            "session": {
                "time": datetime.datetime.now().isoformat(),
                "duration_sec": elapsed,
                "packets": packet_count,
            },
            "summary": smry,
            "alerts": [a.to_dict() for a in engine.alerts],
        }, f, indent=2)

    # ── print summary ──────────────────────────────────────
    print("=" * 62)
    print("  SESSION SUMMARY")
    print("=" * 62)
    print(f"  Packets analyzed : {smry['total_packets']}")
    print(f"  Alerts triggered : {smry['total_alerts']}")
    print(f"  Clean packets    : {smry['clean_packets']}")
    print(f"  IPs auto-blocked : {len(smry['blocked_ips'])}")
    if smry['blocked_ips']:
        for ip in smry['blocked_ips']:
            print(f"    ✗  {ip}")
    print()
    print("  Severity breakdown:")
    bars = {"CRITICAL": "#", "HIGH": "#", "MEDIUM": "-", "LOW": "."}
    for sev, cnt in smry["severity"].items():
        bar = bars[sev] * cnt
        print(f"    {sev:<10} {cnt:>2}  {bar}")
    print()
    print("  Attack categories:")
    for cat, cnt in sorted(smry["categories"].items(), key=lambda x: -x[1]):
        print(f"    {cat:<28} {cnt} alert(s)")
    print()
    print("  Protocol mix:")
    for proto, cnt in smry["protocols"].items():
        print(f"    {proto:<8} {cnt} packets")
    print()
    print(f"  Log saved → {log_file}  ({elapsed}s)")
    print("=" * 62)


if __name__ == "__main__":
    run(packet_count=200)
