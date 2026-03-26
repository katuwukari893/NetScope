"""
NetScope - Vercel Serverless Backend
Stateless: each request generates realistic simulated traffic data.
No background threads (not supported in serverless environments).
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
import random
import time
import os

app = Flask(__name__)
CORS(app)

# ─────────────────────────────────────────────
# Simulated data generators
# ─────────────────────────────────────────────
INTERNAL_IPS = [
    "192.168.1.10", "192.168.1.22", "192.168.1.45",
    "10.0.0.5",     "10.0.0.12",    "172.16.0.8",
]
EXTERNAL_IPS = [
    "8.8.8.8",       "1.1.1.1",        "142.250.80.14",
    "151.101.1.140", "104.18.20.36",   "93.184.216.34",
    "52.84.227.100", "185.199.108.153","13.107.42.14",
]
SUSPICIOUS_IPS = ["45.33.32.156", "198.20.69.74", "89.248.167.131"]

PROTOCOLS = [
    ("HTTPS", 443,  70),
    ("HTTP",  80,   10),
    ("DNS",   53,   8),
    ("TCP",   8080, 5),
    ("SSH",   22,   3),
    ("UDP",   123,  3),
    ("FTP",   21,   1),
]

DNS_DOMAINS = [
    "google.com.", "github.com.", "api.stripe.com.",
    "cdn.jsdelivr.net.", "fonts.googleapis.com.", "aws.amazon.com.",
]

TCP_FLAGS = ["SYN ACK", "ACK", "ACK", "ACK", "FIN ACK"]

def weighted_choice(choices):
    total = sum(w for _, _, w in choices)
    r = random.uniform(0, total)
    upto = 0
    for item in choices:
        upto += item[2]
        if r <= upto:
            return item
    return choices[0]

def make_packet(pid, ts_offset=0):
    proto, dport, _ = weighted_choice(PROTOCOLS)
    src    = random.choice(INTERNAL_IPS + EXTERNAL_IPS)
    dst    = random.choice(EXTERNAL_IPS)
    length = random.randint(64, 1500)
    sport  = random.randint(1024, 65535)

    t = time.time() - ts_offset
    from datetime import datetime
    time_str = datetime.fromtimestamp(t).strftime("%H:%M:%S.%f")[:-3]

    if proto == "DNS":
        info = f"Query: {random.choice(DNS_DOMAINS)}"
    else:
        flag = random.choice(TCP_FLAGS)
        info = f"Port {sport}→{dport} [{flag}]"

    return {
        "id":       pid,
        "time":     time_str,
        "src":      src,
        "dst":      dst,
        "protocol": proto,
        "length":   length,
        "info":     info,
    }

def make_attack_packets(pid_start):
    """Occasionally inject realistic attack traffic."""
    pkts = []
    attacker = random.choice(SUSPICIOUS_IPS)
    attack   = random.choice(["port_scan", "syn_flood", "none", "none", "none"])

    if attack == "port_scan":
        for i in range(random.randint(5, 12)):
            dport = random.randint(1, 1024)
            pkts.append({
                "id":       pid_start + i,
                "time":     time.strftime("%H:%M:%S"),
                "src":      attacker,
                "dst":      random.choice(INTERNAL_IPS),
                "protocol": "TCP",
                "length":   60,
                "info":     f"Port {random.randint(1024,65535)}→{dport} [SYN]",
            })
    elif attack == "syn_flood":
        for i in range(random.randint(5, 10)):
            pkts.append({
                "id":       pid_start + i,
                "time":     time.strftime("%H:%M:%S"),
                "src":      attacker,
                "dst":      random.choice(INTERNAL_IPS),
                "protocol": "TCP",
                "length":   60,
                "info":     f"Port {random.randint(1024,65535)}→80 [SYN]",
            })
    return pkts

def generate_packets(count=80):
    """Generate a realistic packet log."""
    random.seed(int(time.time() / 8))  # Changes every 8s for "live" feel
    pkts = []
    for i in range(count):
        pkts.append(make_packet(count - i, ts_offset=i * 0.15))

    # Inject attack traffic
    if random.random() < 0.35:
        attack_pkts = make_attack_packets(count + 1)
        pkts = attack_pkts + pkts

    return pkts[:count]

def generate_stats(packets):
    proto_counts = {}
    ip_counts    = {}
    port_counts  = {}
    total_bytes  = 0

    for p in packets:
        proto_counts[p["protocol"]] = proto_counts.get(p["protocol"], 0) + 1
        ip_counts[p["src"]]         = ip_counts.get(p["src"], 0) + 1
        total_bytes                += p["length"]

        if "→" in p["info"]:
            try:
                dport = int(p["info"].split("→")[-1].split(" ")[0])
                port_counts[dport] = port_counts.get(dport, 0) + 1
            except ValueError:
                pass

    top_ips   = sorted(ip_counts.items(),   key=lambda x: x[1], reverse=True)[:10]
    top_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    return {
        "total_packets":   len(packets),
        "total_bytes":     total_bytes,
        "packets_per_sec": round(random.uniform(8, 25), 1),
        "uptime_seconds":  int(time.time() % 86400),
        "capture_mode":    "simulated",
        "protocol_counts": proto_counts,
        "top_ips":         top_ips,
        "top_ports":       top_ports,
    }

def generate_alerts(packets):
    alerts = []
    from datetime import datetime

    # Check for port scan pattern
    syn_by_ip = {}
    ports_by_ip = {}
    for p in packets:
        if "[SYN]" in p["info"] and p["src"] in SUSPICIOUS_IPS:
            syn_by_ip[p["src"]]   = syn_by_ip.get(p["src"], 0) + 1
            if p["src"] not in ports_by_ip:
                ports_by_ip[p["src"]] = set()
            if "→" in p["info"]:
                try:
                    dport = int(p["info"].split("→")[-1].split(" ")[0])
                    ports_by_ip[p["src"]].add(dport)
                except ValueError:
                    pass

    for ip, count in syn_by_ip.items():
        if len(ports_by_ip.get(ip, set())) > 5:
            alerts.append({
                "type":     "Port Scan",
                "severity": "MEDIUM",
                "src":      ip,
                "detail":   f"Probed {len(ports_by_ip[ip])} ports",
                "time":     datetime.now().strftime("%H:%M:%S"),
            })
        elif count > 8:
            alerts.append({
                "type":     "SYN Flood",
                "severity": "HIGH",
                "src":      ip,
                "detail":   f"{count} SYN packets detected",
                "time":     datetime.now().strftime("%H:%M:%S"),
            })

    return alerts


# ─────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────
@app.route("/api/packets")
def get_packets():
    limit = int(request.args.get("limit", 50))
    pkts  = generate_packets(100)
    return jsonify(pkts[:limit])

@app.route("/api/stats")
def get_stats():
    pkts  = generate_packets(100)
    return jsonify(generate_stats(pkts))

@app.route("/api/alerts")
def get_alerts():
    pkts = generate_packets(100)
    return jsonify(generate_alerts(pkts))

@app.route("/api/reset", methods=["POST"])
def reset():
    # Stateless — nothing to clear, just acknowledge
    return jsonify({"status": "reset"})

@app.route("/")
def index():
    return jsonify({"status": "NetScope API running", "mode": "serverless"})