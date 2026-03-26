import os
from flask import Flask, jsonify, request
from flask_cors import CORS
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, Raw
import threading
import time
import json
from collections import defaultdict, deque
from datetime import datetime

app = Flask(__name__)
CORS(app)

# ─────────────────────────────────────────────
# Shared state (thread-safe via GIL for reads)
# ─────────────────────────────────────────────
packets_log = deque(maxlen=500)        # Recent packets (capped at 500)
protocol_counts = defaultdict(int)     # e.g. {"TCP": 412, "UDP": 88}
ip_counts = defaultdict(int)           # Source IP frequency
port_counts = defaultdict(int)         # Destination port frequency
alerts = deque(maxlen=100)             # Security alerts
stats = {
    "total": 0,
    "bytes": 0,
    "start_time": time.time(),
}

# Alert detection state
syn_tracker = defaultdict(list)        # IP -> [timestamps of SYN packets]
port_scan_tracker = defaultdict(set)   # IP -> set of destination ports


# ─────────────────────────────────────────────
# Packet processing
# ─────────────────────────────────────────────
def get_protocol(pkt):
    if pkt.haslayer(TCP):
        dport = pkt[TCP].dport
        if dport == 80 or dport == 8080:
            return "HTTP"
        if dport == 443:
            return "HTTPS"
        if dport == 22:
            return "SSH"
        if dport == 21:
            return "FTP"
        return "TCP"
    if pkt.haslayer(UDP):
        if pkt.haslayer(DNS):
            return "DNS"
        return "UDP"
    return "OTHER"


def check_alerts(pkt):
    if not pkt.haslayer(IP):
        return

    src_ip = pkt[IP].src
    now = time.time()

    # SYN flood detection: >20 SYNs from same IP in 5 seconds
    if pkt.haslayer(TCP) and pkt[TCP].flags == 0x02:  # SYN flag
        syn_tracker[src_ip].append(now)
        syn_tracker[src_ip] = [t for t in syn_tracker[src_ip] if now - t < 5]
        if len(syn_tracker[src_ip]) > 20:
            alerts.appendleft({
                "type": "SYN Flood",
                "severity": "HIGH",
                "src": src_ip,
                "detail": f"{len(syn_tracker[src_ip])} SYN packets in 5s",
                "time": datetime.now().strftime("%H:%M:%S"),
            })
            syn_tracker[src_ip] = []  # Reset after alert

    # Port scan detection: >15 unique ports from same IP in 10 seconds
    if pkt.haslayer(TCP):
        port_scan_tracker[src_ip].add(pkt[TCP].dport)
        if len(port_scan_tracker[src_ip]) > 15:
            alerts.appendleft({
                "type": "Port Scan",
                "severity": "MEDIUM",
                "src": src_ip,
                "detail": f"Probed {len(port_scan_tracker[src_ip])} ports",
                "time": datetime.now().strftime("%H:%M:%S"),
            })
            port_scan_tracker[src_ip] = set()  # Reset after alert

    # Suspicious port: connections to common malware C2 ports
    SUSPICIOUS_PORTS = {4444, 1337, 31337, 6667, 6666, 9001}
    if pkt.haslayer(TCP) and pkt[TCP].dport in SUSPICIOUS_PORTS:
        alerts.appendleft({
            "type": "Suspicious Port",
            "severity": "HIGH",
            "src": src_ip,
            "detail": f"Connection to port {pkt[TCP].dport}",
            "time": datetime.now().strftime("%H:%M:%S"),
        })


def packet_callback(pkt):
    if not pkt.haslayer(IP):
        return

    proto = get_protocol(pkt)
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    length = len(pkt)

    # Update global stats
    stats["total"] += 1
    stats["bytes"] += length
    protocol_counts[proto] += 1
    ip_counts[src_ip] += 1

    if pkt.haslayer(TCP):
        port_counts[pkt[TCP].dport] += 1
    elif pkt.haslayer(UDP):
        port_counts[pkt[UDP].dport] += 1

    # Build packet record
    record = {
        "id": stats["total"],
        "time": datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "src": src_ip,
        "dst": dst_ip,
        "protocol": proto,
        "length": length,
        "info": "",
    }

    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        try:
            record["info"] = f"Query: {pkt[DNSQR].qname.decode()}"
        except Exception:
            pass
    elif pkt.haslayer(TCP):
        flags = pkt[TCP].flags
        flag_str = ""
        if flags & 0x02: flag_str += "SYN "
        if flags & 0x10: flag_str += "ACK "
        if flags & 0x01: flag_str += "FIN "
        if flags & 0x04: flag_str += "RST "
        record["info"] = f"Port {pkt[TCP].sport}→{pkt[TCP].dport} [{flag_str.strip()}]"

    packets_log.appendleft(record)
    check_alerts(pkt)


def start_capture():
    print("[*] Starting packet capture (requires root)...")
    sniff(prn=packet_callback, store=False)


# ─────────────────────────────────────────────
# REST API endpoints
# ─────────────────────────────────────────────
@app.route("/api/packets")
def get_packets():
    limit = int(request.args.get("limit", 50))
    return jsonify(list(packets_log)[:limit])


@app.route("/api/stats")
def get_stats():
    elapsed = max(1, time.time() - stats["start_time"])
    return jsonify({
        "total_packets": stats["total"],
        "total_bytes": stats["bytes"],
        "packets_per_sec": round(stats["total"] / elapsed, 1),
        "uptime_seconds": int(elapsed),
        "protocol_counts": dict(protocol_counts),
        "top_ips": sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10],
        "top_ports": sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:10],
    })


@app.route("/api/alerts")
def get_alerts():
    return jsonify(list(alerts))


@app.route("/api/reset", methods=["POST"])
def reset():
    packets_log.clear()
    protocol_counts.clear()
    ip_counts.clear()
    port_counts.clear()
    alerts.clear()
    syn_tracker.clear()
    port_scan_tracker.clear()
    stats["total"] = 0
    stats["bytes"] = 0
    stats["start_time"] = time.time()
    return jsonify({"status": "reset"})


# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────


if __name__ == "__main__":
    capture_thread = threading.Thread(target=start_capture, daemon=True)
    capture_thread.start()
    port = int(os.environ.get("PORT", 5000))
    print(f"[*] API running at http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)
