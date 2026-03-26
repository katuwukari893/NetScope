from flask import Flask, jsonify, request
from flask_cors import CORS
import threading
import time
import random
import os
from collections import defaultdict, deque
from datetime import datetime

app = Flask(__name__)
CORS(app)

# ─────────────────────────────────────────────
# Shared state
# ─────────────────────────────────────────────
packets_log      = deque(maxlen=500)
protocol_counts  = defaultdict(int)
ip_counts        = defaultdict(int)
port_counts      = defaultdict(int)
alerts           = deque(maxlen=100)
stats = {
    "total":      0,
    "bytes":      0,
    "start_time": time.time(),
}

syn_tracker       = defaultdict(list)
port_scan_tracker = defaultdict(set)

CAPTURE_MODE = "unknown"


# ─────────────────────────────────────────────
# Shared packet processing
# ─────────────────────────────────────────────
def process_packet(src, dst, protocol, length, info, flags=None):
    stats["total"] += 1
    stats["bytes"] += length
    protocol_counts[protocol] += 1
    ip_counts[src] += 1

    record = {
        "id":       stats["total"],
        "time":     datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "src":      src,
        "dst":      dst,
        "protocol": protocol,
        "length":   length,
        "info":     info,
    }
    packets_log.appendleft(record)

    # SYN flood detection
    if flags == "SYN":
        now = time.time()
        syn_tracker[src].append(now)
        syn_tracker[src] = [t for t in syn_tracker[src] if now - t < 5]
        if len(syn_tracker[src]) > 20:
            alerts.appendleft({
                "type":     "SYN Flood",
                "severity": "HIGH",
                "src":      src,
                "detail":   f"{len(syn_tracker[src])} SYN packets in 5s",
                "time":     datetime.now().strftime("%H:%M:%S"),
            })
            syn_tracker[src] = []

    # Port scan detection
    if protocol == "TCP" and "→" in info:
        try:
            dport = int(info.split("→")[-1].split(" ")[0])
            port_counts[dport] += 1
            port_scan_tracker[src].add(dport)
            if len(port_scan_tracker[src]) > 15:
                alerts.appendleft({
                    "type":     "Port Scan",
                    "severity": "MEDIUM",
                    "src":      src,
                    "detail":   f"Probed {len(port_scan_tracker[src])} ports",
                    "time":     datetime.now().strftime("%H:%M:%S"),
                })
                port_scan_tracker[src] = set()
        except ValueError:
            pass

    # Suspicious port detection
    SUSPICIOUS = {4444, 1337, 31337, 6667, 9001}
    if "→" in info:
        try:
            dport = int(info.split("→")[-1].split(" ")[0])
            if dport in SUSPICIOUS:
                alerts.appendleft({
                    "type":     "Suspicious Port",
                    "severity": "HIGH",
                    "src":      src,
                    "detail":   f"Connection to port {dport}",
                    "time":     datetime.now().strftime("%H:%M:%S"),
                })
        except ValueError:
            pass


# ─────────────────────────────────────────────
# Mode 1: Live capture via scapy
# ─────────────────────────────────────────────
def try_live_capture():
    global CAPTURE_MODE
    try:
        from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR

        def get_protocol(pkt):
            if pkt.haslayer(TCP):
                d = pkt[TCP].dport
                if d in (80, 8080): return "HTTP"
                if d == 443:        return "HTTPS"
                if d == 22:         return "SSH"
                if d == 21:         return "FTP"
                return "TCP"
            if pkt.haslayer(UDP):
                return "DNS" if pkt.haslayer(DNS) else "UDP"
            return "OTHER"

        def packet_callback(pkt):
            if not pkt.haslayer(IP):
                return
            proto  = get_protocol(pkt)
            src    = pkt[IP].src
            dst    = pkt[IP].dst
            length = len(pkt)
            info   = ""
            flags  = None

            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                try:
                    info = f"Query: {pkt[DNSQR].qname.decode()}"
                except Exception:
                    pass
            elif pkt.haslayer(TCP):
                f = pkt[TCP].flags
                flag_str = ""
                if f & 0x02: flag_str += "SYN "; flags = "SYN"
                if f & 0x10: flag_str += "ACK "
                if f & 0x01: flag_str += "FIN "
                if f & 0x04: flag_str += "RST "
                info = f"Port {pkt[TCP].sport}→{pkt[TCP].dport} [{flag_str.strip()}]"

            process_packet(src, dst, proto, length, info, flags)

        CAPTURE_MODE = "live"
        print("[*] Live packet capture started")
        sniff(prn=packet_callback, store=False)

    except PermissionError:
        print("[!] Raw socket access denied — switching to simulated traffic")
        CAPTURE_MODE = "simulated"
        run_simulated_capture()
    except Exception as e:
        print(f"[!] Scapy unavailable ({e}) — switching to simulated traffic")
        CAPTURE_MODE = "simulated"
        run_simulated_capture()


# ─────────────────────────────────────────────
# Mode 2: Simulated traffic (cloud-safe)
# ─────────────────────────────────────────────
INTERNAL_IPS = [
    "192.168.1.10", "192.168.1.22", "192.168.1.45",
    "10.0.0.5",     "10.0.0.12",    "172.16.0.8",
]
EXTERNAL_IPS = [
    "8.8.8.8",        "1.1.1.1",        "142.250.80.14",
    "151.101.1.140",  "104.18.20.36",   "93.184.216.34",
    "52.84.227.100",  "185.199.108.153",
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

def weighted_choice(choices):
    total = sum(w for _, _, w in choices)
    r = random.uniform(0, total)
    upto = 0
    for item in choices:
        upto += item[2]
        if r <= upto:
            return item
    return choices[0]

def simulate_normal_packet():
    proto, dport, _ = weighted_choice(PROTOCOLS)
    src    = random.choice(INTERNAL_IPS + EXTERNAL_IPS)
    dst    = random.choice(EXTERNAL_IPS)
    length = random.randint(64, 1500)
    sport  = random.randint(1024, 65535)

    if proto == "DNS":
        domains = ["google.com.", "github.com.", "api.example.com.", "cdn.jsdelivr.net."]
        info = f"Query: {random.choice(domains)}"
        return src, dst, proto, length, info, None
    else:
        flags = random.choice(["SYN ACK", "ACK", "ACK", "ACK", "FIN ACK"])
        info = f"Port {sport}→{dport} [{flags}]"
        flag = "SYN" if flags == "SYN ACK" else None
        return src, dst, proto, length, info, flag

def simulate_port_scan(attacker):
    dst   = random.choice(INTERNAL_IPS)
    dport = random.randint(1, 1024)
    info  = f"Port {random.randint(1024,65535)}→{dport} [SYN]"
    return attacker, dst, "TCP", 60, info, "SYN"

def simulate_syn_flood(attacker):
    dst  = random.choice(INTERNAL_IPS)
    info = f"Port {random.randint(1024,65535)}→80 [SYN]"
    return attacker, dst, "TCP", 60, info, "SYN"

def run_simulated_capture():
    print("[*] Simulated traffic mode active")
    attack_state = {
        "port_scan":  None, "scan_count": 0,
        "syn_flood":  None, "flood_count": 0,
    }

    while True:
        r = random.random()
        if r < 0.002 and not attack_state["port_scan"]:
            attack_state["port_scan"]  = random.choice(SUSPICIOUS_IPS)
            attack_state["scan_count"] = random.randint(18, 30)
        if r < 0.001 and not attack_state["syn_flood"]:
            attack_state["syn_flood"]   = random.choice(SUSPICIOUS_IPS)
            attack_state["flood_count"] = random.randint(25, 40)

        if attack_state["port_scan"] and attack_state["scan_count"] > 0:
            process_packet(*simulate_port_scan(attack_state["port_scan"]))
            attack_state["scan_count"] -= 1
            if attack_state["scan_count"] == 0:
                attack_state["port_scan"] = None

        if attack_state["syn_flood"] and attack_state["flood_count"] > 0:
            for _ in range(3):
                process_packet(*simulate_syn_flood(attack_state["syn_flood"]))
            attack_state["flood_count"] -= 1
            if attack_state["flood_count"] == 0:
                attack_state["syn_flood"] = None

        for _ in range(random.randint(1, 4)):
            process_packet(*simulate_normal_packet())

        time.sleep(random.uniform(0.1, 0.4))


# ─────────────────────────────────────────────
# REST API
# ─────────────────────────────────────────────
@app.route("/api/packets")
def get_packets():
    limit = int(request.args.get("limit", 50))
    return jsonify(list(packets_log)[:limit])


@app.route("/api/stats")
def get_stats():
    elapsed = max(1, time.time() - stats["start_time"])
    return jsonify({
        "total_packets":   stats["total"],
        "total_bytes":     stats["bytes"],
        "packets_per_sec": round(stats["total"] / elapsed, 1),
        "uptime_seconds":  int(elapsed),
        "capture_mode":    CAPTURE_MODE,
        "protocol_counts": dict(protocol_counts),
        "top_ips":   sorted(ip_counts.items(),   key=lambda x: x[1], reverse=True)[:10],
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
    stats["total"]      = 0
    stats["bytes"]      = 0
    stats["start_time"] = time.time()
    return jsonify({"status": "reset"})


# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────
if __name__ == "__main__":
    t = threading.Thread(target=try_live_capture, daemon=True)
    t.start()
    port = int(os.environ.get("PORT", 5000))
    print(f"[*] API running at http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)
