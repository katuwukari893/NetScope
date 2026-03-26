# NetScope — Network Traffic Analyzer

A full-stack network traffic analyzer with real-time packet capture, protocol breakdown, IP statistics, and security alerting.

## Project structure

```
network_analyzer/
├── backend/
│   └── app.py          # Flask API + scapy capture engine
├── frontend/
│   └── index.html      # Dashboard (open directly in browser)
├── requirements.txt
└── README.md
```

## Quick start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

> On Linux/macOS you may need: `pip3 install -r requirements.txt`

### 2. Start the backend (requires root for raw packet capture)

```bash
# Linux / macOS
sudo python backend/app.py

# Windows (run terminal as Administrator)
python backend/app.py
```

You should see:
```
[*] Starting packet capture (requires root)...
[*] API running at http://localhost:5000
```

### 3. Open the dashboard

Open `frontend/index.html` directly in your browser. No server needed for the frontend.

---

## API endpoints

| Method | Route | Description |
|--------|-------|-------------|
| GET | `/api/packets?limit=N` | Recent packets (default 50) |
| GET | `/api/stats` | Aggregate stats, top IPs/ports |
| GET | `/api/alerts` | Security alert log |
| POST | `/api/reset` | Clear all captured data |

---

## Alert detection

| Alert type | Trigger condition |
|------------|-------------------|
| SYN Flood | >20 SYN packets from same IP in 5 seconds |
| Port Scan | >15 unique destination ports from same IP |
| Suspicious Port | Connection to 4444, 1337, 31337, 6667, 9001 |

---

## Extending the project

- Add packet export to PCAP: use `scapy.utils.wrpcap()`
- Add GeoIP lookup: `pip install geoip2` + MaxMind database
- Plug in a SQLite database for persistent storage
- Add anomaly detection with simple threshold-based ML (scikit-learn)
- Add WebSocket streaming with `flask-socketio` for push instead of poll

---

## Notes

- Packet capture requires elevated privileges (root/Administrator)
- The dashboard polls the backend every second
- Only IP-layer packets are analyzed (non-IP traffic is ignored)
- Tested on Linux with Python 3.10+
