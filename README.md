# NetScope

A full-stack network traffic analyzer with real-time packet visualization, protocol breakdown, IP statistics, and an automated security alert engine. Built with Python, Flask, and vanilla JS — deployed on Vercel.

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.x-black?style=flat-square&logo=flask)
![Vercel](https://img.shields.io/badge/Deployed-Vercel-black?style=flat-square&logo=vercel)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

---

## Features

- **Live packet stream** — scrolling table of captured packets with protocol, source/destination IP, port, flags, and payload info
- **Protocol breakdown** — real-time donut chart across HTTPS, HTTP, TCP, UDP, DNS, SSH, FTP
- **Top source IPs** — ranked bar view of the most active IP addresses
- **Security alert engine** — automatic detection of SYN floods, port scans, and suspicious port connections
- **Filter & search** — filter the packet table by protocol or IP address on the fly
- **Dual capture mode** — uses live scapy packet capture when run locally with root; falls back to realistic simulated traffic when deployed to the cloud

---

## Project structure

```
NetScope/
├── api/
│   └── index.py          # Serverless Flask backend (Vercel)
├── frontend/
│   └── index.html        # Dashboard UI
├── backend/
│   └── app.py            # Local Flask backend (live capture via scapy)
├── vercel.json           # Vercel routing config
├── requirements.txt      # Python dependencies
└── README.md
```

---

## Live demo

> [netscope.vercel.app](https://netscope.vercel.app) ← replace with your actual URL

---

## Running locally (real packet capture)

Local mode uses scapy to capture actual network traffic. Root access is required to open raw sockets.

**1. Install dependencies**

```bash
pip install flask flask-cors scapy
```

**2. Start the backend**

```bash
# Linux / macOS
sudo python backend/app.py

# Windows — run terminal as Administrator
python backend/app.py
```

**3. Open the dashboard**

Open `frontend/index.html` in your browser. Make sure the API constant in the file points to `http://localhost:5000/api`.

---

## Deploying to Vercel

The `api/` folder contains a serverless version of the backend compatible with Vercel's Python runtime. In this mode, traffic is simulated — cloud environments don't permit raw socket access.

**1. Fork or clone this repo**

```bash
git clone https://github.com/katuwukari893/NetScope.git
cd NetScope
```

**2. Import into Vercel**

- Go to [vercel.com](https://vercel.com) → New Project → Import your GitHub repo
- Leave Root Directory blank
- Framework Preset: Other
- Click Deploy

The `vercel.json` file handles routing — `/api/*` goes to the Flask serverless function, `/` serves the dashboard.

---

## API reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/packets?limit=N` | Recent packets (default 50, max 100) |
| `GET` | `/api/stats` | Aggregate stats, protocol counts, top IPs and ports |
| `GET` | `/api/alerts` | Security alert log |
| `POST` | `/api/reset` | Clear all captured data |

**Example response — `/api/stats`**

```json
{
  "total_packets": 1024,
  "total_bytes": 987432,
  "packets_per_sec": 14.3,
  "capture_mode": "simulated",
  "protocol_counts": { "HTTPS": 712, "DNS": 89, "HTTP": 98 },
  "top_ips": [["8.8.8.8", 142], ["1.1.1.1", 98]],
  "top_ports": [[443, 712], [53, 89]]
}
```

---

## Alert detection

| Alert | Severity | Trigger |
|-------|----------|---------|
| SYN Flood | HIGH | >20 SYN packets from the same IP within 5 seconds |
| Port Scan | MEDIUM | >15 unique destination ports probed by the same IP |
| Suspicious Port | HIGH | Connection attempt to known malicious ports (4444, 1337, 31337, 6667, 9001) |

---

## Tech stack

| Layer | Technology |
|-------|-----------|
| Backend | Python, Flask, flask-cors |
| Packet capture | Scapy (local only) |
| Frontend | HTML, CSS, Vanilla JS |
| Charts | Chart.js |
| Hosting | Vercel (serverless) |

---

## Roadmap

- [ ] PCAP file upload and offline analysis
- [ ] GeoIP lookup with country flags on IP table
- [ ] SQLite persistence for capture history
- [ ] WebSocket push instead of REST polling
- [ ] Anomaly detection with scikit-learn

---

## License

MIT — see [LICENSE](./LICENSE) for details.
