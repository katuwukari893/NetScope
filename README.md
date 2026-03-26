NetScope
A full-stack network traffic analyzer with real-time packet visualization, protocol breakdown, IP statistics, and an automated security alert engine. Built with Python, Flask, and vanilla JS — deployed on Vercel.
Show Image
Show Image
Show Image
Show Image

Features

Live packet stream — scrolling table of captured packets with protocol, source/destination IP, port, flags, and payload info
Protocol breakdown — real-time donut chart across HTTPS, HTTP, TCP, UDP, DNS, SSH, FTP
Top source IPs — ranked bar view of the most active IP addresses
Security alert engine — automatic detection of SYN floods, port scans, and suspicious port connections
Filter & search — filter the packet table by protocol or IP address on the fly
Dual capture mode — uses live scapy packet capture when run locally with root; falls back to realistic simulated traffic when deployed to the cloud


Project structure
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

Live demo

https://net-scope-two.vercel.app/
