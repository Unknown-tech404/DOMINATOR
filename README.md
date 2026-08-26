# 🚀 DOMINATOR v2.0 - Zero-Config Domain Reconnaissance Tool

[![Python](https://img.shields.io/badge/Python-3.7%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/Unknown-tech404/DOMINATOR.svg)](https://github.com/Unknown-tech404/DOMINATOR/stargazers)
[![GitHub issues](https://img.shields.io/github/issues/Unknown-tech404/DOMINATOR.svg)](https://github.com/Unknown-tech404/DOMINATOR/issues)

> **DOMINATOR** is a powerful, zero-configuration domain reconnaissance tool that requires **no API keys** and **no arguments** to run. Just provide a domain and get comprehensive intelligence in seconds.

![DOMINATOR Banner](https://raw.githubusercontent.com/Unknown-tech404/DOMINATOR/main/assets/banner.png)

---

## ✨ Features

### 🔍 Passive Enumeration
- Subdomain Discovery from multiple sources:
  - Certificate Transparency logs (crt.sh)
  - DNSDumpster
  - Riddler.io
  - DNS records extraction (MX, NS, CNAME)

### 🌐 DNS Intelligence
- Full DNS record enumeration:
  - A, AAAA, MX, NS, TXT, CNAME, SOA, CAA, SRV
  - DNS Zone Transfer attempts
  - HackerTarget DNS lookup integration

### 🎯 Active Reconnaissance
- Port Scanning (25+ common ports):
  - HTTP/HTTPS, SSH, FTP, SMTP, MySQL, PostgreSQL, Redis
  - Banner grabbing for service identification
  - Multi-threaded for speed

### 🧠 IP Intelligence
- Geolocation (country, city, ISP, organization)
- ASN (Autonomous System Number) lookup
- Reverse DNS (PTR records)

### 🔒 Security Analysis
- SSL/TLS certificate inspection:
  - Issuer, Subject, Validity period
  - Serial number, Fingerprint
  - Version information

### 📊 Reporting
- JSON output with all collected data
- Colorful console output for easy reading
- Summary statistics displayed automatically

---

## 📦 Installation

### Quick Install

```bash
git clone https://github.com/Unknown-tech404/DOMINATOR.git
cd DOMINATOR
pip install -r requirements.txt
```
###Dependencies
```bash
dnspython>=2.6.1      # DNS resolution
python-whois>=0.9.4   # WHOIS lookup
requests>=2.31.0      # HTTP requests
aiohttp>=3.8.0        # Async HTTP
colorama>=0.4.6       # Colored output
```
## 🚀 Usage

### Basic Usage
```bash

python DOMINATOR.py example.com
```

###Show Help
```bash

python DOMINATOR.py
```

###Examples
```bash

# Scan a domain
python DOMINATOR.py google.com

# Scan with custom ports (edit DEFAULT_PORTS in code)
python DOMINATOR.py github.com

# Scan a subdomain
python DOMINATOR.py mail.example.com
```

### 📊 Output Example
```bash

{
  "target": "example.com",
  "timestamp": "2026-08-26T10:30:00Z",
  "version": "2.0",
  "subdomains": [
    "example.com",
    "www.example.com",
    "mail.example.com",
    "api.example.com"
  ],
  "subdomain_count": 4,
  "unique_ips": [
    "93.184.216.34",
    "93.184.216.35"
  ],
  "ip_count": 2,
  "ip_intelligence": {
    "93.184.216.34": {
      "reverse_dns": ["example.com"],
      "geolocation": {
        "status": "success",
        "country": "United States",
        "city": "Los Angeles",
        "isp": "Example ISP"
      },
      "asn": {
        "ASN": "AS15133",
        "Organization": "Example Org"
      }
    }
  },
  "port_scan": {
    "93.184.216.34": [
      {"port": 80, "state": "open", "latency_ms": 45.2, "banner": "HTTP/1.1 200 OK"},
      {"port": 443, "state": "open", "latency_ms": 52.1, "banner": "TLS/SSL Certificate"}
    ]
  },
  "dns": {
    "A": {"status": "ok", "values": ["93.184.216.34"]},
    "MX": {"status": "ok", "values": ["mail.example.com"]},
    "NS": {"status": "ok", "values": ["ns1.example.com"]}
  },
  "ssl_certificates": {
    "example.com": {
      "status": "ok",
      "issuer": {"O": "Example CA"},
      "not_before": "2025-01-01T00:00:00Z",
      "not_after": "2026-01-01T00:00:00Z"
    }
  }
}
```
## ⚠️ Disclaimer

    Important: This tool is designed for educational and authorized testing purposes only. Use it only on domains and IP addresses you own or have explicit permission to test. The author is not responsible for any misuse or damage caused by this tool.

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

    Fork the repository

    Create a feature branch (git checkout -b feature/AmazingFeature)

    Commit your changes (git commit -m 'Add AmazingFeature')

    Push to the branch (git push origin feature/AmazingFeature)

    Open a Pull Request

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.
⭐ Star History

If you find DOMINATOR useful, please give it a star on GitHub! ⭐

https://api.star-history.com/svg?repos=Unknown-tech404/DOMINATOR&type=Date

## Made with ❤️ by Unknown-tech404
