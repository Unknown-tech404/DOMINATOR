#!/usr/bin/env python3
"""
DOMINATOR v2.0 - Zero-Config Domain Reconnaissance
Usage: python dominator.py example.com
No API keys required. No arguments needed. Just run.
"""

from __future__ import annotations

import argparse
import asyncio
import aiohttp
import concurrent.futures
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Set, Optional
from urllib.parse import urlparse

import dns.exception
import dns.resolver
import dns.reversename
import requests
import whois

# ==================== BANNERS ====================
SMALL_BANNER = """
▓▓▓▓   ▓▓▓  ▓   ▓ ▓▓▓ ▓   ▓  ▓▓▓  ▓▓▓▓▓  ▓▓▓  ▓▓▓▓    
▓░░░▓ ▓ ░░▓ ▓▓ ▓▓░ ▓░░▓▓  ▓░▓ ░░▓  ░▓░░░▓ ░░▓ ▓░░░▓   
▓░░░▓░▓░ ░▓░▓░▓ ▓░░▓░░▓░▓ ▓░▓▓▓▓▓░  ▓░░░▓░ ░▓░▓▓▓▓░░  
▓░░ ▓░▓░░ ▓░▓░░░▓░░▓░░▓░░▓▓░▓░░░▓░░ ▓░░ ▓░░ ▓░▓░░▓░ ░ 
▓▓▓▓ ░░▓▓▓ ░▓░░ ▓░▓▓▓░▓░░ ▓░▓░░░▓░░ ▓░░  ▓▓▓ ░▓░░░▓░  
 ░░░░ ░ ░░░ ░░░  ░░░░░ ░░  ░░░░  ░░  ░░   ░░░ ░░░  ░  
  ░░░░   ░░░  ░   ░ ░░░ ░   ░ ░   ░   ░    ░░░  ░   ░ 
"""

USAGE_TEXT = """
╔══════════════════════════════════════════════════════════════╗
║                    DOMINATOR v2.0                            ║
║         Zero-Config Domain Reconnaissance Tool              ║
╚══════════════════════════════════════════════════════════════╝

USAGE:
    python dominator.py <domain>

EXAMPLES:
    python dominator.py example.com
    python dominator.py google.com
    python dominator.py github.com

FEATURES:
    • Subdomain enumeration (crt.sh, DNSDumpster, Riddler)
    • DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA, CAA, SRV)
    • IP resolution & intelligence (GeoIP, ASN, Reverse DNS)
    • Port scanning (25 common ports with banner grabbing)
    • SSL/TLS certificate analysis
    • WHOIS lookup
    • JSON report generation

OUTPUT:
    Creates <domain>_report.json with all collected data

REQUIREMENTS:
    pip install dnspython python-whois requests aiohttp

NOTE:
    No API keys required. All sources are public and free.
"""

# ==================== CONFIGURATION ====================
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
DEFAULT_PORTS = (21, 22, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 
                 465, 587, 993, 995, 1433, 3306, 3389, 5432, 6379, 8080, 8443, 
                 9000, 9200, 27017, 27018, 5000, 8000, 8888)
DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)

# Public APIs (no registration needed)
PUBLIC_APIS = {
    "dns_history": "https://api.securitytrails.com/v1/domain/{domain}/subdomains",
    "whois_history": "https://api.domainsdb.info/v1/domains/search?domain={domain}",
    "certificate": "https://crt.sh/?q=%.{domain}&output=json",
    "reverse_dns": "https://api.hackertarget.com/reversedns/?q={domain}",
    "asn_lookup": "https://api.hackertarget.com/aslookup/?q={domain}",
    "geo_ip": "http://ip-api.com/json/{ip}",
    "dns_records": "https://api.hackertarget.com/dnslookup/?q={domain}",
}

# ==================== UTILITY FUNCTIONS ====================
def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def json_safe(value: Any) -> Any:
    if isinstance(value, (datetime)):
        return value.isoformat()
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [json_safe(item) for item in value]
    return value

def normalize_domain(raw_domain: str) -> str:
    domain = raw_domain.strip().lower().rstrip(".")
    if domain.startswith("*."):
        domain = domain[2:]
    if not DOMAIN_PATTERN.fullmatch(domain):
        raise ValueError(f"Invalid domain: {raw_domain}")
    return domain

def is_in_scope(hostname: str, root_domain: str) -> bool:
    hostname = hostname.lower().rstrip(".")
    return hostname == root_domain or hostname.endswith("." + root_domain)

def clean_hostname(value: str, root_domain: str) -> Optional[str]:
    hostname = value.strip().lower().rstrip(".")
    if hostname.startswith("*."):
        hostname = hostname[2:]
    if not hostname or not is_in_scope(hostname, root_domain):
        return None
    if len(hostname) > 253 or any(not label or len(label) > 63 for label in hostname.split(".")):
        return None
    return hostname

def error_object(exc: Exception) -> Dict[str, str]:
    return {"type": type(exc).__name__, "message": str(exc)}

# ==================== PASSIVE ENUMERATION ====================
def fetch_crtsh(domain: str) -> List[str]:
    """Get subdomains from certificate transparency logs"""
    try:
        response = requests.get(
            "https://crt.sh/",
            params={"q": f"%.{domain}", "output": "json"},
            headers={"User-Agent": USER_AGENT},
            timeout=15
        )
        response.raise_for_status()
        entries = response.json()
        subdomains = set()
        for entry in entries:
            for candidate in str(entry.get("name_value", "")).splitlines():
                hostname = clean_hostname(candidate, domain)
                if hostname:
                    subdomains.add(hostname)
        return sorted(subdomains)
    except Exception:
        return []

def fetch_dns_dumpster(domain: str) -> List[str]:
    """Get subdomains from DNSDumpster"""
    try:
        session = requests.Session()
        resp = session.get("https://dnsdumpster.com/", timeout=10)
        csrf = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', resp.text)
        if not csrf:
            return []
        
        resp = session.post(
            "https://dnsdumpster.com/",
            data={"csrfmiddlewaretoken": csrf.group(1), "targetip": domain},
            headers={"Referer": "https://dnsdumpster.com/"},
            timeout=15
        )
        
        pattern = re.compile(r'<td class="col-md-4">([^<]+)</td>')
        matches = pattern.findall(resp.text)
        subdomains = set()
        for match in matches:
            hostname = clean_hostname(match.strip(), domain)
            if hostname:
                subdomains.add(hostname)
        return sorted(subdomains)
    except Exception:
        return []

def fetch_riddler(domain: str) -> List[str]:
    """Get subdomains from Riddler.io"""
    try:
        response = requests.get(
            "https://riddler.io/search",
            params={"q": f"domain:{domain}"},
            headers={"User-Agent": USER_AGENT},
            timeout=10
        )
        data = response.json() if response.text.startswith('{') else {}
        subdomains = set()
        for result in data.get("results", []):
            hostname = clean_hostname(result.get("name", ""), domain)
            if hostname:
                subdomains.add(hostname)
        return sorted(subdomains)
    except Exception:
        return []

def fetch_hackertarget_dns(domain: str) -> Dict[str, List[str]]:
    """Get DNS records from HackerTarget"""
    records = {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [], "CNAME": []}
    try:
        response = requests.get(
            f"https://api.hackertarget.com/dnslookup/?q={domain}",
            headers={"User-Agent": USER_AGENT},
            timeout=10
        )
        lines = response.text.strip().split("\n")
        for line in lines:
            if ":" in line:
                record_type, value = line.split(":", 1)
                record_type = record_type.strip().upper()
                if record_type in records:
                    records[record_type].append(value.strip())
    except Exception:
        pass
    return records

def fetch_public_whois(domain: str) -> Dict[str, Any]:
    """WHOIS lookup with fallback to multiple servers"""
    try:
        record = whois.whois(domain)
        return {"status": "ok", "data": json_safe(dict(record))}
    except Exception:
        try:
            response = requests.get(
                f"https://api.domainsdb.info/v1/domains/search?domain={domain}",
                headers={"User-Agent": USER_AGENT},
                timeout=10
            )
            return {"status": "ok", "data": response.json()}
        except Exception:
            return {"status": "error", "error": {"message": "WHOIS lookup failed"}}

# ==================== DNS ENUMERATION ====================
def dns_enumeration(domain: str) -> Dict[str, Any]:
    """Comprehensive DNS record enumeration"""
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = 2.0
    resolver.lifetime = 4.0
    
    record_types = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA", "SRV")
    results = {}
    
    for record_type in record_types:
        try:
            answer = resolver.resolve(domain, record_type, raise_on_no_answer=False)
            values = [item.to_text() for item in answer] if answer.rrset else []
            results[record_type] = {"status": "ok", "values": values}
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            results[record_type] = {"status": "no_answer", "values": []}
        except dns.exception.DNSException as exc:
            results[record_type] = {"status": "error", "error": error_object(exc)}
    
    try:
        ns_records = results.get("NS", {}).get("values", [])
        for ns in ns_records[:3]:
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=5))
                results["zone_transfer"] = {
                    "status": "success",
                    "records": [str(name) for name in zone.nodes.keys()]
                }
                break
            except Exception:
                continue
    except Exception:
        pass
    
    return results

# ==================== REVERSE DNS & IP INTEL ====================
def reverse_dns_lookup(ip: str) -> List[str]:
    """Get PTR records for an IP"""
    try:
        addr = dns.reversename.from_address(ip)
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.0
        answer = resolver.resolve(addr, "PTR")
        return [str(record) for record in answer]
    except Exception:
        return []

def get_ip_geolocation(ip: str) -> Dict[str, Any]:
    """Get geolocation data from free API"""
    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,city,region,isp,org,as,lat,lon"},
            timeout=5
        )
        if response.status_code == 200:
            return response.json()
    except Exception:
        pass
    return {"status": "fail", "message": "Geolocation unavailable"}

def get_asn_info(ip: str) -> Dict[str, Any]:
    """Get ASN information"""
    try:
        response = requests.get(
            f"https://api.hackertarget.com/aslookup/?q={ip}",
            headers={"User-Agent": USER_AGENT},
            timeout=5
        )
        if response.status_code == 200:
            lines = response.text.strip().split("\n")
            asn_data = {}
            for line in lines:
                if ":" in line:
                    key, val = line.split(":", 1)
                    asn_data[key.strip()] = val.strip()
            return asn_data
    except Exception:
        pass
    return {}

# ==================== PORT SCANNING ====================
def scan_port(ip: str, port: int, timeout: float = 1.0) -> Optional[Dict[str, Any]]:
    """TCP port scan with banner grabbing"""
    started = time.monotonic()
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            latency = round((time.monotonic() - started) * 1000, 1)
            result = {"port": port, "state": "open", "latency_ms": latency}
            
            try:
                sock.settimeout(2.0)
                if port == 80 or port == 443:
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                elif port == 21:
                    sock.send(b"QUIT\r\n")
                elif port == 22:
                    sock.send(b"SSH-2.0-Client\r\n")
                elif port == 25:
                    sock.send(b"EHLO test\r\n")
                elif port == 110:
                    sock.send(b"QUIT\r\n")
                elif port == 143:
                    sock.send(b"LOGOUT\r\n")
                else:
                    sock.send(b"\n")
                
                banner = sock.recv(256).decode("utf-8", errors="ignore").strip()
                if banner:
                    result["banner"] = banner[:200]
            except Exception:
                pass
            
            return result
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None

def scan_ports(ip: str, ports: tuple = DEFAULT_PORTS) -> List[Dict[str, Any]]:
    """Multi-threaded port scanning"""
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(scan_port, ip, port): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
    return sorted(open_ports, key=lambda x: x["port"])

# ==================== SSL/TLS ANALYSIS ====================
def get_ssl_info(domain: str) -> Dict[str, Any]:
    """Get SSL certificate information"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return {
                    "status": "ok",
                    "subject": dict(cert.get("subject", [])),
                    "issuer": dict(cert.get("issuer", [])),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "serial": cert.get("serialNumber"),
                    "version": cert.get("version"),
                    "fingerprint": ssock.getpeercert(binary_form=True).hex()[:40]
                }
    except Exception as exc:
        return {"status": "error", "error": error_object(exc)}

# ==================== MAIN ENGINE ====================
class Dominator:
    def __init__(self, domain: str):
        self.domain = normalize_domain(domain)
        self.subdomains = set()
        self.ips = set()
        self.results = {
            "target": domain,
            "timestamp": utc_now(),
            "version": "2.0"
        }
    
    def run_passive_enumeration(self):
        """Collect subdomains from multiple sources"""
        print(f"[*] Scanning {self.domain}...", flush=True)
        
        sources = [
            ("crt.sh", fetch_crtsh),
            ("DNSDumpster", fetch_dns_dumpster),
            ("Riddler", fetch_riddler),
        ]
        
        all_subdomains = set([self.domain])
        for name, func in sources:
            try:
                print(f"[*] Querying {name}...", flush=True)
                results = func(self.domain)
                all_subdomains.update(results)
                print(f"[+] {name}: found {len(results)} subdomains", flush=True)
            except Exception as e:
                print(f"[-] {name} failed: {e}", flush=True)
        
        dns_records = fetch_hackertarget_dns(self.domain)
        for record_type, values in dns_records.items():
            for value in values:
                if record_type in ["MX", "NS", "CNAME"]:
                    potential = clean_hostname(value, self.domain)
                    if potential:
                        all_subdomains.add(potential)
        
        self.subdomains = all_subdomains
        self.results["subdomains"] = sorted(self.subdomains)
        self.results["subdomain_count"] = len(self.subdomains)
        
        print(f"[+] Total subdomains: {len(self.subdomains)}", flush=True)
    
    def resolve_hostnames(self):
        """Resolve all subdomains to IPs"""
        print("[*] Resolving hostnames...", flush=True)
        resolved = {}
        ips = set()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(socket.gethostbyname_ex, host): host for host in self.subdomains}
            for future in concurrent.futures.as_completed(futures):
                host = futures[future]
                try:
                    _, _, ip_list = future.result()
                    resolved[host] = ip_list
                    ips.update(ip_list)
                except Exception:
                    resolved[host] = []
        
        self.ips = ips
        self.results["resolved"] = resolved
        self.results["unique_ips"] = sorted(self.ips)
        self.results["ip_count"] = len(self.ips)
        
        print(f"[+] Resolved {len(resolved)} hostnames to {len(ips)} unique IPs", flush=True)
    
    def analyze_ips(self):
        """Get intelligence on all IPs"""
        print("[*] Analyzing IPs...", flush=True)
        ip_intel = {}
        
        for ip in list(self.ips)[:50]:
            intel = {
                "reverse_dns": reverse_dns_lookup(ip),
                "geolocation": get_ip_geolocation(ip),
                "asn": get_asn_info(ip)
            }
            ip_intel[ip] = intel
            
            geo = intel["geolocation"]
            if geo.get("status") == "success":
                print(f"  {ip}: {geo.get('country', 'Unknown')} - {geo.get('isp', 'Unknown')}", flush=True)
        
        self.results["ip_intelligence"] = ip_intel
    
    def scan_all_ips(self):
        """Port scan all unique IPs"""
        print(f"[*] Port scanning {len(self.ips)} IPs...", flush=True)
        print("[!] This may take a while. Press Ctrl+C to skip.", flush=True)
        
        scan_results = {}
        for ip in list(self.ips)[:20]:
            try:
                open_ports = scan_ports(ip)
                if open_ports:
                    scan_results[ip] = open_ports
                    print(f"[+] {ip}: {len(open_ports)} open ports", flush=True)
                else:
                    print(f"[-] {ip}: no open ports found", flush=True)
            except Exception as e:
                print(f"[-] {ip} scan failed: {e}", flush=True)
        
        self.results["port_scan"] = scan_results
    
    def get_ssl_certificates(self):
        """Check SSL for all subdomains"""
        print("[*] Checking SSL certificates...", flush=True)
        ssl_info = {}
        
        for host in list(self.subdomains)[:20]:
            try:
                info = get_ssl_info(host)
                if info.get("status") == "ok":
                    ssl_info[host] = info
                    print(f"[+] {host}: SSL certificate valid", flush=True)
            except Exception:
                pass
        
        self.results["ssl_certificates"] = ssl_info
    
    def dns_records(self):
        """Get all DNS records"""
        print("[*] Gathering DNS records...", flush=True)
        self.results["dns"] = dns_enumeration(self.domain)
        
        hackertarget = fetch_hackertarget_dns(self.domain)
        self.results["dns"]["extra"] = hackertarget
    
    def whois_lookup(self):
        """Get WHOIS information"""
        print("[*] WHOIS lookup...", flush=True)
        self.results["whois"] = fetch_public_whois(self.domain)
    
    def generate_report(self):
        """Generate JSON report"""
        output_file = f"{self.domain}_report.json"
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(json_safe(self.results), f, indent=2, ensure_ascii=False)
        print(f"\n[+] Report saved to: {output_file}")
        print(f"[+] Total hosts: {len(self.subdomains)}")
        print(f"[+] Total IPs: {len(self.ips)}")
        
        print("\n=== SUMMARY ===")
        print(f"Domain: {self.domain}")
        print(f"Subdomains: {len(self.subdomains)}")
        print(f"Unique IPs: {len(self.ips)}")
        if "port_scan" in self.results:
            total_ports = sum(len(ports) for ports in self.results["port_scan"].values())
            print(f"Open ports found: {total_ports}")
        if "ssl_certificates" in self.results:
            print(f"SSL certificates: {len(self.results['ssl_certificates'])}")
        
        print("\n=== OPEN PORTS ===")
        for ip, ports in self.results.get("port_scan", {}).items():
            port_list = [p["port"] for p in ports]
            print(f"{ip}: {port_list}")
        
        print("\n=== IP GEOLOCATION ===")
        for ip, intel in self.results.get("ip_intelligence", {}).items():
            geo = intel.get("geolocation", {})
            if geo.get("status") == "success":
                print(f"{ip}: {geo.get('country')} - {geo.get('isp')}")
    
    def run(self):
        """Execute full reconnaissance"""
        print("=" * 60)
        print(f"DOMINATOR v2.0 - Scanning {self.domain}")
        print("=" * 60)
        
        self.whois_lookup()
        self.dns_records()
        self.run_passive_enumeration()
        self.resolve_hostnames()
        self.analyze_ips()
        self.get_ssl_certificates()
        self.scan_all_ips()
        self.generate_report()
        
        print("\n[+] Scan complete!")

# ==================== ENTRY POINT ====================
def main():
    if len(sys.argv) < 2:
        print(SMALL_BANNER)
        print(USAGE_TEXT)
        sys.exit(0)
    
    domain = sys.argv[1]
    
    # Show small banner before starting
    print(SMALL_BANNER)
    print(f"[*] Initializing DOMINATOR v2.0 for target: {domain}\n")
    
    try:
        dominator = Dominator(domain)
        dominator.run()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
