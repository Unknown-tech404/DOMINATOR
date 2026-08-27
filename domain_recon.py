#!/usr/bin/env python3
"""Permission-aware domain reconnaissance utility.

Performs WHOIS lookup, DNS enumeration, passive subdomain collection from crt.sh
and optionally SecurityTrails, followed by bounded TCP-connect checks against
IPs resolved from the collected hostnames.

Use only for domains and IP addresses you own or are explicitly authorized to test.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import os
import re
import socket
import sys
import time
from datetime import date, datetime, timezone
from typing import Any, Iterable

import dns.exception
import dns.resolver
import requests
import whois

USER_AGENT = "domain-recon/1.0 (authorized-security-assessment)"
DEFAULT_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA")
DEFAULT_PORTS = (21, 22, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587, 993, 995, 1433, 3306, 3389, 5432, 6379, 8080, 8443)
DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def json_safe(value: Any) -> Any:
    """Convert common third-party-library values to JSON-compatible values."""
    if isinstance(value, (datetime, date)):
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
        raise ValueError("Provide a valid fully qualified domain name, such as example.com.")
    return domain


def is_in_scope(hostname: str, root_domain: str) -> bool:
    hostname = hostname.lower().rstrip(".")
    return hostname == root_domain or hostname.endswith("." + root_domain)


def clean_hostname(value: str, root_domain: str) -> str | None:
    hostname = value.strip().lower().rstrip(".")
    if hostname.startswith("*."):
        hostname = hostname[2:]
    if not hostname or not is_in_scope(hostname, root_domain):
        return None
    if len(hostname) > 253 or any(not label or len(label) > 63 for label in hostname.split(".")):
        return None
    return hostname


def error_object(exc: Exception) -> dict[str, str]:
    return {"type": type(exc).__name__, "message": str(exc)}


def lookup_whois(domain: str) -> dict[str, Any]:
    try:
        record = whois.whois(domain)
        return {"status": "ok", "data": json_safe(dict(record))}
    except Exception as exc:  # WHOIS servers vary widely by TLD and may reject queries.
        return {"status": "error", "error": error_object(exc)}


def enumerate_dns(domain: str, timeout: float, lifetime: float) -> dict[str, Any]:
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = timeout
    resolver.lifetime = lifetime
    records: dict[str, Any] = {}

    for record_type in DEFAULT_RECORD_TYPES:
        try:
            answer = resolver.resolve(domain, record_type, raise_on_no_answer=False)
            values = [item.to_text() for item in answer] if answer.rrset else []
            records[record_type] = {"status": "ok", "values": values}
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            records[record_type] = {"status": "no_answer", "values": []}
        except dns.exception.DNSException as exc:
            records[record_type] = {"status": "error", "error": error_object(exc)}

    return records


def fetch_crtsh_subdomains(domain: str, request_timeout: float) -> dict[str, Any]:
    endpoint = "https://crt.sh/"
    try:
        response = requests.get(
            endpoint,
            params={"q": f"%.{domain}", "output": "json"},
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
            timeout=request_timeout,
        )
        response.raise_for_status()
        entries = response.json()
        names: set[str] = set()
        for entry in entries:
            for candidate in str(entry.get("name_value", "")).splitlines():
                hostname = clean_hostname(candidate, domain)
                if hostname:
                    names.add(hostname)
        return {
            "status": "ok",
            "source": "crt.sh",
            "query_url": response.url,
            "certificate_entries": len(entries),
            "subdomains": sorted(names),
        }
    except (requests.RequestException, ValueError, TypeError) as exc:
        return {"status": "error", "source": "crt.sh", "error": error_object(exc), "subdomains": []}


def fetch_securitytrails_subdomains(domain: str, api_key: str | None, request_timeout: float) -> dict[str, Any]:
    if not api_key:
        return {
            "status": "skipped",
            "source": "SecurityTrails",
            "reason": "No API key supplied. Set SECURITYTRAILS_API_KEY or use --securitytrails-api-key.",
            "subdomains": [],
        }

    endpoint = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    try:
        response = requests.get(
            endpoint,
            headers={"APIKEY": api_key, "User-Agent": USER_AGENT, "Accept": "application/json"},
            timeout=request_timeout,
        )
        response.raise_for_status()
        payload = response.json()
        names = {
            hostname
            for item in payload.get("subdomains", [])
            if (hostname := clean_hostname(f"{item}.{domain}", domain))
        }
        return {
            "status": "ok",
            "source": "SecurityTrails",
            "subdomains": sorted(names),
            "reported_count": len(payload.get("subdomains", [])),
        }
    except (requests.RequestException, ValueError, TypeError) as exc:
        return {
            "status": "error",
            "source": "SecurityTrails",
            "error": error_object(exc),
            "subdomains": [],
        }


def resolve_hostname(hostname: str) -> dict[str, Any]:
    addresses: set[str] = set()
    errors: list[dict[str, str]] = []
    try:
        results = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        addresses = {result[4][0] for result in results}
    except socket.gaierror as exc:
        errors.append(error_object(exc))

    return {"hostname": hostname, "ips": sorted(addresses), "errors": errors}


def resolve_hostnames(hostnames: Iterable[str], workers: int) -> list[dict[str, Any]]:
    ordered = sorted(set(hostnames))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        return list(executor.map(resolve_hostname, ordered))


def scan_one_port(ip: str, port: int, timeout: float) -> dict[str, Any] | None:
    started = time.monotonic()
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return {"port": port, "state": "open", "latency_ms": round((time.monotonic() - started) * 1000, 1)}
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def scan_ip(ip: str, ports: tuple[int, ...], timeout: float, workers: int) -> dict[str, Any]:
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, len(ports))) as executor:
        results = list(executor.map(lambda port: scan_one_port(ip, port, timeout), ports))
    return {"ip": ip, "open_tcp_ports": [result for result in results if result is not None]}


def scan_ips(ips: Iterable[str], ports: tuple[int, ...], timeout: float, workers: int) -> list[dict[str, Any]]:
    targets: list[str] = []
    for candidate in sorted(set(ips)):
        try:
            ipaddress.ip_address(candidate)
            targets.append(candidate)
        except ValueError:
            continue

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        return list(executor.map(lambda ip: scan_ip(ip, ports, timeout, workers), targets))


def parse_ports(raw_ports: str | None) -> tuple[int, ...]:
    if not raw_ports:
        return DEFAULT_PORTS
    ports: set[int] = set()
    for part in raw_ports.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            port = int(part)
        except ValueError as exc:
            raise ValueError(f"Invalid TCP port: {part}") from exc
        if not 1 <= port <= 65535:
            raise ValueError(f"TCP port must be 1–65535: {port}")
        ports.add(port)
    if not ports:
        raise ValueError("At least one TCP port must be supplied.")
    return tuple(sorted(ports))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Authorized domain reconnaissance with structured JSON output.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("domain", help="Root domain to assess, e.g. example.com")
    parser.add_argument("--output", "-o", help="Write JSON report to this file; defaults to stdout")
    parser.add_argument(
        "--authorized",
        action="store_true",
        help="Required acknowledgement that you own or have explicit authorization to assess this domain and its resolved IPs",
    )
    parser.add_argument("--securitytrails-api-key", help="SecurityTrails API key; alternatively use SECURITYTRAILS_API_KEY")
    parser.add_argument("--ports", help="Comma-separated TCP ports; uses a small common-port set when omitted")
    parser.add_argument("--connect-timeout", type=float, default=1.0, help="Timeout per TCP connection in seconds")
    parser.add_argument("--dns-timeout", type=float, default=2.0, help="DNS query timeout in seconds")
    parser.add_argument("--request-timeout", type=float, default=15.0, help="Passive-source HTTP timeout in seconds")
    parser.add_argument("--workers", type=int, default=8, help="Maximum concurrent hostname/IP checks")
    parser.add_argument("--skip-port-scan", action="store_true", help="Collect passive and DNS data without TCP-connect checks")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not args.authorized:
        parser.error("--authorized is required. Run only against systems you own or are explicitly permitted to assess.")
    if args.workers < 1 or args.workers > 32:
        parser.error("--workers must be between 1 and 32.")
    if args.connect_timeout <= 0 or args.dns_timeout <= 0 or args.request_timeout <= 0:
        parser.error("All timeout values must be greater than zero.")

    try:
        domain = normalize_domain(args.domain)
        ports = parse_ports(args.ports)
    except ValueError as exc:
        parser.error(str(exc))

    securitytrails_key = args.securitytrails_api_key or os.getenv("SECURITYTRAILS_API_KEY")
    report: dict[str, Any] = {
        "schema_version": "1.0",
        "generated_at": utc_now(),
        "target": {"domain": domain},
        "authorization": {
            "user_attestation": "The operator supplied --authorized and asserts authority to assess the target domain and IPs resolved from it.",
            "scope_note": "Passive sources may return historical or third-party records; only in-scope hostnames are resolved, and only their resolved IPs are checked.",
        },
        "configuration": {
            "tcp_ports": list(ports),
            "connect_timeout_seconds": args.connect_timeout,
            "max_workers": args.workers,
            "port_scan_skipped": args.skip_port_scan,
        },
        "whois": lookup_whois(domain),
        "dns": enumerate_dns(domain, args.dns_timeout, args.dns_timeout * 2),
    }

    crtsh = fetch_crtsh_subdomains(domain, args.request_timeout)
    securitytrails = fetch_securitytrails_subdomains(domain, securitytrails_key, args.request_timeout)
    discovered = {domain, *crtsh["subdomains"], *securitytrails["subdomains"]}
    resolutions = resolve_hostnames(discovered, args.workers)
    resolved_ips = sorted({ip for resolution in resolutions for ip in resolution["ips"]})

    report["subdomain_discovery"] = {
        "sources": {"crt_sh": crtsh, "securitytrails": securitytrails},
        "unique_in_scope_hostnames": sorted(discovered),
        "unique_in_scope_hostname_count": len(discovered),
    }
    report["resolution"] = {"hostnames": resolutions, "unique_ips": resolved_ips}
    report["port_scan"] = (
        {"status": "skipped", "reason": "--skip-port-scan was supplied", "results": []}
        if args.skip_port_scan
        else {"status": "ok", "method": "bounded TCP connect", "results": scan_ips(resolved_ips, ports, args.connect_timeout, args.workers)}
    )

    rendered = json.dumps(json_safe(report), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if args.output:
        with open(args.output, "w", encoding="utf-8") as output_file:
            output_file.write(rendered)
        print(f"Wrote report to {args.output}", file=sys.stderr)
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
