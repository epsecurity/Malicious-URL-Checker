"""Validate and normalize the submitted URL. Blocks SSRF targets.

Writes:  out/target.json  with keys: {url, host, ok, reason}
Sets GHA step output 'url' when run under GitHub Actions.

Standalone usage:
    python scripts/validate_input.py --url "https://example.com"
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import socket
import sys
from pathlib import Path
from urllib.parse import urlparse, urlunparse

MAX_URL_LENGTH = 2048


def _is_blocked_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast:
        return True
    if addr.is_reserved or addr.is_unspecified:
        return True
    # AWS / GCP / Azure instance metadata endpoints
    if str(addr) in {"169.254.169.254", "100.100.100.200"}:
        return True
    return False


def validate(url: str) -> dict:
    if not url or len(url) > MAX_URL_LENGTH:
        return {"ok": False, "reason": "url missing or too long", "url": url}

    url = url.strip()

    # Default to https:// if no scheme given
    if "://" not in url:
        url = "https://" + url

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return {"ok": False, "reason": f"unsupported scheme: {parsed.scheme}", "url": url}

    host = parsed.hostname
    if not host:
        return {"ok": False, "reason": "no host in url", "url": url}

    # Reject literal IP hosts that are in blocked ranges
    try:
        ipaddress.ip_address(host)
        if _is_blocked_ip(host):
            return {"ok": False, "reason": f"blocked IP host: {host}", "url": url}
    except ValueError:
        # Hostname — resolve and check all returned addresses
        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror as e:
            return {"ok": False, "reason": f"dns resolution failed: {e}", "url": url}
        for info in infos:
            ip = info[4][0]
            if _is_blocked_ip(ip):
                return {"ok": False, "reason": f"host {host} resolves to blocked IP {ip}", "url": url}

    # Strip default ports, trailing fragment
    normalized = urlunparse(parsed._replace(fragment=""))

    return {"ok": True, "url": normalized, "host": host}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--output", default="out/target.json")
    args = parser.parse_args()

    result = validate(args.url)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    # Write to GHA step outputs so downstream jobs can consume
    gha_out = os.environ.get("GITHUB_OUTPUT")
    if gha_out:
        with open(gha_out, "a", encoding="utf-8") as f:
            f.write(f"ok={'true' if result['ok'] else 'false'}\n")
            f.write(f"url={result.get('url', '')}\n")
            f.write(f"host={result.get('host', '')}\n")

    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 2


if __name__ == "__main__":
    sys.exit(main())
