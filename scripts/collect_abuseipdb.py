"""Resolve URL host to IP, query AbuseIPDB reputation.

Writes:  out/abuseipdb.json

Standalone usage:
    ABUSEIPDB_API_KEY=xxx python scripts/collect_abuseipdb.py --url "https://example.com"
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
from pathlib import Path
from urllib.parse import urlparse

import requests

CHECK_URL = "https://api.abuseipdb.com/api/v2/check"


def resolve(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


def query(ip: str, api_key: str) -> dict:
    resp = requests.get(
        CHECK_URL,
        headers={"Key": api_key, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json().get("data", {})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--output", default="out/abuseipdb.json")
    args = parser.parse_args()

    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if not api_key:
        data = {"ok": False, "error": "ABUSEIPDB_API_KEY not set"}
        output_path.write_text(json.dumps(data, indent=2))
        print(json.dumps(data, indent=2))
        return 0

    host = urlparse(args.url).hostname
    if not host:
        data = {"ok": False, "error": "could not extract host"}
        output_path.write_text(json.dumps(data, indent=2))
        return 0

    ip = resolve(host)
    if not ip:
        data = {"ok": False, "error": f"could not resolve {host}"}
        output_path.write_text(json.dumps(data, indent=2))
        print(json.dumps(data, indent=2))
        return 0

    try:
        raw = query(ip, api_key)
        data = {
            "ok": True,
            "host": host,
            "ip": ip,
            "abuse_confidence_score": raw.get("abuseConfidenceScore"),
            "total_reports": raw.get("totalReports"),
            "distinct_users": raw.get("numDistinctUsers"),
            "last_reported": raw.get("lastReportedAt"),
            "country_code": raw.get("countryCode"),
            "usage_type": raw.get("usageType"),
            "isp": raw.get("isp"),
            "domain": raw.get("domain"),
            "is_tor": raw.get("isTor"),
            "is_whitelisted": raw.get("isWhitelisted"),
        }
    except requests.HTTPError as e:
        data = {"ok": False, "error": f"HTTP {e.response.status_code}: {e.response.text[:200]}"}
    except Exception as e:
        data = {"ok": False, "error": f"{type(e).__name__}: {e}"}

    output_path.write_text(json.dumps(data, indent=2))
    print(json.dumps(data, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
