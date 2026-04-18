"""WHOIS lookup for the URL's registrable domain.

Writes:  out/whois.json

Standalone usage:
    python scripts/collect_whois.py --url "https://example.com"
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import whois


def _first(value):
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _iso(dt) -> str | None:
    dt = _first(dt)
    if not isinstance(dt, datetime):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _age_days(dt) -> int | None:
    dt = _first(dt)
    if not isinstance(dt, datetime):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = datetime.now(timezone.utc) - dt
    return max(delta.days, 0)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--output", default="out/whois.json")
    args = parser.parse_args()

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    host = urlparse(args.url).hostname
    if not host:
        data = {"ok": False, "error": "could not extract host"}
        output_path.write_text(json.dumps(data, indent=2))
        print(json.dumps(data, indent=2))
        return 0

    try:
        record = whois.whois(host)
        creation = record.creation_date
        expiration = record.expiration_date
        registrant_name = _first(record.get("name")) if hasattr(record, "get") else None
        org = _first(record.get("org")) if hasattr(record, "get") else None
        registrant_lower = (str(registrant_name) + " " + str(org)).lower() if (registrant_name or org) else ""
        privacy = any(k in registrant_lower for k in ("privacy", "whoisguard", "proxy", "redacted", "withheld"))

        data = {
            "ok": True,
            "host": host,
            "domain": _first(record.domain_name),
            "registrar": _first(record.registrar),
            "creation_date": _iso(creation),
            "expiration_date": _iso(expiration),
            "age_days": _age_days(creation),
            "country": _first(record.country) if hasattr(record, "country") else None,
            "status": record.status if isinstance(record.status, list) else ([record.status] if record.status else []),
            "name_servers": record.name_servers if isinstance(record.name_servers, list) else ([record.name_servers] if record.name_servers else []),
            "privacy_protected": privacy,
        }
    except Exception as e:
        data = {"ok": False, "host": host, "error": f"{type(e).__name__}: {e}"}

    output_path.write_text(json.dumps(data, indent=2))
    print(json.dumps(data, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
