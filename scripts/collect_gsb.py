"""Google Safe Browsing v4 threatMatches lookup.

Writes:  out/gsb.json

Standalone usage:
    GSB_API_KEY=xxx python scripts/collect_gsb.py --url "https://example.com"
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import requests

LOOKUP_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
CLIENT_ID = "malicious-url-checker"
CLIENT_VERSION = "0.1.0"

THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]


def query(url: str, api_key: str) -> dict:
    payload = {
        "client": {"clientId": CLIENT_ID, "clientVersion": CLIENT_VERSION},
        "threatInfo": {
            "threatTypes": THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    resp = requests.post(
        LOOKUP_URL,
        params={"key": api_key},
        json=payload,
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--output", default="out/gsb.json")
    args = parser.parse_args()

    api_key = os.environ.get("GSB_API_KEY")
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if not api_key:
        data = {"ok": False, "error": "GSB_API_KEY not set"}
        output_path.write_text(json.dumps(data, indent=2))
        print(json.dumps(data, indent=2))
        return 0

    try:
        raw = query(args.url, api_key)
        matches = raw.get("matches", []) or []
        data = {
            "ok": True,
            "threat_matches": [
                {
                    "threat_type": m.get("threatType"),
                    "platform_type": m.get("platformType"),
                    "threat_entry_type": m.get("threatEntryType"),
                    "cache_duration": m.get("cacheDuration"),
                }
                for m in matches
            ],
            "any_match": len(matches) > 0,
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
