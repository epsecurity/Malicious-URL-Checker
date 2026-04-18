"""Submit a URL to urlscan.io, poll for results, extract key fields.

Writes:  out/urlscan.json

Standalone usage:
    URLSCAN_API_KEY=xxx python scripts/collect_urlscan.py --url "https://example.com"
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import requests

SUBMIT_URL = "https://urlscan.io/api/v1/scan/"
RESULT_URL = "https://urlscan.io/api/v1/result/{uuid}/"
POLL_INTERVAL = 5
POLL_MAX_ATTEMPTS = 18  # 90s
SUBMIT_TIMEOUT = 20


def submit(url: str, api_key: str) -> dict[str, Any]:
    resp = requests.post(
        SUBMIT_URL,
        headers={"API-Key": api_key, "Content-Type": "application/json"},
        json={"url": url, "visibility": "unlisted"},
        timeout=SUBMIT_TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()


def poll(uuid: str) -> dict[str, Any] | None:
    for attempt in range(POLL_MAX_ATTEMPTS):
        time.sleep(POLL_INTERVAL)
        try:
            resp = requests.get(RESULT_URL.format(uuid=uuid), timeout=15)
        except requests.RequestException:
            continue
        if resp.status_code == 404:
            continue  # not ready yet
        if resp.status_code == 200:
            return resp.json()
        # Any other status — fail fast
        return None
    return None


def extract(result: dict[str, Any]) -> dict[str, Any]:
    """Pull a compact subset of urlscan fields for Claude's context."""
    verdicts = result.get("verdicts", {}).get("overall", {}) or {}
    page = result.get("page", {}) or {}
    task = result.get("task", {}) or {}
    stats = result.get("stats", {}) or {}
    meta = result.get("meta", {}) or {}

    # Detected technologies (Wappalyzer)
    tech: list[str] = []
    wappa = meta.get("processors", {}).get("wappa", {}).get("data", []) or []
    for item in wappa:
        name = item.get("app") or item.get("name")
        if name:
            tech.append(name)

    # Network requests — keep distinct external hostnames (top 20)
    external_hosts: list[str] = []
    seen = set()
    page_host = (page.get("domain") or "").lower()
    for entry in result.get("lists", {}).get("urls", []) or []:
        try:
            host = entry.split("/")[2].lower() if "://" in entry else entry
        except Exception:
            continue
        if host and host != page_host and host not in seen:
            seen.add(host)
            external_hosts.append(host)
        if len(external_hosts) >= 20:
            break

    return {
        "uuid": task.get("uuid"),
        "result_url": task.get("reportURL"),
        "screenshot_url": task.get("screenshotURL"),
        "effective_url": page.get("url"),
        "title": page.get("title"),
        "country": page.get("country"),
        "server": page.get("server"),
        "ip": page.get("ip"),
        "asn": page.get("asn"),
        "asn_name": page.get("asnname"),
        "verdict_malicious": bool(verdicts.get("malicious", False)),
        "verdict_score": verdicts.get("score"),
        "verdict_categories": verdicts.get("categories", []) or [],
        "verdict_tags": verdicts.get("tags", []) or [],
        "stats_malicious_requests": stats.get("malicious"),
        "total_requests": stats.get("totalRequests"),
        "detected_technologies": tech,
        "external_hosts": external_hosts,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--output", default="out/urlscan.json")
    args = parser.parse_args()

    api_key = os.environ.get("URLSCAN_API_KEY")
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if not api_key:
        result = {"ok": False, "error": "URLSCAN_API_KEY not set"}
        output_path.write_text(json.dumps(result, indent=2))
        print(json.dumps(result, indent=2))
        return 0  # Don't fail the workflow — other sources can still run

    try:
        submission = submit(args.url, api_key)
        uuid = submission.get("uuid")
        if not uuid:
            raise RuntimeError(f"no uuid in submission response: {submission}")

        result_full = poll(uuid)
        if result_full is None:
            data = {
                "ok": False,
                "error": "scan not ready within poll window",
                "uuid": uuid,
                "result_url": submission.get("result"),
            }
        else:
            data = {"ok": True, **extract(result_full)}

    except requests.HTTPError as e:
        data = {"ok": False, "error": f"HTTP {e.response.status_code}: {e.response.text[:200]}"}
    except Exception as e:
        data = {"ok": False, "error": f"{type(e).__name__}: {e}"}

    output_path.write_text(json.dumps(data, indent=2))
    print(json.dumps(data, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
