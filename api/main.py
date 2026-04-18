"""Thin FastAPI wrapper. Fires repository_dispatch at the GitHub repo and
proxies status / artifact retrieval. Optional — same code path as the
PowerShell module, just a different front door.

Run locally:
    uvicorn api.main:app --reload --port 8080

Env vars:
    GH_DISPATCH_TOKEN   GitHub PAT with contents:write + actions:read
    GH_REPO_OWNER       Repo owner
    GH_REPO_NAME        Repo name
    API_TOKEN           Bearer token required on /scan requests
"""
from __future__ import annotations

import io
import os
import time
import zipfile
from datetime import datetime, timedelta, timezone

import requests
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, HttpUrl

GH_TOKEN = os.environ.get("GH_DISPATCH_TOKEN")
GH_OWNER = os.environ.get("GH_REPO_OWNER")
GH_REPO = os.environ.get("GH_REPO_NAME")
API_TOKEN = os.environ.get("API_TOKEN")

GH_API = "https://api.github.com"

app = FastAPI(title="Malicious URL Checker API", version="0.1.0")


class ScanRequest(BaseModel):
    url: HttpUrl


class ScanResponse(BaseModel):
    run_id: int | None
    status_url: str
    run_url: str
    expected_seconds: int = 240


def _require_auth(authorization: str | None) -> None:
    if not API_TOKEN:
        raise HTTPException(500, "server missing API_TOKEN")
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "missing bearer token")
    if authorization.split(" ", 1)[1].strip() != API_TOKEN:
        raise HTTPException(403, "bad token")


def _require_gh() -> None:
    if not (GH_TOKEN and GH_OWNER and GH_REPO):
        raise HTTPException(500, "server missing GH_DISPATCH_TOKEN / GH_REPO_OWNER / GH_REPO_NAME")


def _gh_headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {GH_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


@app.post("/scan", response_model=ScanResponse, status_code=202)
def scan(req: ScanRequest, authorization: str | None = Header(default=None)) -> ScanResponse:
    _require_auth(authorization)
    _require_gh()

    # Fire repository_dispatch
    resp = requests.post(
        f"{GH_API}/repos/{GH_OWNER}/{GH_REPO}/dispatches",
        headers=_gh_headers(),
        json={"event_type": "analyze-url", "client_payload": {"url": str(req.url)}},
        timeout=15,
    )
    if resp.status_code >= 300:
        raise HTTPException(resp.status_code, f"dispatch failed: {resp.text[:200]}")

    # Find the run (look for repository_dispatch runs started in the last 2 min)
    run_id = None
    deadline = time.time() + 60
    while time.time() < deadline and run_id is None:
        time.sleep(3)
        r = requests.get(
            f"{GH_API}/repos/{GH_OWNER}/{GH_REPO}/actions/workflows/analyze-url.yml/runs",
            headers=_gh_headers(),
            params={"event": "repository_dispatch", "per_page": 10},
            timeout=15,
        )
        if r.status_code != 200:
            continue
        for run in r.json().get("workflow_runs", []):
            created = datetime.fromisoformat(run["created_at"].replace("Z", "+00:00"))
            age = datetime.now(timezone.utc) - created
            if age < timedelta(minutes=2) and run["status"] in ("queued", "in_progress", "waiting"):
                run_id = run["id"]
                break

    if not run_id:
        raise HTTPException(504, "dispatched but could not locate workflow run")

    return ScanResponse(
        run_id=run_id,
        status_url=f"/scan/{run_id}",
        run_url=f"https://github.com/{GH_OWNER}/{GH_REPO}/actions/runs/{run_id}",
    )


@app.get("/scan/{run_id}")
def scan_status(run_id: int, authorization: str | None = Header(default=None)) -> dict:
    _require_auth(authorization)
    _require_gh()

    run = requests.get(
        f"{GH_API}/repos/{GH_OWNER}/{GH_REPO}/actions/runs/{run_id}",
        headers=_gh_headers(),
        timeout=15,
    )
    if run.status_code != 200:
        raise HTTPException(run.status_code, run.text[:200])

    run_data = run.json()
    result = {
        "run_id": run_id,
        "status": run_data["status"],
        "conclusion": run_data.get("conclusion"),
        "run_url": run_data["html_url"],
        "summary": None,
    }

    if run_data["status"] != "completed":
        return result

    artifacts = requests.get(
        f"{GH_API}/repos/{GH_OWNER}/{GH_REPO}/actions/runs/{run_id}/artifacts",
        headers=_gh_headers(),
        timeout=15,
    ).json()
    artifact = next((a for a in artifacts.get("artifacts", []) if a["name"].startswith("analyze-url-")), None)
    if not artifact:
        return result

    dl = requests.get(artifact["archive_download_url"], headers=_gh_headers(), timeout=60)
    if dl.status_code != 200:
        return result

    with zipfile.ZipFile(io.BytesIO(dl.content)) as zf:
        if "summary.json" in zf.namelist():
            with zf.open("summary.json") as f:
                import json as _json
                result["summary"] = _json.loads(f.read().decode("utf-8"))

    return result


@app.get("/health")
def health() -> dict:
    return {"ok": True, "owner": GH_OWNER, "repo": GH_REPO, "configured": bool(GH_TOKEN and API_TOKEN)}
