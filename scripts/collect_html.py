"""Fetch raw HTML, parse with BeautifulSoup, extract structural features.

Writes:  out/raw-html.json

Standalone usage:
    python scripts/collect_html.py --url "https://example.com"
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib.parse import urlparse

import requests
import urllib3
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Upgrade-Insecure-Requests": "1",
}

MAX_BYTES = 5 * 1024 * 1024   # 5MB cap
SCRIPT_BUDGET = 8 * 1024      # total chars of script content kept
HTML_HEAD_BUDGET = 2 * 1024
HTML_BODY_BUDGET = 8 * 1024


def _truncate_script(text: str, remaining: int) -> tuple[str, int]:
    if remaining <= 0:
        return "", 0
    if len(text) <= remaining:
        return text, remaining - len(text)
    return text[:remaining] + "\n/* ...truncated... */", 0


def fetch_and_parse(url: str) -> dict:
    try:
        resp = requests.get(
            url,
            headers=HEADERS,
            timeout=15,
            allow_redirects=True,
            verify=False,
            stream=True,
        )
    except requests.RequestException as e:
        return {"ok": False, "error": f"fetch failed: {type(e).__name__}: {e}"}

    # Capped read
    content = b""
    for chunk in resp.iter_content(chunk_size=16384):
        content += chunk
        if len(content) >= MAX_BYTES:
            break

    try:
        text = content.decode(resp.encoding or "utf-8", errors="replace")
    except Exception:
        text = content.decode("utf-8", errors="replace")

    redirect_chain = [{"url": h.url, "status": h.status_code} for h in resp.history]
    redirect_chain.append({"url": resp.url, "status": resp.status_code})

    soup = BeautifulSoup(text, "html.parser")
    title = (soup.title.string.strip() if soup.title and soup.title.string else None)

    # Extract scripts under a shared budget
    scripts: list[str] = []
    remaining = SCRIPT_BUDGET
    script_srcs: list[str] = []
    for script in soup.find_all("script"):
        if script.get("src"):
            script_srcs.append(script["src"])
            continue
        body = script.string or script.get_text() or ""
        body = body.strip()
        if not body:
            continue
        kept, remaining = _truncate_script(body, remaining)
        if kept:
            scripts.append(kept)
        if remaining <= 0:
            break

    # Forms
    forms: list[str] = []
    password_inputs = 0
    for form in soup.find_all("form"):
        forms.append(str(form)[:600])
        password_inputs += len(form.find_all("input", {"type": "password"}))

    # Iframes
    iframes = [str(f)[:300] for f in soup.find_all("iframe")]

    # External hosts referenced by scripts/links/images
    page_host = urlparse(resp.url).hostname or ""
    external_urls: list[str] = []
    seen = set()
    for tag, attr in (("script", "src"), ("link", "href"), ("img", "src"), ("iframe", "src")):
        for el in soup.find_all(tag):
            value = el.get(attr)
            if not value or not value.startswith(("http://", "https://")):
                continue
            host = urlparse(value).hostname or ""
            if host and host != page_host and host not in seen:
                seen.add(host)
                external_urls.append(value)
            if len(external_urls) >= 40:
                break

    # Compact HTML (head + body prefix)
    head_html = str(soup.head)[:HTML_HEAD_BUDGET] if soup.head else ""
    body_html = str(soup.body)[:HTML_BODY_BUDGET] if soup.body else text[:HTML_BODY_BUDGET]
    compact_html = head_html + "\n" + body_html

    # Meta refresh detection
    meta_refresh = None
    if soup.head:
        for meta in soup.head.find_all("meta"):
            if (meta.get("http-equiv", "") or "").lower() == "refresh":
                meta_refresh = meta.get("content", "")
                break

    return {
        "ok": True,
        "url": url,
        "effective_url": resp.url,
        "status_code": resp.status_code,
        "final_host": urlparse(resp.url).hostname,
        "content_type": resp.headers.get("Content-Type"),
        "content_length_bytes": len(content),
        "redirect_chain": redirect_chain,
        "title": title,
        "password_input_count": password_inputs,
        "form_count": len(soup.find_all("form")),
        "iframe_count": len(soup.find_all("iframe")),
        "script_src_count": len(script_srcs),
        "script_srcs": script_srcs[:20],
        "external_urls": external_urls,
        "meta_refresh": meta_refresh,
        "scripts": scripts,
        "forms": forms,
        "iframes": iframes,
        "html": compact_html,
        "ssl_verified": resp.url.startswith("https://"),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--output", default="out/raw-html.json")
    args = parser.parse_args()

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    data = fetch_and_parse(args.url)
    output_path.write_text(json.dumps(data, indent=2))

    # Compact print — the full payload is huge
    summary = {k: v for k, v in data.items() if k not in ("html", "scripts", "forms", "iframes")}
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
