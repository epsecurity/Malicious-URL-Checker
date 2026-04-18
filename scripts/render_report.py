"""Render the short terminal summary JSON and a self-contained HTML report.

Consumes:  out/verdict.json + out/{urlscan,abuseipdb,gsb,whois,raw-html,patterns}.json
Produces:  out/summary.json, out/report.html

Standalone usage:
    python scripts/render_report.py --url "https://example.com"
"""
from __future__ import annotations

import argparse
import html
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


def _load(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def defang(url: str) -> str:
    return url.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]", 1)


def build_summary(url: str, evidence: dict[str, Any]) -> dict[str, Any]:
    verdict = evidence.get("verdict") or {}
    urlscan = evidence.get("urlscan") or {}
    whois_data = evidence.get("whois") or {}
    abuse = evidence.get("abuseipdb") or {}

    return {
        "url": url,
        "url_defanged": defang(url),
        "verdict": verdict.get("verdict", "insufficient_data"),
        "confidence": verdict.get("confidence", 0.0),
        "summary": verdict.get("summary", ""),
        "key_indicators": verdict.get("key_indicators", []),
        "recommended_action": verdict.get("recommended_action", "investigate_further"),
        "reasoning_short": verdict.get("reasoning_short", ""),
        "urlscan_result_url": urlscan.get("result_url"),
        "domain_age_days": whois_data.get("age_days") if whois_data.get("ok") else None,
        "registrar": whois_data.get("registrar") if whois_data.get("ok") else None,
        "abuse_confidence_score": abuse.get("abuse_confidence_score") if abuse.get("ok") else None,
        "ip": abuse.get("ip") if abuse.get("ok") else None,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def build_mermaid_redirect_chain(raw_html: dict[str, Any] | None) -> str | None:
    if not raw_html or not raw_html.get("ok"):
        return None
    chain = raw_html.get("redirect_chain") or []
    if len(chain) <= 1:
        return None
    lines = ["flowchart LR"]
    nodes: list[str] = []
    for i, hop in enumerate(chain):
        label = hop.get("url", "")
        host = urlparse(label).hostname or label
        node_id = f"N{i}"
        nodes.append(f'    {node_id}["{html.escape(host)}<br/>{hop.get("status", "")}"]')
    lines.extend(nodes)
    for i in range(len(chain) - 1):
        lines.append(f"    N{i} --> N{i+1}")
    return "\n".join(lines)


def render_html(url: str, summary: dict[str, Any], evidence: dict[str, Any]) -> str:
    verdict = summary["verdict"]
    colors = {
        "malicious": "#d9534f",
        "suspicious": "#f0ad4e",
        "clean": "#5cb85c",
        "insufficient_data": "#999",
    }
    color = colors.get(verdict, "#999")

    mermaid_redirect = build_mermaid_redirect_chain(evidence.get("raw_html"))

    indicators_html = "".join(
        f"<li>{html.escape(i)}</li>" for i in summary.get("key_indicators", [])
    ) or "<li><em>(none)</em></li>"

    def section(title: str, obj: Any) -> str:
        pretty = html.escape(json.dumps(obj, indent=2, default=str))
        return f"""
        <details>
            <summary>{html.escape(title)}</summary>
            <pre>{pretty}</pre>
        </details>
        """

    mermaid_block = ""
    if mermaid_redirect:
        mermaid_block = f"""
        <h2>Redirect Chain</h2>
        <pre class="mermaid">{html.escape(mermaid_redirect)}</pre>
        <script type="module">
          import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';
          mermaid.initialize({{ startOnLoad: true }});
        </script>
        """

    return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>URL Analysis: {html.escape(summary['url_defanged'])}</title>
    <style>
        body {{ font-family: -apple-system, Segoe UI, sans-serif; max-width: 960px; margin: 2em auto; padding: 0 1em; color: #222; }}
        .verdict {{ display: inline-block; padding: 0.3em 0.8em; border-radius: 4px; color: white; font-weight: bold; background: {color}; }}
        .meta {{ color: #666; font-size: 0.9em; }}
        pre {{ background: #f5f5f5; padding: 1em; border-radius: 4px; overflow-x: auto; font-size: 0.85em; }}
        details {{ margin: 0.5em 0; }}
        summary {{ cursor: pointer; font-weight: bold; padding: 0.4em; background: #eee; border-radius: 4px; }}
        h1 {{ margin-bottom: 0.2em; }}
        h2 {{ margin-top: 1.5em; border-bottom: 1px solid #ddd; padding-bottom: 0.2em; }}
        ul {{ line-height: 1.6; }}
        a {{ color: #337ab7; }}
        .field {{ margin: 0.3em 0; }}
        .field strong {{ display: inline-block; min-width: 180px; }}
    </style>
</head>
<body>
    <h1>URL Analysis</h1>
    <p class="meta">{html.escape(summary['generated_at'])}</p>

    <div class="field"><strong>URL (defanged):</strong> <code>{html.escape(summary['url_defanged'])}</code></div>
    <div class="field"><strong>Verdict:</strong> <span class="verdict">{html.escape(verdict.upper())}</span> &nbsp; Confidence: <strong>{summary['confidence']:.2f}</strong></div>
    <div class="field"><strong>Recommended action:</strong> {html.escape(summary['recommended_action'])}</div>
    <div class="field"><strong>Summary:</strong> {html.escape(summary['summary'])}</div>

    <h2>Key Indicators</h2>
    <ul>{indicators_html}</ul>

    <h2>Reasoning</h2>
    <p>{html.escape(summary['reasoning_short'])}</p>

    <h2>Quick Facts</h2>
    <div class="field"><strong>Domain age:</strong> {summary.get('domain_age_days', '—')} days</div>
    <div class="field"><strong>Registrar:</strong> {html.escape(str(summary.get('registrar') or '—'))}</div>
    <div class="field"><strong>Hosting IP:</strong> {html.escape(str(summary.get('ip') or '—'))}</div>
    <div class="field"><strong>AbuseIPDB score:</strong> {summary.get('abuse_confidence_score', '—')}</div>
    <div class="field"><strong>URLScan report:</strong> {f'<a href="{html.escape(summary["urlscan_result_url"])}" target="_blank">open</a>' if summary.get('urlscan_result_url') else '—'}</div>

    {mermaid_block}

    <h2>Raw Evidence</h2>
    {section('urlscan.json', evidence.get('urlscan'))}
    {section('abuseipdb.json', evidence.get('abuseipdb'))}
    {section('gsb.json', evidence.get('gsb'))}
    {section('whois.json', evidence.get('whois'))}
    {section('patterns.json', evidence.get('patterns'))}
    {section('raw-html.json (meta)', {k: v for k, v in (evidence.get('raw_html') or {{}}).items() if k not in ('html', 'scripts', 'forms', 'iframes')})}
    {section('verdict.json', evidence.get('verdict'))}
</body>
</html>
"""


def render_terminal(summary: dict[str, Any]) -> str:
    """ANSI-colored terminal output."""
    colors = {
        "malicious": "\x1b[1;91m",
        "suspicious": "\x1b[1;93m",
        "clean": "\x1b[1;92m",
        "insufficient_data": "\x1b[1;90m",
    }
    reset = "\x1b[0m"
    bold = "\x1b[1m"
    c = colors.get(summary["verdict"], "\x1b[0m")

    lines = [
        "",
        f"URL Analysis: {summary['url_defanged']}",
        "",
        f"  Verdict:       {c}{summary['verdict'].upper():<16}{reset} Confidence: {summary['confidence']:.2f}",
        f"  Action:        {summary['recommended_action']}",
        f"  Summary:       {summary['summary']}",
        "",
        "  Key Indicators:",
    ]
    for ind in summary["key_indicators"]:
        lines.append(f"    • {ind}")
    if not summary["key_indicators"]:
        lines.append("    (none)")

    lines.append("")
    if summary.get("domain_age_days") is not None:
        lines.append(f"  Domain age:    {summary['domain_age_days']} days ({summary.get('registrar') or 'registrar unknown'})")
    if summary.get("ip"):
        abuse = summary.get("abuse_confidence_score")
        abuse_str = f"{abuse}/100" if abuse is not None else "n/a"
        lines.append(f"  Hosting IP:    {summary['ip']}   AbuseIPDB: {abuse_str}")
    if summary.get("urlscan_result_url"):
        lines.append(f"  URLScan:       {summary['urlscan_result_url']}")

    lines.append(f"\n  {bold}Reasoning:{reset} {summary['reasoning_short']}")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--out-dir", default="out")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    evidence = {
        "urlscan": _load(out_dir / "urlscan.json"),
        "abuseipdb": _load(out_dir / "abuseipdb.json"),
        "gsb": _load(out_dir / "gsb.json"),
        "whois": _load(out_dir / "whois.json"),
        "raw_html": _load(out_dir / "raw-html.json"),
        "patterns": _load(out_dir / "patterns.json"),
        "verdict": _load(out_dir / "verdict.json"),
    }

    summary = build_summary(args.url, evidence)
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))
    (out_dir / "report.html").write_text(render_html(args.url, summary, evidence), encoding="utf-8")

    print(render_terminal(summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
