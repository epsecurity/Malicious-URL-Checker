"""Run YARA-style regex rules against collected HTML output.

Consumes:  out/raw-html.json  (produced by collect_html.py)
Produces:  out/patterns.json

Standalone usage:
    python scripts/pattern_scan.py [--input out/raw-html.json] [--output out/patterns.json]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_PATH = REPO_ROOT / "rules" / "patterns.yml"

SNIPPET_CONTEXT = 40  # chars on each side of a match


@dataclass
class Hit:
    rule_id: str
    description: str
    severity: str
    tags: list[str]
    target: str
    snippet: str


def load_rules(path: Path = RULES_PATH) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data.get("rules", [])


def _target_text(html_data: dict[str, Any], target: str) -> str:
    if target == "html":
        return html_data.get("html", "") or ""
    if target == "scripts":
        return "\n".join(html_data.get("scripts", []) or [])
    if target == "forms":
        return "\n".join(html_data.get("forms", []) or [])
    if target == "urls":
        return "\n".join(html_data.get("external_urls", []) or [])
    if target == "title":
        return html_data.get("title", "") or ""
    if target == "all":
        parts = [
            html_data.get("html", "") or "",
            "\n".join(html_data.get("scripts", []) or []),
            "\n".join(html_data.get("forms", []) or []),
        ]
        return "\n".join(parts)
    return ""


def _extract_snippet(text: str, start: int, end: int) -> str:
    left = max(0, start - SNIPPET_CONTEXT)
    right = min(len(text), end + SNIPPET_CONTEXT)
    snippet = text[left:right]
    snippet = snippet.replace("\n", " ").replace("\r", " ")
    snippet = re.sub(r"\s+", " ", snippet).strip()
    return snippet[:200]


def scan(html_data: dict[str, Any], rules: list[dict[str, Any]]) -> list[Hit]:
    hits: list[Hit] = []
    is_http = (html_data.get("effective_url") or html_data.get("url", "")).lower().startswith("http://")

    for rule in rules:
        if rule.get("requires_http") and not is_http:
            continue

        target = rule.get("target", "html")
        text = _target_text(html_data, target)
        if not text:
            continue

        try:
            pattern = re.compile(rule["pattern"], re.DOTALL)
        except re.error as e:
            print(f"warn: bad regex in rule {rule.get('id')}: {e}", file=sys.stderr)
            continue

        match = pattern.search(text)
        if match:
            hits.append(
                Hit(
                    rule_id=rule["id"],
                    description=rule["description"],
                    severity=rule["severity"],
                    tags=rule.get("tags", []),
                    target=target,
                    snippet=_extract_snippet(text, match.start(), match.end()),
                )
            )

    return hits


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="out/raw-html.json")
    parser.add_argument("--output", default="out/patterns.json")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"input not found: {input_path}", file=sys.stderr)
        # Emit an empty result so downstream jobs do not fail.
        result = {"hits": [], "error": f"input missing: {input_path}"}
    else:
        with input_path.open("r", encoding="utf-8") as f:
            html_data = json.load(f)
        rules = load_rules()
        hits = scan(html_data, rules)
        result = {
            "hits": [asdict(h) for h in hits],
            "hit_count": len(hits),
            "rules_evaluated": len(rules),
        }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    print(f"patterns: {result.get('hit_count', 0)} hits -> {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
