#!/usr/bin/env python3
"""
render-redteam-summary.py

Parses `vetto redteam --json` output and renders a structured Markdown
table for $GITHUB_STEP_SUMMARY covering the 8 core kernel containment attack vectors.

Usage:
    vetto redteam --json | python3 scripts/render-redteam-summary.py
    python3 scripts/render-redteam-summary.py --input /path/to/report.json
    python3 scripts/render-redteam-summary.py /path/to/report.json
"""

import argparse
import json
import os
import sys


def parse_args():
    parser = argparse.ArgumentParser(
        description="Render vetto redteam JSON report into GitHub Actions step summary markdown."
    )
    parser.add_argument(
        "report_file",
        nargs="?",
        default=None,
        help="Path to JSON report file (defaults to stdin if omitted or '-')",
    )
    parser.add_argument(
        "--input",
        "-i",
        dest="input_file",
        default=None,
        help="Explicit input JSON report path (takes precedence over positional arg)",
    )
    parser.add_argument(
        "--output",
        "-o",
        dest="output_file",
        default=None,
        help="Output markdown file path (defaults to $GITHUB_STEP_SUMMARY if set, else stdout)",
    )
    parser.add_argument(
        "--allow-failure",
        action="store_true",
        default=False,
        help="Exit 0 even if redteam report indicates containment failures",
    )
    return parser.parse_args()


def sanitize_cell(val):
    if val is None:
        return ""
    s = str(val).replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
    s = s.replace("\\|", "|").replace("|", "\\|")
    return s.strip()


def load_report(args):
    input_path = args.input_file or args.report_file
    raw_content = None

    if not input_path or input_path == "-":
        if sys.stdin.isatty():
            env_file = os.environ.get("REDTEAM_REPORT")
            if env_file and os.path.exists(env_file):
                input_path = env_file
            else:
                if args.allow_failure:
                    return {
                        "results": [],
                        "passed": 0,
                        "failed": 0,
                        "skipped": 0,
                        "success": False,
                        "raw_error": "No stdin input provided",
                    }
                print("Error: No input provided on stdin or via arguments.", file=sys.stderr)
                sys.exit(2)
        else:
            raw_content = sys.stdin.read()

    if raw_content is None:
        if not os.path.exists(input_path):
            if args.allow_failure:
                return {
                    "results": [],
                    "passed": 0,
                    "failed": 0,
                    "skipped": 0,
                    "success": False,
                    "raw_error": f"Report file not found at '{input_path}'",
                }
            print(f"Error: Report file not found at '{input_path}'", file=sys.stderr)
            sys.exit(2)
        try:
            with open(input_path, "r", encoding="utf-8") as fh:
                raw_content = fh.read()
        except OSError as exc:
            if args.allow_failure:
                return {
                    "results": [],
                    "passed": 0,
                    "failed": 0,
                    "skipped": 0,
                    "success": False,
                    "raw_error": f"Error reading file '{input_path}': {exc}",
                }
            print(f"Error reading file '{input_path}': {exc}", file=sys.stderr)
            sys.exit(2)

    if not raw_content or not raw_content.strip():
        if args.allow_failure:
            return {
                "results": [],
                "passed": 0,
                "failed": 0,
                "skipped": 0,
                "success": False,
                "raw_error": "Empty redteam report input",
            }
        print("Error: Empty redteam report input.", file=sys.stderr)
        sys.exit(2)

    try:
        data = json.loads(raw_content)
    except (json.JSONDecodeError, Exception) as exc:
        if args.allow_failure:
            return {
                "results": [],
                "passed": 0,
                "failed": 0,
                "skipped": 0,
                "success": False,
                "raw_error": f"Error parsing JSON: {exc}",
            }
        print(f"Error parsing JSON: {exc}", file=sys.stderr)
        sys.exit(2)

    if isinstance(data, list):
        data = {"results": data}
    elif not isinstance(data, dict):
        if args.allow_failure:
            return {
                "results": [],
                "passed": 0,
                "failed": 0,
                "skipped": 0,
                "success": False,
                "raw_error": f"Root JSON is not an object or list ({type(data).__name__})",
            }
        return {
            "results": [],
            "passed": 0,
            "failed": 0,
            "skipped": 0,
            "success": False,
            "raw_error": f"Root JSON is not an object or list ({type(data).__name__})",
        }

    return data


def render_markdown(report):
    if not isinstance(report, dict):
        report = {}

    raw_error = report.get("raw_error")
    if raw_error:
        lines = [
            "## 🛡️ Vetto Kernel Containment & Red-Team Attack Matrix",
            "",
            "**Overall Verdict**: ⚠️ **WARNING (INPUT UNAVAILABLE)** | **Passed**: `0/8` | **Failed**: `0/8` | **Skipped**: `8/8`",
            f"> **Notice**: Red-team containment report could not be loaded: {sanitize_cell(raw_error)}.",
            "",
            "| ID | Attack Vector | Target & Description | Status | Isolation & Kernel Details |",
            "|:--:|:--------------|:---------------------|:------:|:---------------------------|",
            f"| - | `redteam_report` | Automated containment audit | ⚪ **SKIP** | {sanitize_cell(raw_error)} |",
            "",
            "> *Boundaries verified via Linux Landlock LSM (ABI v1–v6), Seccomp-BPF filters, and PID/Mount/Network namespaces.*",
            "> *Evaluated under strict-wins isolation policy. Non-Linux runners report `SKIP` for unsupported kernel interfaces.*",
            "",
        ]
        return "\n".join(lines), False

    raw_results = report.get("results")
    results = raw_results if isinstance(raw_results, list) else []

    passed = int(report.get("passed") or 0)
    failed = int(report.get("failed") or 0)
    skipped = int(report.get("skipped") or 0)
    success = bool(report.get("success", False)) and (failed == 0) and bool(results)
    total = len(results) if results else 8

    if success:
        verdict_badge = "🟢 **SECURE (FAIL-CLOSED)**"
        verdict_note = "All kernel containment boundaries verified; zero vector escapes detected."
    else:
        verdict_badge = "🔴 **CONTAINMENT FAILURE**"
        verdict_note = (
            f"**ALERT**: {failed} attack vector(s) breached sandbox containment!"
            if failed > 0
            else "**ALERT**: Sandbox containment verification was incomplete or failed."
        )

    lines = [
        "## 🛡️ Vetto Kernel Containment & Red-Team Attack Matrix",
        "",
        f"**Overall Verdict**: {verdict_badge} | **Passed**: `{passed}/{total}` | **Failed**: `{failed}/{total}` | **Skipped**: `{skipped}/{total}`",
        f"> {verdict_note}",
        "",
        "| ID | Attack Vector | Target & Description | Status | Isolation & Kernel Details |",
        "|:--:|:--------------|:---------------------|:------:|:---------------------------|",
    ]

    status_map = {
        "PASS": "✅ **PASS**",
        "FAIL": "❌ **FAIL**",
        "SKIP": "⚪ **SKIP**",
    }

    for item in results:
        if not isinstance(item, dict):
            continue
        v_id = sanitize_cell(item.get("id") if item.get("id") is not None else "-")
        name = sanitize_cell(item.get("name", "unknown"))
        desc = sanitize_cell(item.get("description", ""))
        status_val = item.get("status")
        status_raw = sanitize_cell("FAIL" if status_val is None else status_val).upper()
        status_md = status_map.get(status_raw, f"⚠️ {status_raw}")
        details = sanitize_cell(item.get("details", ""))

        lines.append(f"| {v_id} | `{name}` | {desc} | {status_md} | {details} |")

    lines.extend([
        "",
        "> *Boundaries verified via Linux Landlock LSM (ABI v1–v6), Seccomp-BPF filters, and PID/Mount/Network namespaces.*",
        "> *Evaluated under strict-wins isolation policy. Non-Linux runners report `SKIP` for unsupported kernel interfaces.*",
        "",
    ])

    return "\n".join(lines), success


def main():
    args = parse_args()
    report = load_report(args)
    markdown_content, success = render_markdown(report)

    output_path = args.output_file or os.environ.get("GITHUB_STEP_SUMMARY")

    if output_path:
        # Append to summary file if it exists, or create new
        try:
            with open(output_path, "a", encoding="utf-8") as fh:
                fh.write(markdown_content + "\n")
            print(f"Appended red-team attack matrix to '{output_path}'")
        except OSError as exc:
            print(f"Warning: Failed to write to '{output_path}': {exc}", file=sys.stderr)
            print(markdown_content)
    else:
        print(markdown_content)

    if not success and not args.allow_failure:
        failed_count = report.get("failed") or 1
        print(f"::error::Red-team containment verification failed ({failed_count} vector(s) failed)", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
