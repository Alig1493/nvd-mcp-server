#!/usr/bin/env python3
"""
Smoke test for the NVD MCP Server HTTP transport.

Connects to a running HTTP server, verifies both tools are available,
and runs a basic call against each.

Usage:
    uv run src/scripts/test_http_connection.py
    uv run src/scripts/test_http_connection.py --url http://localhost:9090/mcp
"""

import argparse
import asyncio
import json
import sys

from fastmcp import Client

REQUIRED_TOOLS = {"search_cves", "search_cve_history"}


async def main(url: str) -> None:
    print(f"Connecting to HTTP server at {url} ...")
    failed = False

    try:
        async with Client(url) as client:
            tools = await client.list_tools()
            tool_names = {t.name for t in tools}
            missing = REQUIRED_TOOLS - tool_names

            if missing:
                print(f"FAIL  missing tools: {missing}")
                sys.exit(1)

            print(f"OK    tools available: {sorted(tool_names)}")

            # ── search_cves ──────────────────────────────────────────────────
            result = await client.call_tool(
                "search_cves",
                {"request": {"cve_id": "CVE-2021-44228"}},
            )

            if result.is_error:
                print(f"FAIL  search_cves error: {result.content[0].text}")
                failed = True
            else:
                data = json.loads(result.content[0].text)
                vuln = data["vulnerabilities"][0]
                assert vuln["id"] == "CVE-2021-44228", f"Unexpected id: {vuln['id']}"
                assert data["total_results"] == 1
                assert vuln["cvss"]["score"] == 10.0
                score, severity = vuln["cvss"]["score"], vuln["cvss"]["severity"]
                print(f"OK    search_cves — CVE-2021-44228 score {score} {severity}")

            # ── search_cve_history ───────────────────────────────────────────
            result = await client.call_tool(
                "search_cve_history",
                {"request": {"cve_id": "CVE-2021-44228", "results_per_page": 5}},
            )

            if result.is_error:
                print(f"FAIL  search_cve_history error: {result.content[0].text}")
                failed = True
            else:
                data = json.loads(result.content[0].text)
                assert data["total_results"] > 0, "Expected history results"
                assert len(data["changes"]) > 0
                first_event = data["changes"][0]["event"]
                print(
                    f"OK    search_cve_history — {data['total_results']} changes"
                    f" · first event: {first_event}"
                )

    except Exception as exc:
        print(f"FAIL  {type(exc).__name__}: {exc}")
        sys.exit(1)

    if failed:
        sys.exit(1)

    print("HTTP connection test passed.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--url",
        default="http://localhost:8000/mcp",
        help="HTTP server URL (default: http://localhost:8000/mcp)",
    )
    args = parser.parse_args()
    asyncio.run(main(args.url))
