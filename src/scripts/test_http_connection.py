#!/usr/bin/env python3
"""
Smoke test for the NVD MCP Server HTTP transport.

Connects to a running HTTP server, calls search_cves with a known CVE,
and verifies the response is valid.

Usage:
    uv run scripts/test_http_connection.py
    uv run scripts/test_http_connection.py --url http://localhost:9090/http/
"""

import argparse
import asyncio
import json
import sys

from fastmcp import Client


async def main(url: str) -> None:
    print(f"Connecting to HTTP server at {url} ...")

    try:
        async with Client(url) as client:
            tools = await client.list_tools()
            tool_names = [t.name for t in tools]

            if "search_cves" not in tool_names:
                print(f"FAIL  search_cves not found in tools: {tool_names}")
                sys.exit(1)

            print(f"OK    tools available: {tool_names}")

            result = await client.call_tool(
                "search_cves",
                {"request": {"cve_id": "CVE-2021-44228"}},
            )

            if result.is_error:
                print(f"FAIL  tool returned error: {result.content[0].text}")
                sys.exit(1)

            data = json.loads(result.content[0].text)
            vuln = data["vulnerabilities"][0]

            assert vuln["id"] == "CVE-2021-44228", f"Unexpected id: {vuln['id']}"
            assert data["total_results"] == 1
            assert vuln["cvss"]["score"] == 10.0

            score = vuln["cvss"]["score"]
            severity = vuln["cvss"]["severity"]
            print(f"OK    CVE-2021-44228 returned — score {score} {severity}")
            print("HTTP connection test passed.")

    except Exception as exc:
        print(f"FAIL  {type(exc).__name__}: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--url",
        default="http://localhost:8000/mcp/",
        help="HTTP server URL (default: http://localhost:8000/mcp/)",
    )
    args = parser.parse_args()
    asyncio.run(main(args.url))
