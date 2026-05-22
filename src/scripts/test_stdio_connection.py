#!/usr/bin/env python3
"""
End-to-end test script for the NVD MCP Server search_cves tool.

Exercises every CVERequest parameter with real values against the live NVD API.
Run from the project root:

    uv run src/scripts/test_stdio_connection.py
"""

import asyncio
import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastmcp.client.client import CallToolResult
from fastmcp.client.transports import ClientTransport
from mcp.types import TextContent

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from fastmcp import Client

from nvd_mcp_server.cli import mcp
from nvd_mcp_server.models.cve_history import EventName, NvdCveHistoryRequest
from nvd_mcp_server.models.cve_request import (
    CVERequest,
    CveTag,
    CVSSV2Severity,
    CVSSV3Severity,
    CVSSV4Severity,
    VersionType,
)


@dataclass
class TestCase:
    name: str
    request: CVERequest
    expect_results: bool = True  # False when the filter may legitimately match nothing


@dataclass
class HistoryTestCase:
    name: str
    request: NvdCveHistoryRequest
    expect_results: bool = True


TEST_CASES: list[TestCase] = [
    # ── Single CVE lookup ────────────────────────────────────────────────────
    TestCase(
        "CVE lookup – Log4Shell (CVE-2021-44228)",
        CVERequest(cve_id="CVE-2021-44228"),
    ),
    TestCase(
        "CVE lookup – EternalBlue (CVE-2017-0144)",
        CVERequest(cve_id="CVE-2017-0144"),
    ),
    TestCase(
        "CVE lookup – Heartbleed (CVE-2014-0160)",
        CVERequest(cve_id="CVE-2014-0160"),
    ),
    # ── Keyword search ───────────────────────────────────────────────────────
    TestCase(
        "Keyword search – 'buffer overflow'",
        CVERequest(keyword_search="buffer overflow", results_per_page=5),
    ),
    TestCase(
        "Keyword exact match – 'sql injection'",
        CVERequest(
            keyword_search="sql injection",
            keyword_exact_match=True,
            results_per_page=5,
        ),
    ),
    # ── CVSS severity filters ────────────────────────────────────────────────
    TestCase(
        "CVSSv3 severity – CRITICAL",
        CVERequest(cvss_v3_severity=CVSSV3Severity.CRITICAL, results_per_page=5),
    ),
    TestCase(
        "CVSSv3 severity – HIGH",
        CVERequest(cvss_v3_severity=CVSSV3Severity.HIGH, results_per_page=5),
    ),
    TestCase(
        "CVSSv2 severity – HIGH",
        CVERequest(cvss_v2_severity=CVSSV2Severity.HIGH, results_per_page=5),
    ),
    TestCase(
        "CVSSv2 severity – MEDIUM",
        CVERequest(cvss_v2_severity=CVSSV2Severity.MEDIUM, results_per_page=5),
    ),
    TestCase(
        "CVSSv4 severity – CRITICAL",
        CVERequest(cvss_v4_severity=CVSSV4Severity.CRITICAL, results_per_page=5),
        expect_results=False,  # v4 scoring is sparse; may return 0
    ),
    # ── CVSS vector string filters ───────────────────────────────────────────
    # NVD API takes the abbreviated vector form (no "CVSS:3.x/" prefix) for v3 metrics.
    # Our model validator accepts both; the API only accepts the abbreviated form.
    TestCase(
        "CVSSv3 metrics – high-severity network vector (abbreviated)",
        CVERequest(
            cvss_v3_metrics="AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            results_per_page=5,
        ),
    ),
    TestCase(
        "CVSSv2 metrics – max base score vector",
        CVERequest(
            cvss_v2_metrics="AV:N/AC:L/Au:N/C:C/I:C/A:C",
            results_per_page=5,
        ),
        # NVD stopped generating CVSSv2 data after 2022-07-13; only older CVEs match.
    ),
    # ── CWE ID filters ───────────────────────────────────────────────────────
    TestCase(
        "CWE-79 (Cross-site Scripting)",
        CVERequest(cwe_id="CWE-79", results_per_page=5),
    ),
    TestCase(
        "CWE-89 (SQL Injection)",
        CVERequest(cwe_id="CWE-89", results_per_page=5),
    ),
    TestCase(
        "CWE-119 (Buffer Overflow)",
        CVERequest(cwe_id="CWE-119", results_per_page=5),
    ),
    # ── Published date range ─────────────────────────────────────────────────
    TestCase(
        "Published Jan 2024 (31-day window)",
        CVERequest(
            pub_start_date="2024-01-01T00:00:00.000",
            pub_end_date="2024-02-01T00:00:00.000",
            results_per_page=5,
        ),
    ),
    TestCase(
        "Published Q1 2023 (89-day window)",
        CVERequest(
            pub_start_date="2023-01-01T00:00:00.000",
            pub_end_date="2023-03-31T00:00:00.000",
            results_per_page=5,
        ),
    ),
    # ── Last-modified date range ─────────────────────────────────────────────
    TestCase(
        "Last modified Jan 2025",
        CVERequest(
            last_mod_start_date="2025-01-01T00:00:00.000",
            last_mod_end_date="2025-02-01T00:00:00.000",
            results_per_page=5,
        ),
    ),
    # ── KEV date range ───────────────────────────────────────────────────────
    TestCase(
        "KEV additions Jan–Mar 2023",
        CVERequest(
            kev_start_date="2023-01-01T00:00:00.000",
            kev_end_date="2023-03-01T00:00:00.000",
            results_per_page=5,
        ),
    ),
    # ── Boolean flag filters ─────────────────────────────────────────────────
    TestCase(
        "hasKev flag – CVEs in CISA KEV catalog",
        CVERequest(has_kev=True, results_per_page=5),
    ),
    TestCase(
        "hasCertAlerts flag – CVEs with US-CERT Alerts",
        CVERequest(has_cert_alerts=True, results_per_page=5),
        expect_results=False,  # deprecated flag; NVD returns 0 results
    ),
    TestCase(
        "hasCertNotes flag – CVEs with CERT/CC Notes",
        CVERequest(has_cert_notes=True, results_per_page=5),
        expect_results=False,  # deprecated flag; NVD returns 0 results
    ),
    TestCase(
        "hasOval flag – CVEs with OVAL data",
        CVERequest(has_oval=True, results_per_page=5),
        expect_results=False,  # deprecated flag; NVD returns 0 results
    ),
    TestCase(
        "noRejected flag + keyword search",
        CVERequest(
            no_rejected=True,
            keyword_search="remote code execution",
            results_per_page=5,
        ),
    ),
    # ── CPE filters ──────────────────────────────────────────────────────────
    TestCase(
        "cpeName – Ubuntu 22.04",
        CVERequest(
            cpe_name="cpe:2.3:o:canonical:ubuntu_linux:22.04:*:*:*:*:*:*:*",
            results_per_page=5,
        ),
    ),
    TestCase(
        "cpeName + isVulnerable – OpenSSL 3.0.0",
        CVERequest(
            cpe_name="cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*",
            is_vulnerable=True,
            results_per_page=5,
        ),
    ),
    TestCase(
        "virtualMatchString – all Linux kernel CVEs",
        CVERequest(
            virtual_match_string="cpe:2.3:o:linux:linux_kernel",
            results_per_page=5,
        ),
    ),
    TestCase(
        "virtualMatchString + version range – Linux kernel 4.x",
        CVERequest(
            virtual_match_string="cpe:2.3:o:linux:linux_kernel",
            version_start="4.0",
            version_start_type=VersionType.INCLUDING,
            version_end="5.0",
            version_end_type=VersionType.EXCLUDING,
            results_per_page=5,
        ),
    ),
    # ── CVE tag ──────────────────────────────────────────────────────────────
    TestCase(
        "cveTag – disputed",
        CVERequest(cve_tag=CveTag.DISPUTED, results_per_page=5),
    ),
    TestCase(
        "cveTag – unsupported-when-assigned",
        CVERequest(cve_tag=CveTag.UNSUPPORTED_WHEN_ASSIGNED, results_per_page=5),
    ),
    # ── Pagination ───────────────────────────────────────────────────────────
    TestCase(
        "Pagination – page 3 of CVSSv3 CRITICAL results (startIndex=10)",
        CVERequest(
            cvss_v3_severity=CVSSV3Severity.CRITICAL,
            results_per_page=5,
            start_index=10,
        ),
    ),
]


HISTORY_TEST_CASES: list[HistoryTestCase] = [
    # ── Single CVE history ───────────────────────────────────────────────────
    HistoryTestCase(
        "History – Log4Shell (CVE-2021-44228)",
        NvdCveHistoryRequest(cve_id="CVE-2021-44228", results_per_page=5),
    ),
    # ── Event name filters ───────────────────────────────────────────────────
    HistoryTestCase(
        "History – Initial Analysis events",
        NvdCveHistoryRequest(event_name=EventName.INITIAL_ANALYSIS, results_per_page=5),
    ),
    # ── Date range ───────────────────────────────────────────────────────────
    HistoryTestCase(
        "History – changes in Jan 2024",
        NvdCveHistoryRequest(
            change_start_date="2024-01-01T00:00:00.000",
            end_date="2024-01-31T23:59:59.000",
            results_per_page=5,
        ),
    ),
]


async def run_test(
    client: Client[ClientTransport], tc: TestCase, sem: asyncio.Semaphore
) -> tuple[str, bool, str, float]:
    async with sem:
        return await _run_test(client, tc)


def _get_text_content(result: CallToolResult) -> str | None:
    match result.content[0]:
        case TextContent():
            return result.content[0].text
        case _:
            return None


def _get_error_content(result: CallToolResult) -> str:
    base_str = "Tool returned error"
    text_content = _get_text_content(result=result)
    if text_content:
        return f"{base_str}: {text_content}"
    return f"{base_str}."


async def _run_test(
    client: Client[ClientTransport], tc: TestCase
) -> tuple[str, bool, str, float]:
    t0 = time.monotonic()
    try:
        # by_alias=False ensures snake_case keys so FastMCP can reconstruct CVERequest
        result = await client.call_tool(
            "search_cves",
            {"request": tc.request.model_dump(by_alias=False, exclude_none=True)},
        )

        elapsed = time.monotonic() - t0

        if result.is_error:
            msg = _get_error_content(result)
            return tc.name, False, msg, elapsed

        if len(result.content) == 0:
            return tc.name, False, "No content returned", elapsed

        text_content = _get_text_content(result=result)
        if not text_content:
            return tc.name, False, "Invalid content returned", elapsed
        data = json.loads(text_content)
        total = data["total_results"]
        returned = len(data["vulnerabilities"])
        first_id = data["vulnerabilities"][0]["id"] if returned > 0 else "—"

        if tc.expect_results and total == 0:
            return tc.name, False, "Expected results but got 0", elapsed

        detail = f"{total:,} total · {returned} returned · first={first_id}"
        return tc.name, True, detail, elapsed

    except Exception as exc:
        return tc.name, False, f"{type(exc).__name__}: {exc}", time.monotonic() - t0


async def run_history_test(
    client: Client[ClientTransport], tc: HistoryTestCase, sem: asyncio.Semaphore
) -> tuple[str, bool, str, float]:
    async with sem:
        t0 = time.monotonic()
        try:
            result = await client.call_tool(
                "search_cve_history",
                {"request": tc.request.model_dump(by_alias=False, exclude_none=True)},
            )
            elapsed = time.monotonic() - t0

            if result.is_error:
                return tc.name, False, _get_error_content(result), elapsed

            text_content = _get_text_content(result)
            if not text_content:
                return tc.name, False, "Invalid content returned", elapsed

            data = json.loads(text_content)
            total = data["total_results"]
            returned = len(data["changes"])
            first_id = data["changes"][0]["cve_id"] if returned > 0 else "—"

            if tc.expect_results and total == 0:
                return tc.name, False, "Expected results but got 0", elapsed

            detail = f"{total:,} total · {returned} returned · first={first_id}"
            return tc.name, True, detail, elapsed

        except Exception as exc:
            return tc.name, False, f"{type(exc).__name__}: {exc}", time.monotonic() - t0


async def _run_suite(
    label: str,
    coros: list[Any],
    total: int,
) -> tuple[int, int, list[str]]:
    passed = failed = 0
    failed_names: list[str] = []
    completed = 0

    print(f"\n{label}")
    print(f"{'─' * 62}")

    for coro in asyncio.as_completed(coros):
        name, ok, detail, elapsed = await coro
        completed += 1
        status = "PASS" if ok else "FAIL"
        print(f"[{completed:02}/{total}] {status}  {name}  ({elapsed:.2f}s)")
        if not ok:
            print(f"         ERROR: {detail}")
        if ok:
            passed += 1
        else:
            failed += 1
            failed_names.append(name)

    return passed, failed, failed_names


async def main() -> None:
    sem = asyncio.Semaphore(10)

    print("NVD MCP Server — end-to-end test run")
    print(f"{'=' * 62}")

    async with Client(mcp) as client:
        cve_coros = [run_test(client, tc, sem) for tc in TEST_CASES]
        history_coros = [run_history_test(client, tc, sem) for tc in HISTORY_TEST_CASES]

        p1, f1, fn1 = await _run_suite(
            f"search_cves  ({len(TEST_CASES)} tests)", cve_coros, len(TEST_CASES)
        )
        p2, f2, fn2 = await _run_suite(
            f"search_cve_history  ({len(HISTORY_TEST_CASES)} tests)",
            history_coros,
            len(HISTORY_TEST_CASES),
        )

    total = len(TEST_CASES) + len(HISTORY_TEST_CASES)
    passed = p1 + p2
    failed = f1 + f2
    failed_names = fn1 + fn2

    print(f"\n{'=' * 62}")
    print(f"Results: {passed} passed, {failed} failed out of {total} tests")

    if failed_names:
        print("\nFailed tests:")
        for name in failed_names:
            print(f"  • {name}")
        sys.exit(1)
    else:
        print("All tests passed.")


if __name__ == "__main__":
    asyncio.run(main())
