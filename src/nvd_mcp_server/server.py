from typing import Any

import aiohttp
from pydantic import ValidationError

from nvd_mcp_server.models.cve_history import (
    NvdCveHistoryRequest,
    NvdCveHistoryResponse,
)

from .handler import RequestHandler
from .models.core import NvdVulnerabilityData
from .models.cve_request import CVERequest
from .models.cve_summary import CveHistorySearchResult, CveSearchResult
from .settings import Settings
from .utils import RequestFailedError, retry

_settings = Settings()


async def _fetch_data(url: str, query_params: dict[str, str]) -> Any:
    async def _fetch() -> dict[str, Any]:
        async with RequestHandler(
            _settings,
            query_params=query_params,
            headers={"apiKey": _settings.nvd_api_key},
        ) as handler:
            response = await handler.get(url)
            if response.status in (429, 503):
                raise aiohttp.ClientResponseError(
                    request_info=response.request_info,
                    history=(),
                    status=response.status,
                )
            if response.status != 200:
                error_body = await response.text()
                raise RuntimeError(
                    f"NVD API returned HTTP {response.status}: {error_body}"
                )
            return await response.json()  # type: ignore[no-any-return]

    try:
        async with retry(_settings.retry_max_duration) as retry_func:
            return await retry_func(_fetch)
    except RequestFailedError:
        raise RuntimeError(
            f"NVD API request timed out after {_settings.retry_max_duration}s. "
            "Try narrowing your search filters."
        )


async def search_cves(request: CVERequest) -> str:
    """
    Search the National Vulnerability Database (NVD) for CVEs
    matching the given filters.

    Returns a JSON string with pagination info and a list of matching CVEs,
    each containing: id, published date, status, English description, CVSS score,
    CWE weaknesses, top 5 references, and CISA KEV data if applicable.

    When to use this tool:
      - You want to find CVEs that match criteria such as keyword, CPE, severity,
        publication date, or CVSS score.
      - You need the current state of a CVE record (description, score, status).

    When NOT to use this tool:
      - You want to see how a CVE record changed over time (e.g. score updates,
        status transitions, new references added) — use search_cve_history instead.
      - You want to audit what happened to a specific CVE on a given date — use
        search_cve_history with cve_id and a date range instead.

    Performance guidance:
      - Keep results_per_page at 5–10 to avoid slow responses.
      - When filtering by date, limit the window to 30 days or less.
      - Broad severity or keyword queries without a date range can be slow;
        add pub_start_date / pub_end_date or last_mod_start_date / last_mod_end_date
        to speed them up.

    Mutually exclusive groups (enforced by validation):
      - cvssV2Metrics / cvssV3Metrics / cvssV4Metrics: use at most one
      - cvssV2Severity / cvssV3Severity / cvssV4Severity: use at most one
      - isVulnerable requires cpeName and excludes virtualMatchString
      - version range params (versionStart/End) require virtualMatchString
    """
    query_params = request.to_query_params()
    data = await _fetch_data(_settings.nvd_cve_url, query_params)

    try:
        raw = NvdVulnerabilityData.model_validate(data)
    except ValidationError as exc:
        raise RuntimeError(f"NVD API response failed validation: {exc}") from exc

    return CveSearchResult.from_response(raw).model_dump_json()


async def search_cve_history(request: NvdCveHistoryRequest) -> str:
    """
    Search the NVD CVE Change History API for changes made to CVE records.

    Returns a JSON string with pagination info and a list of change events,
    each containing the CVE ID, event type, source, timestamp, and change details.

    When to use this tool:
      - You want to see how a CVE record changed over time (e.g. score updates,
        status transitions, analyst comments, new references added).
      - You want to audit activity on a specific CVE — use cve_id for the fastest query.
      - You want to find all CVEs that were modified within a date range.

    When NOT to use this tool:
      - You want to find CVEs matching criteria like keyword, CPE, or severity —
        use search_cves instead.
      - You need the current description, score, or status of a CVE — use
        search_cves instead, which returns the current NVD record.

    Performance guidance — the history API is significantly slower than the CVE API:
      - Always set results_per_page to 2–5.
      - Narrow the date window to 7 days or less when using change_start_date /
        change_end_date. The maximum allowable range is 120 consecutive days.
      - Avoid querying by event_name alone without a date range — it scans the
        entire history database and will time out. Combine event_name with a
        date range.
      - For a specific CVE use cve_id; that is the fastest query.
    """
    data = await _fetch_data(
        _settings.nvd_cve_history_url,
        request.model_dump(by_alias=True, exclude_none=True, mode="json"),
    )

    try:
        raw = NvdCveHistoryResponse.model_validate(data)
    except ValidationError as exc:
        raise RuntimeError(
            f"NVD API history response failed validation: {exc}"
        ) from exc

    return CveHistorySearchResult.from_response(raw).model_dump_json()
