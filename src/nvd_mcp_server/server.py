from fastmcp import FastMCP
from pydantic import ValidationError

from .handler import RequestHandler
from .models.core import NvdVulnerabilityData
from .models.cve_request import CVERequest
from .models.cve_summary import CveSearchResult, CveSummary
from .settings import Settings
from .utils import RequestFailedError, retry

mcp: FastMCP = FastMCP("NVD MCP Server")
_settings = Settings()


@mcp.tool()
async def search_cves(request: CVERequest) -> str:
    """
    Search the National Vulnerability Database (NVD) for CVEs
    matching the given filters.

    Returns a JSON string with pagination info and a list of matching CVEs,
    each containing: id, published date, status, English description, CVSS score,
    CWE weaknesses, top 5 references, and CISA KEV data if applicable.

    All filter parameters are optional — omit any you do not need. Mutually exclusive
    groups (enforced by validation):
      - cvssV2Metrics / cvssV3Metrics / cvssV4Metrics: use at most one
      - cvssV2Severity / cvssV3Severity / cvssV4Severity: use at most one
      - isVulnerable requires cpeName and excludes virtualMatchString
      - version range params (versionStart/End) require virtualMatchString
    """
    query_params: dict[str, str] = {}
    for key, value in request.model_dump(by_alias=True, exclude_none=True).items():
        if isinstance(value, bool):
            if value:
                query_params[key] = ""
        else:
            query_params[key] = str(value)

    query_params["resultsPerPage"] = "10"

    headers = {"apiKey": _settings.nvd_api_key}
    url = str(_settings.nvd_cve_url)

    try:
        async with retry(_settings.retry_max_duration) as retry_func:
            async with RequestHandler(
                _settings, query_params=query_params, headers=headers
            ) as handler:
                response = await retry_func(handler.get, url)

                if response.status != 200:
                    error_body = await response.text()
                    raise RuntimeError(
                        f"NVD API returned HTTP {response.status}: {error_body}"
                    )

                data = await response.json()
    except RequestFailedError:
        raise RuntimeError(
            f"NVD API request timed out after {_settings.retry_max_duration}s. "
            "Try narrowing your search filters."
        )

    try:
        raw = NvdVulnerabilityData.model_validate(data)
    except ValidationError as exc:
        raise RuntimeError(f"NVD API response failed validation: {exc}") from exc

    next_index = raw.start_index + raw.results_per_page
    has_more = next_index < raw.total_results
    result = CveSearchResult(
        total_results=raw.total_results,
        results_per_page=raw.results_per_page,
        start_index=raw.start_index,
        vulnerabilities=[
            CveSummary.from_cve_item(item.cve) for item in raw.vulnerabilities
        ],
        next_start_index=next_index if has_more else None,
        pagination_hint=(
            f"{raw.total_results - next_index} more results available. "
            f"Call again with start_index={next_index} to get the next page."
        ) if has_more else None,
    )
    return result.model_dump_json()


def start_mcp_server() -> None:
    mcp.run()


if __name__ == "__main__":
    start_mcp_server()
