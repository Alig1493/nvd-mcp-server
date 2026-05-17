from dotenv import dotenv_values
import pytest

from nvd_mcp_server.models.core import NvdVulnerabilityData
from nvd_mcp_server.settings import Settings
from nvd_mcp_server.handler import RequestHandler


@pytest.fixture
def mock_settings() -> Settings:
    return Settings.model_validate(
        {
            "retry_max_duration": 0,
            "total_timeout": 5,
            **dotenv_values(".env")
        }
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cve_id",
    [
        "CVE-2002-0392",  # 2.0
        "CVE-2013-1937",  # 3.0
        "CVE-2025-50181",  # 3.1
        "CVE-2025-27516"  # 4.0
    ]
)
async def test_schema(
    mock_settings: Settings,
    cve_id: str,
) -> None:
    # make a request using the request handler
    async with RequestHandler(
        query_params={
            "cveId": cve_id
        },
        settings=mock_settings,
        headers={
            "Content-Type": "application/json",
            "apiKey": mock_settings.nvd_api_key
        }
    ) as handler:
        response = await handler.get(str(mock_settings.nvd_cve_url))
        assert response.status == 200
        result = await response.json()
        NvdVulnerabilityData.model_validate(
            result
        )
