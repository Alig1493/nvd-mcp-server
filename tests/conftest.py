from typing import Any, Mapping

import pytest

from nvd_mcp_server.settings import Settings


@pytest.fixture
def mock_settings() -> Settings:
    """Create a mock Settings object for testing."""
    return Settings.model_validate({
        "retry_max_duration": 1,
        "total_timeout": 1,
        "nvd_api_key": "test_key",
        "nvd_cve_url": "https://example.com/cve",
        "nvd_cve_history_url": "https://example.com/history",
    })
