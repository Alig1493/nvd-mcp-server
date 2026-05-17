import pytest
from aiohttp import ClientConnectorDNSError

from nvd_mcp_server.handler import RequestHandler
from nvd_mcp_server.settings import Settings


@pytest.fixture
def mock_settings(
    mock_settings: Settings
) -> Settings:
    return Settings.model_validate(
        {
            **mock_settings.model_dump(),
            "total_timeout": 3
        }
    )


@pytest.mark.asyncio
async def test_successful_get_request(mock_settings: Settings):
    """Test successful GET request to httpbin.org"""
    async with RequestHandler(settings=mock_settings) as handler:
        response = await handler.get("https://httpbin.org/get")

        assert response.status == 200
        data = await response.json()
        assert "url" in data
        assert data["url"] == "https://httpbin.org/get"


@pytest.mark.asyncio
async def test_get_request_with_query_params(mock_settings: Settings):
    """Test GET request with query parameters"""
    query_params = {"param1": "value1", "param2": "value2"}

    async with RequestHandler(
        query_params=query_params, settings=mock_settings
    ) as handler:
        response = await handler.get("https://httpbin.org/get")

        assert response.status == 200
        data = await response.json()
        assert "args" in data
        assert data["args"]["param1"] == "value1"
        assert data["args"]["param2"] == "value2"


@pytest.mark.asyncio
async def test_get_request_with_headers(mock_settings: Settings):
    """Test GET request with custom headers"""
    headers = {"User-Agent": "TestAgent/1.0", "X-Custom-Header": "custom-value"}

    async with RequestHandler(headers=headers, settings=mock_settings) as handler:
        response = await handler.get("https://httpbin.org/get")

        assert response.status == 200
        data = await response.json()
        assert "headers" in data
        assert data["headers"]["User-Agent"] == "TestAgent/1.0"
        assert data["headers"]["X-Custom-Header"] == "custom-value"


@pytest.mark.asyncio
async def test_status_code_responses(mock_settings: Settings):
    """Test different HTTP status codes"""
    async with RequestHandler(settings=mock_settings) as handler:
        # Test 200 OK
        response = await handler.get("https://httpbin.org/status/200")
        assert response.status == 200

        # Test 404 Not Found
        response = await handler.get("https://httpbin.org/status/404")
        assert response.status == 404

        # Test 500 Internal Server Error
        response = await handler.get("https://httpbin.org/status/500")
        assert response.status == 500


@pytest.mark.asyncio
async def test_invalid_url_failure(mock_settings: Settings):
    """Test request to invalid URL that should fail"""
    async with RequestHandler(settings=mock_settings) as handler:
        with pytest.raises(ClientConnectorDNSError):
            await handler.get("https://this-domain-does-not-exist-12345.com")


@pytest.mark.asyncio
async def test_json_response_parsing(mock_settings: Settings):
    """Test JSON response parsing"""
    async with RequestHandler(settings=mock_settings) as handler:
        response = await handler.get("https://httpbin.org/json")

        assert response.status == 200
        data = await response.json()
        assert isinstance(data, dict)
        assert "slideshow" in data


@pytest.mark.asyncio
async def test_large_response(mock_settings: Settings):
    """Test handling of larger responses"""
    async with RequestHandler(settings=mock_settings) as handler:
        # Get a response with specified size
        response = await handler.get("https://httpbin.org/bytes/1024")

        assert response.status == 200
        content = await response.read()
        assert len(content) == 1024


@pytest.mark.asyncio
async def test_combined_params_and_headers(mock_settings: Settings):
    """Test request with both query parameters and headers"""
    query_params = {"test": "integration"}
    headers = {"X-Test": "integration-test"}

    async with RequestHandler(
        settings=mock_settings, query_params=query_params, headers=headers
    ) as handler:
        response = await handler.get("https://httpbin.org/get")

        assert response.status == 200
        data = await response.json()
        assert data["args"]["test"] == "integration"
        assert data["headers"]["X-Test"] == "integration-test"
