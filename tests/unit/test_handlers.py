import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from nvd_mcp_server.handler import RequestHandler
from nvd_mcp_server.settings import Settings
from nvd_mcp_server.utils import RequestFailedError, retry


@pytest.mark.asyncio
async def test_successful_request(mock_settings):
    """Test that a successful HTTP request returns the expected response."""
    mock_response = AsyncMock()
    mock_response.status = 200
    mock_response.json.return_value = {"success": True}

    with patch("aiohttp.ClientSession") as mock_session_class:
        mock_session = AsyncMock()
        mock_session.get.return_value = mock_response
        mock_session_class.return_value = mock_session

        async with RequestHandler(mock_settings) as handler:
            response = await handler.get("https://example.com")

            assert response == mock_response
            mock_session.get.assert_called_once_with(
                "https://example.com", params={}, headers={}, allow_redirects=False
            )


@pytest.mark.asyncio
async def test_request_with_params_and_headers(mock_settings):
    """Test that requests with query parameters and headers are passed correctly."""
    mock_response = AsyncMock()
    mock_response.status = 200

    query_params = {"page": 1, "limit": 10}
    headers = {"Authorization": "Bearer token"}

    with patch("aiohttp.ClientSession") as mock_session_class:
        mock_session = AsyncMock()
        mock_session.get.return_value = mock_response
        mock_session_class.return_value = mock_session

        async with RequestHandler(
            mock_settings, query_params=query_params, headers=headers
        ) as handler:
            response = await handler.get("https://example.com")

            assert response == mock_response
            mock_session.get.assert_called_once_with(
                "https://example.com",
                params=query_params,
                headers=headers,
                allow_redirects=False
            )


@pytest.mark.asyncio
async def test_unsuccessful_request_with_retries(mock_settings: Settings):
    """Test that failed requests are retried and eventually succeed."""
    mock_response = AsyncMock()
    mock_response.status = 200

    with patch("aiohttp.ClientSession") as mock_session_class:
        mock_session = AsyncMock()
        # Fail once, then succeed
        mock_session.get.side_effect = [
            aiohttp.ClientConnectorError(
                connection_key=MagicMock(), os_error=MagicMock()
            ),
            mock_response,
        ]
        mock_session_class.return_value = mock_session

        with patch("asyncio.sleep") as mock_sleep:
            async with RequestHandler(mock_settings) as handler:
                async with retry(
                    max_duration=mock_settings.retry_max_duration
                ) as retry_func:
                    response = await retry_func(handler.get, "https://example.com")

                    assert response == mock_response
                    assert mock_session.get.call_count == 2
                    assert mock_sleep.call_count == 1


@pytest.mark.asyncio
async def test_retry_mechanism_exponential_backoff(mock_settings: Settings):
    """Test that retry mechanism uses exponential backoff delays."""
    with patch("aiohttp.ClientSession") as mock_session_class:
        mock_session = AsyncMock()
        mock_session.get.side_effect = [
            aiohttp.ClientConnectorError(
                connection_key=MagicMock(), os_error=MagicMock()
            ),
            AsyncMock(),  # Success on second try
        ]
        mock_session_class.return_value = mock_session

        with patch("asyncio.sleep") as mock_sleep:
            async with RequestHandler(mock_settings) as handler:
                async with retry(
                    max_duration=mock_settings.retry_max_duration
                ) as retry_func:
                    await retry_func(handler.get, "https://example.com")

                    # Check exponential backoff: should sleep for approximately 1s
                    assert mock_sleep.call_count == 1
                    sleep_duration = mock_sleep.call_args[0][0]
                    assert 0.9 <= sleep_duration <= 1.0


@pytest.mark.asyncio
async def test_failed_retry_mechanism_raises_error(mock_settings: Settings):
    """Test that exhausted retries raise RequestFailedError."""
    with patch("aiohttp.ClientSession") as mock_session_class:
        mock_session = AsyncMock()
        mock_session.get.side_effect = aiohttp.ClientConnectorError(
            connection_key=MagicMock(), os_error=MagicMock()
        )
        mock_session_class.return_value = mock_session

        with patch("time.time") as mock_time:
            # Mock time to simulate max_duration exceeded
            mock_time.side_effect = [0, 2]  # Start at 0, then 2 seconds later

            async with RequestHandler(mock_settings) as handler:
                with pytest.raises(RequestFailedError) as exc_info:
                    async with retry(
                    max_duration=mock_settings.retry_max_duration
                ) as retry_func:
                        await retry_func(handler.get, "https://example.com")

                assert "Request failed after" in str(exc_info.value)
                assert "seconds of retries" in str(exc_info.value)


@pytest.mark.asyncio
async def test_timeout_error_triggers_retry(mock_settings: Settings):
    """Test that timeout errors trigger retry mechanism."""
    mock_response = AsyncMock()
    mock_response.status = 200

    with patch("aiohttp.ClientSession") as mock_session_class:
        mock_session = AsyncMock()
        mock_session.get.side_effect = [asyncio.TimeoutError(), mock_response]
        mock_session_class.return_value = mock_session

        with patch("asyncio.sleep") as mock_sleep:
            async with RequestHandler(mock_settings) as handler:
                async with retry(
                    max_duration=mock_settings.retry_max_duration
                ) as retry_func:
                    response = await retry_func(handler.get, "https://example.com")

                    assert response == mock_response
                    assert mock_session.get.call_count == 2
                    assert mock_sleep.call_count == 1
                    sleep_duration = mock_sleep.call_args[0][0]
                    assert 0.9 <= sleep_duration <= 1.0


@pytest.mark.asyncio
@patch(
    "nvd_mcp_server.utils.time",
    side_effect=[1, 2]
)
async def test_timeout_error_with_delay_triggers_error(
    start_time_patch, mock_settings: Settings
):
    """Test that timeout errors trigger retry mechanism."""
    mock_response = AsyncMock()
    mock_response.status = 200

    with patch("aiohttp.ClientSession") as mock_session_class:
        mock_session = AsyncMock()
        mock_session.get.side_effect = [ValueError()]
        mock_session_class.return_value = mock_session

        with patch("asyncio.sleep") as mock_sleep:
            async with RequestHandler(mock_settings) as handler:
                async with retry(
                    max_duration=mock_settings.retry_max_duration
                ) as retry_func:
                    with pytest.raises(ValueError):
                        await retry_func(handler.get, "https://example.com")

                    assert mock_session.get.call_count == 1
                    assert mock_sleep.call_count == 0


@pytest.mark.asyncio
async def test_runtime_error_when_not_initialized(mock_settings: Settings):
    """Test that using RequestHandler without initialization raises RuntimeError."""
    handler = RequestHandler(mock_settings)

    with pytest.raises(RuntimeError) as exc_info:
        await handler.get("https://example.com")

    assert "RequestHandler not initialized" in str(exc_info.value)


@pytest.mark.asyncio
async def test_custom_timeout():
    """Test that custom timeout values are passed to aiohttp ClientSession."""
    with patch("aiohttp.ClientSession") as mock_session_class:
        mock_session = AsyncMock()
        mock_session_class.return_value = mock_session

        timeout_val = 5.0
        custom_settings = Settings(
            retry_max_duration=30,
            total_timeout=timeout_val,
            nvd_api_key="test_key",
            nvd_cve_url="https://example.com/cve",
            nvd_cve_history_url="https://example.com/history"
        )
        async with RequestHandler(custom_settings):
            # Verify ClientSession was created with correct timeout
            expected_timeout = aiohttp.ClientTimeout(total=timeout_val)
            mock_session_class.assert_called_once_with(timeout=expected_timeout)


