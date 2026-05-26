import logging
from typing import Any, Dict, Optional

import aiohttp
from pydantic import SecretStr

from nvd_mcp_server.settings import Settings

logger = logging.getLogger(__name__)


class RequestHandler:
    def __init__(
        self,
        settings: Settings,
        query_params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.session: Optional[aiohttp.ClientSession] = None
        self.query_params = query_params or {}
        self.headers: Dict[str, Any] = headers or {}
        self.timeout = aiohttp.ClientTimeout(total=settings.total_timeout)

    async def __aenter__(self) -> "RequestHandler":
        logger.info("Initializing HTTP session")
        self.session = aiohttp.ClientSession(timeout=self.timeout)
        logger.debug("HTTP session created successfully")
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self.session:
            logger.info("Closing HTTP session")
            await self.session.close()
            logger.debug("HTTP session closed successfully")

    async def get(self, url: str) -> aiohttp.ClientResponse:
        if not self.session:
            raise RuntimeError(
                "RequestHandler not initialized. Use as async context manager."
            )

        logger.info(f"Making GET request to: {url}")
        logger.debug(f"Query params: {self.query_params}")
        logger.debug(f"Headers: {self.headers}")

        resolved_headers = {
            k: v.get_secret_value() if isinstance(v, SecretStr) else v
            for k, v in self.headers.items()
        }

        try:
            return await self.session.get(
                url,
                params=self.query_params,
                headers=resolved_headers,
                allow_redirects=False,
            )
        except aiohttp.ClientError as e:
            logger.error(f"Request encountered an errror: {str(e)}")
            raise e
