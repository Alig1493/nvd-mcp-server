import asyncio
import logging
from contextlib import asynccontextmanager
from time import time
from typing import AsyncGenerator, Callable

import aiohttp

logger = logging.getLogger(__name__)


class RequestFailedError(Exception):
    """Raised when a request fails after all retries are exhausted."""
    pass


@asynccontextmanager
async def retry(
    max_duration: int, base_delay: int = 1
) -> AsyncGenerator[Callable, None]:
    """
    Context manager that provides a retry function with exponential backoff
    for up to max_duration seconds defined as int.
    """
    async def retry_func(func: Callable, *args, **kwargs):
        start_time = time()
        attempt = 1

        while True:
            try:
                return await func(*args, **kwargs)
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                elapsed_time = time() - start_time

                if elapsed_time > max_duration:
                    error_msg = (
                        f"Request failed after {elapsed_time:.1f} seconds of retries "
                        f"with error: {type(e).__name__}."
                    )
                    logger.error(error_msg)
                    raise RequestFailedError(error_msg)

                delay = base_delay * (2**attempt)
                if elapsed_time + delay > max_duration:
                    remaining_time = max_duration - elapsed_time
                    if remaining_time > 0:
                        delay = remaining_time
                    else:
                        logger.error(
                            f"Request failed after {max_duration} seconds of retries"
                            f"with error: {str(e)}"
                        )
                        raise e

                attempt += 1
                logger.warning(
                    f"Request failed (attempt {attempt}), "
                    f"retrying in {delay:.2f} seconds: {str(e)}"
                )
                await asyncio.sleep(delay)

    yield retry_func
