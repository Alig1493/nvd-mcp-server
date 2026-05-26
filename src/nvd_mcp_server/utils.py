import asyncio
import functools
import logging
from contextlib import asynccontextmanager
from time import time
from typing import Any, AsyncGenerator, Callable, Coroutine, TypeVar

import aiohttp

logger = logging.getLogger(__name__)

_T = TypeVar("_T")


class RequestFailedError(Exception):
    """Raised when a request fails after all retries are exhausted."""

    pass


def guard_tool_errors(
    func: Callable[..., Coroutine[Any, Any, _T]],
) -> Callable[..., Coroutine[Any, Any, _T]]:
    @functools.wraps(func)
    async def wrapper(*args: Any, **kwargs: Any) -> _T:
        try:
            return await func(*args, **kwargs)
        except RuntimeError:
            raise
        except Exception:
            logger.exception("Unexpected error in %s", func.__name__)
            raise RuntimeError("An unexpected error occurred. Check server logs.")

    return wrapper


@asynccontextmanager
async def retry(
    max_duration: int, base_delay: int = 1
) -> AsyncGenerator[Callable[..., Any], None]:
    """
    Context manager that provides a retry function with exponential backoff
    for up to max_duration seconds defined as int.
    """

    async def retry_func(func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
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
