import argparse

from fastmcp import FastMCP
from fastmcp.tools import FunctionTool
from fastmcp.utilities.logging import get_logger

from .server import search_cve_history, search_cves

mcp: FastMCP = FastMCP("NVD MCP Server")
mcp.add_tool(FunctionTool.from_function(search_cves))
mcp.add_tool(FunctionTool.from_function(search_cve_history))


logger = get_logger(__name__)


def main() -> None:
    parser = argparse.ArgumentParser(description="NVD MCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "http"],
        default="stdio",
        help="Transport protocol (default: stdio)",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind to — HTTP only (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to listen on — HTTP only (default: 8000)",
    )
    args = parser.parse_args()

    try:
        if args.transport == "http":
            mcp.run(transport=args.transport, host=args.host, port=args.port)
        else:
            mcp.run(transport=args.transport)
    except KeyboardInterrupt:
        logger.info("Exiting.")
        exit(0)
    except Exception as exc:
        logger.warning(f"Exiting due to {exc}")
        exit(1)
