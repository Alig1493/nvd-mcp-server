import argparse

from fastmcp import FastMCP

from .transport import sse, stdio

mcp: FastMCP = FastMCP("NVD MCP Server")


def main() -> None:
    parser = argparse.ArgumentParser(description="NVD MCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse"],
        default="stdio",
        help="Transport protocol (default: stdio)",
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host to bind to — SSE only (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to listen on — SSE only (default: 8000)",
    )
    args = parser.parse_args()

    if args.transport == "sse":
        sse.run(mcp, host=args.host, port=args.port)
    else:
        stdio.run(mcp)
