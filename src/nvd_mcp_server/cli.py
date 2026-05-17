import argparse

from .server import mcp
from .transport import http, stdio


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
        default="0.0.0.0",
        help="Host to bind to — HTTP only (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to listen on — HTTP only (default: 8000)",
    )
    args = parser.parse_args()

    if args.transport == "http":
        print(f"Starting Streamable HTTP MCP Server on http://{args.host}:{args.port}")
        http.run(mcp, host=args.host, port=args.port)
    else:
        stdio.run(mcp)
