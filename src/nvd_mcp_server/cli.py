import argparse

from fastmcp import FastMCP
from fastmcp.tools import FunctionTool

from .server import search_cves
from .transport import http, stdio

mcp: FastMCP = FastMCP("NVD MCP Server")
mcp.add_tool(FunctionTool.from_function(search_cves))


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

    if args.transport == "http":
        print(f"Starting Streamable HTTP MCP Server on http://{args.host}:{args.port}")
        http.run(mcp, host=args.host, port=args.port)
    else:
        stdio.run(mcp)
