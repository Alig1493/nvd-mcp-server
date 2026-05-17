from fastmcp import FastMCP


def run(mcp: FastMCP, host: str, port: int) -> None:
    mcp.run(transport="sse", host=host, port=port)
