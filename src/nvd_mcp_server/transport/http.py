from fastmcp import FastMCP


def run(mcp: FastMCP, host: str, port: int) -> None:
    mcp.run(transport="http", host=host, port=port)
