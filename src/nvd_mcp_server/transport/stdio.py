from fastmcp import FastMCP


def run(mcp: FastMCP) -> None:
    mcp.run(transport="stdio")
