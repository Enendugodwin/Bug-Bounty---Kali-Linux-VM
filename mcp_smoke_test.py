"""Smoke test for the kali-pentest-mcp FastMCP server.

Connects over stdio like a real MCP client, lists tools, and calls
only SAFE tools (no network scanning).
"""
import asyncio
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

PROJECT = Path(__file__).resolve().parent
PY = str(PROJECT / ".venv" / "bin" / "python")


async def main() -> int:
    print(f"[*] python: {PY}")
    print(f"[*] project: {PROJECT}")

    params = StdioServerParameters(
        command=PY,
        args=["-m", "src.server"],
        cwd=str(PROJECT),
        env=None,
    )

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            print(f"[+] Connected. Server: {init.serverInfo.name} "
                  f"v{init.serverInfo.version}")

            tools = await session.list_tools()
            names = [t.name for t in tools.tools]
            print(f"[+] Tools exposed ({len(names)}):")
            for n in names:
                print(f"      - {n}")

            print("\n[>] call planner(goal='smoke test')")
            r = await session.call_tool("planner", {"goal": "smoke test"})
            _show(r)

            print("\n[>] call generate_findings_report()")
            r = await session.call_tool("generate_findings_report", {})
            _show(r)

            print("\n[>] call query_past_scans(query='open port 8080')")
            r = await session.call_tool(
                "query_past_scans", {"query": "open port 8080"}
            )
            _show(r)

    print("\n[+] SMOKE TEST PASSED")
    return 0


def _show(result) -> None:
    if getattr(result, "isError", False):
        print("[!] tool returned an error")
    for block in result.content:
        text = getattr(block, "text", None)
        if text is not None:
            for line in text.splitlines()[:12]:
                print(f"      | {line}")


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except Exception as exc:  # noqa: BLE001
        print(f"[!] SMOKE TEST FAILED: {type(exc).__name__}: {exc}")
        sys.exit(1)
