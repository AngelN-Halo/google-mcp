"""Explicit live smoke test for a running Google Directory MCP endpoint."""

from __future__ import annotations

import asyncio
import json
import os
import sys

from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport


async def main() -> int:
    endpoint = sys.argv[1] if len(sys.argv) > 1 else os.getenv(
        "GOOGLE_MCP_ENDPOINT", "http://127.0.0.1:8000/mcp"
    )
    existing = os.getenv("GOOGLE_TEST_USER", "").strip()
    missing = os.getenv("GOOGLE_TEST_MISSING_USER", "").strip()
    if not existing:
        print("GOOGLE_TEST_USER is required", file=sys.stderr)
        return 2

    output = {"connected": False, "existing_user_state": None, "missing_user_state": None}
    gateway_secret = os.getenv("GOOGLE_TEST_GATEWAY_SECRET", "").strip()
    headers = {}
    if gateway_secret:
        headers = {"Authorization": f"Bearer {gateway_secret}"}
    transport = StreamableHttpTransport(endpoint, headers=headers)
    async with Client(transport) as client:
        tools = await client.list_tools()
        names = {tool.name for tool in tools}
        expected = {
            "google_user_status",
            "google_user_search",
            "google_user_aliases",
            "google_user_summary",
            "google_user_groups",
        }
        if names != expected:
            raise RuntimeError("The live server does not expose exactly the configured tool set")
        output["connected"] = True
        existing_result = await client.call_tool("google_user_status", {"email": existing})
        existing_data = existing_result.data
        if not isinstance(existing_data, dict) or existing_data.get("state") != "ACTIVE":
            raise RuntimeError("GOOGLE_TEST_USER did not return ACTIVE")
        output["existing_user_state"] = "ACTIVE"

        if missing:
            missing_result = await client.call_tool("google_user_status", {"email": missing})
            missing_data = missing_result.data
            if not isinstance(missing_data, dict) or missing_data.get("state") != "NOT_FOUND":
                raise RuntimeError("GOOGLE_TEST_MISSING_USER did not return NOT_FOUND")
            output["missing_user_state"] = "NOT_FOUND"

    print(json.dumps(output, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
