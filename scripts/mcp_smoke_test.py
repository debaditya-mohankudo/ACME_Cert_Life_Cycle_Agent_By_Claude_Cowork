from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import anyio
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _parse_json_text(text: str) -> dict[str, Any]:
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Expected JSON tool output, got: {text!r}") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"Expected JSON object output, got: {type(value).__name__}")
    return value


def _first_text(result: Any) -> str:
    if not result.content:
        raise RuntimeError("Tool returned no content")
    text = getattr(result.content[0], "text", None)
    if not text:
        raise RuntimeError("Tool returned non-text content")
    return text


async def _run(args: argparse.Namespace) -> int:
    server_params = StdioServerParameters(
        command="uv",
        args=["run", "python", "mcp_server.py"],
        cwd=PROJECT_ROOT,
    )

    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()

            tools_result = await session.list_tools()
            available_tools = {tool.name for tool in tools_result.tools}
            expected_tools = {
                "health",
                "renew_once",
                "revoke_cert",
                "expiring_in_30_days",
                "domain_status",
            }
            missing = expected_tools - available_tools
            if missing:
                raise RuntimeError(f"Missing expected tools: {sorted(missing)}")

            health_result = await session.call_tool("health", {"ca_input_mode": "config"})
            if health_result.isError:
                raise RuntimeError("health tool returned isError=true")
            health = _parse_json_text(_first_text(health_result))

            print("[OK] connected to MCP server")
            print(f"[OK] tools available: {sorted(available_tools)}")
            print(f"[OK] health provider={health.get('provider')} llm_provider={health.get('llm_provider')}")

            if args.run_renew:
                renew_args: dict[str, Any] = {
                    "checkpoint": args.checkpoint,
                    "ca_input_mode": "config",
                }
                if args.domains:
                    renew_args["domains"] = args.domains
                renew_result = await session.call_tool("renew_once", renew_args)
                if renew_result.isError:
                    raise RuntimeError("renew_once tool returned isError=true")
                renew = _parse_json_text(_first_text(renew_result))
                print(
                    "[OK] renew_once completed=%s failed=%s"
                    % (
                        len(renew.get("completed_renewals", [])),
                        len(renew.get("failed_renewals", [])),
                    )
                )

            if args.run_revoke:
                if not args.revoke_domains:
                    raise RuntimeError("--run-revoke requires --revoke-domains")
                revoke_result = await session.call_tool(
                    "revoke_cert",
                    {
                        "domains": args.revoke_domains,
                        "reason": args.reason,
                        "checkpoint": args.checkpoint,
                        "ca_input_mode": "config",
                    },
                )
                if revoke_result.isError:
                    raise RuntimeError("revoke_cert tool returned isError=true")
                revoke = _parse_json_text(_first_text(revoke_result))
                print(
                    "[OK] revoke_cert revoked=%s failed=%s"
                    % (
                        len(revoke.get("revoked_domains", [])),
                        len(revoke.get("failed_revocations", [])),
                    )
                )

    print("[PASS] MCP smoke test completed")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Smoke test the local MCP server")
    parser.add_argument("--run-renew", action="store_true", help="Also call renew_once")
    parser.add_argument("--run-revoke", action="store_true", help="Also call revoke_cert")
    parser.add_argument("--domains", nargs="+", help="Domains to pass to renew_once")
    parser.add_argument(
        "--revoke-domains",
        nargs="+",
        help="Domains to pass to revoke_cert (required with --run-revoke)",
    )
    parser.add_argument(
        "--reason",
        type=int,
        default=0,
        choices=[0, 1, 4, 5],
        help=(
            "Revocation reason code: "
            "0=unspecified, 1=keyCompromise, 4=superseded, 5=cessationOfOperation"
        ),
    )
    parser.add_argument("--checkpoint", action="store_true", help="Enable checkpoint mode")
    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    try:
        return anyio.run(_run, args)
    except Exception as exc:
        print(f"[FAIL] {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
