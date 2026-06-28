#!/usr/bin/env python
"""Benchmark direct Codex Responses transports without using the local proxy.

This script sends requests directly to the ChatGPT Codex Responses backend and
compares HTTP SSE with WebSocket transports. It intentionally bypasses
`src/proxy_app/main.py` so the reported timings measure upstream transport and
model latency rather than proxy forwarding overhead.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import statistics
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, Iterable, Optional

import httpx

DEFAULT_CODEX_API_BASE = "https://chatgpt.com/backend-api/codex"
DEFAULT_CODEX_RESPONSES_ENDPOINT = f"{DEFAULT_CODEX_API_BASE}/responses"
DEFAULT_CODEX_WS_ENDPOINT = "wss://chatgpt.com/backend-api/codex/responses"
DEFAULT_CODEX_USAGE_ENDPOINT = "https://chatgpt.com/backend-api/wham/usage"
DEFAULT_WS_BETA_HEADER = "responses_websockets=2026-02-06"
DEFAULT_SSE_BETA_HEADER = "responses=experimental"
TERMINAL_EVENTS = {
    "response.completed",
    "response.incomplete",
    "response.failed",
    "response.done",
    "error",
}
OUTPUT_DELTA_EVENTS = {
    "response.output_text.delta",
    "response.reasoning_summary_text.delta",
    "response.reasoning_text.delta",
    "response.function_call_arguments.delta",
}


@dataclass
class AuthSelection:
    credential_path: str
    auth_headers: Dict[str, str]
    account_id: Optional[str]


@dataclass
class BenchmarkResult:
    transport: str
    run: int
    model: str
    status: str = "ok"
    error: Optional[str] = None
    connect_ms: Optional[float] = None
    headers_ms: Optional[float] = None
    first_event_ms: Optional[float] = None
    first_output_ms: Optional[float] = None
    total_ms: Optional[float] = None
    events: int = 0
    output_events: int = 0
    output_chars: int = 0
    response_id: Optional[str] = None
    terminal_event: Optional[str] = None
    event_gaps_ms: list[float] = field(default_factory=list)

    @property
    def avg_event_gap_ms(self) -> Optional[float]:
        if not self.event_gaps_ms:
            return None
        return statistics.fmean(self.event_gaps_ms)

    @property
    def max_event_gap_ms(self) -> Optional[float]:
        if not self.event_gaps_ms:
            return None
        return max(self.event_gaps_ms)


def strip_provider_prefix(model: str) -> str:
    return model.split("/", 1)[1] if "/" in model else model


def build_responses_payload(
    *,
    model: str,
    prompt: str,
    instructions: str,
    reasoning_effort: str,
    service_tier: Optional[str],
    session_id: Optional[str],
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "model": strip_provider_prefix(model),
        "input": [
            {
                "type": "message",
                "role": "user",
                "content": [{"type": "input_text", "text": prompt}],
            }
        ],
        "stream": True,
        "store": False,
        "instructions": instructions,
        "text": {"verbosity": "medium"},
    }
    if reasoning_effort:
        payload["reasoning"] = {"effort": reasoning_effort, "summary": "auto"}
    if service_tier:
        payload["service_tier"] = service_tier
    if session_id:
        payload["prompt_cache_key"] = session_id
    return payload


def build_websocket_response_create_event(
    payload: Dict[str, Any],
    previous_response_id: Optional[str] = None,
) -> Dict[str, Any]:
    event = {"type": "response.create", **payload}
    event.pop("stream", None)
    event.pop("background", None)
    if previous_response_id:
        event["previous_response_id"] = previous_response_id
    return event


def build_sse_headers(
    auth_headers: Dict[str, str],
    *,
    account_id: Optional[str],
    session_id: Optional[str],
    extra_headers: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    headers = {
        **auth_headers,
        "Content-Type": "application/json",
        "Accept": "text/event-stream",
        "OpenAI-Beta": DEFAULT_SSE_BETA_HEADER,
    }
    if account_id:
        headers["ChatGPT-Account-Id"] = account_id
    if session_id:
        headers["session_id"] = session_id
        headers["x-client-request-id"] = session_id
    if extra_headers:
        headers.update(extra_headers)
    return headers


def build_websocket_headers(
    auth_headers: Dict[str, str],
    *,
    account_id: Optional[str],
    session_id: Optional[str],
    extra_headers: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    request_id = session_id or f"bench-{uuid.uuid4().hex}"
    headers = {
        **auth_headers,
        "OpenAI-Beta": DEFAULT_WS_BETA_HEADER,
        "x-client-request-id": request_id,
        "session-id": request_id,
    }
    if account_id:
        headers["ChatGPT-Account-Id"] = account_id
    if extra_headers:
        headers.update(extra_headers)
    headers.pop("Accept", None)
    headers.pop("Content-Type", None)
    return headers


def _credential_sort_key(path: Path) -> tuple[int, str]:
    stem = path.stem
    try:
        index = int(stem.rsplit("_", 1)[1])
    except (IndexError, ValueError):
        index = sys.maxsize
    return index, path.name


def discover_codex_credentials(root: Optional[Path] = None) -> list[Path]:
    root = root or Path(__file__).resolve().parents[1]
    oauth_dir = root / "oauth_creds"
    return sorted(oauth_dir.glob("codex_oauth_*.json"), key=_credential_sort_key)


def discover_usage_ranked_codex_accessors(root: Optional[Path] = None) -> list[str]:
    """Return non-exhausted env://codex/N accessors ranked by local usage state."""
    root = root or Path(__file__).resolve().parents[1]
    usage_path = root / "usage" / "usage_codex.json"
    try:
        with usage_path.open("r", encoding="utf-8") as handle:
            usage_data = json.load(handle)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return []

    now = time.time()
    ranked: list[tuple[int, float, str]] = []
    for state in usage_data.get("credentials", {}).values():
        if not isinstance(state, dict):
            continue
        accessor = str(state.get("accessor") or "")
        if not accessor.startswith("env://codex/"):
            continue
        health = state.get("credential_health")
        if isinstance(health, dict) and health.get("blocked"):
            continue

        remaining_values: list[int] = []
        exhausted = False
        for group_data in (state.get("group_usage") or {}).values():
            if not isinstance(group_data, dict):
                continue
            windows = group_data.get("windows") or {}
            for window in windows.values():
                if not isinstance(window, dict):
                    continue
                limit = window.get("limit")
                if not limit:
                    continue
                try:
                    limit_int = int(limit)
                    count = int(window.get("request_count") or 0)
                except (TypeError, ValueError):
                    continue
                reset_at = window.get("reset_at")
                reset_in_future = not reset_at
                try:
                    reset_in_future = float(reset_at) > now
                except (TypeError, ValueError):
                    pass
                remaining = max(0, limit_int - count)
                remaining_values.append(remaining)
                if remaining <= 0 and reset_in_future:
                    exhausted = True

        if exhausted:
            continue
        min_remaining = min(remaining_values) if remaining_values else 0
        try:
            accessor_index = int(accessor.rsplit("/", 1)[1])
        except ValueError:
            accessor_index = sys.maxsize
        ranked.append((-min_remaining, accessor_index, accessor))

    ranked.sort()
    return [accessor for _, _, accessor in ranked]


def import_pi_agent_env(root: Path) -> None:
    """Load Pi-managed OAuth credentials into this benchmark process."""
    src_dir = root / "src"
    if str(src_dir) not in sys.path:
        sys.path.insert(0, str(src_dir))
    try:
        from dotenv import load_dotenv

        load_dotenv(root / ".env", override=False)
    except Exception:
        pass
    try:
        from proxy_app.pi_agent_importer import import_pi_agent_config

        import_pi_agent_config(root_dir=root)
    except Exception as exc:
        print(f"warning: Pi agent credential import failed: {exc!r}", file=sys.stderr)


async def load_auth(
    credential_path: str | Path,
    *,
    use_provider_refresh: bool,
) -> tuple[Dict[str, str], Optional[str]]:
    credential_ref = str(credential_path)
    if use_provider_refresh:
        root = Path(__file__).resolve().parents[1]
        sys.path.insert(0, str(root / "src"))
        from rotator_library.providers.codex_provider import CodexProvider

        provider = CodexProvider()
        auth_headers = await provider.get_auth_header(credential_ref)
        account_id = await provider.get_account_id(credential_ref)
        return auth_headers, account_id

    path = Path(credential_ref)
    with path.open("r", encoding="utf-8") as handle:
        creds = json.load(handle)
    token = creds.get("api_key") or creds.get("access_token")
    if not token:
        raise ValueError(f"Credential file has no api_key/access_token: {credential_ref}")
    account_id = creds.get("account_id") or creds.get("_proxy_metadata", {}).get("account_id")
    return {"Authorization": f"Bearer {token}"}, account_id


async def probe_auth(
    *,
    endpoint: str,
    headers: Dict[str, str],
    payload: Dict[str, Any],
    timeout_seconds: float,
) -> bool:
    """Return True when a credential is accepted by the direct Codex backend."""
    del endpoint, payload
    probe_headers = {
        **headers,
        "Content-Type": "application/json",
        "User-Agent": "codex-cli",
    }
    timeout = httpx.Timeout(
        connect=min(10.0, timeout_seconds),
        read=min(30.0, timeout_seconds),
        write=10.0,
        pool=10.0,
    )
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        response = await client.get(DEFAULT_CODEX_USAGE_ENDPOINT, headers=probe_headers)
    return 200 <= response.status_code < 300


async def select_auth_for_benchmark(
    *,
    credential: Optional[Path],
    root: Path,
    endpoint: str,
    model: str,
    use_provider_refresh: bool,
    timeout_seconds: float,
    auth_loader: Callable[..., Awaitable[tuple[Dict[str, str], Optional[str]]]] = load_auth,
    auth_probe: Callable[..., Awaitable[bool]] = probe_auth,
    pi_importer: Callable[[Path], None] = import_pi_agent_env,
) -> AuthSelection:
    if credential is not None:
        auth_headers, account_id = await auth_loader(
            credential,
            use_provider_refresh=use_provider_refresh,
        )
        return AuthSelection(str(credential), auth_headers, account_id)

    if use_provider_refresh:
        pi_importer(root)

    candidates: list[str] = []
    seen: set[str] = set()
    if use_provider_refresh:
        for accessor in discover_usage_ranked_codex_accessors(root):
            if accessor not in seen:
                candidates.append(accessor)
                seen.add(accessor)
    for path in discover_codex_credentials(root):
        path_value = str(path)
        if path_value not in seen:
            candidates.append(path_value)
            seen.add(path_value)

    if not candidates:
        raise FileNotFoundError(
            f"No Codex credentials found in usage state or under {root / 'oauth_creds'}"
        )

    probe_payload = build_responses_payload(
        model=model,
        prompt="Credential probe",
        instructions="Credential probe.",
        reasoning_effort="",
        service_tier=None,
        session_id=None,
    )
    failures: list[str] = []
    for candidate in candidates:
        try:
            auth_headers, account_id = await auth_loader(
                candidate,
                use_provider_refresh=use_provider_refresh,
            )
            probe_headers = build_sse_headers(
                auth_headers,
                account_id=account_id,
                session_id=None,
            )
            if await auth_probe(
                endpoint=endpoint,
                headers=probe_headers,
                payload=probe_payload,
                timeout_seconds=min(timeout_seconds, 30.0),
            ):
                return AuthSelection(candidate, auth_headers, account_id)
            failures.append(f"{candidate}: probe rejected")
        except Exception as exc:
            failures.append(f"{candidate}: {exc!r}")

    details = "; ".join(failures[-5:])
    raise RuntimeError(
        "No usable Codex credential found. Re-authenticate a Codex credential or pass "
        f"--credential explicitly. Last failures: {details}"
    )


async def iter_sse_events(response: httpx.Response) -> AsyncIterator[Dict[str, Any]]:
    buffer = ""
    async for chunk in response.aiter_text():
        if not chunk:
            continue
        buffer += chunk
        while True:
            event_text, separator, rest = buffer.partition("\n\n")
            if not separator:
                break
            buffer = rest
            data_lines = [
                line[5:].strip()
                for line in event_text.splitlines()
                if line.startswith("data:")
            ]
            if not data_lines:
                continue
            data = "\n".join(data_lines).strip()
            if not data or data == "[DONE]":
                continue
            try:
                yield json.loads(data)
            except json.JSONDecodeError:
                continue


async def benchmark_sse_once(
    *,
    run: int,
    endpoint: str,
    headers: Dict[str, str],
    payload: Dict[str, Any],
    timeout_seconds: float,
) -> BenchmarkResult:
    result = BenchmarkResult(transport="sse", run=run, model=str(payload.get("model", "")))
    start = time.perf_counter()
    last_event_at: Optional[float] = None
    timeout = httpx.Timeout(
        connect=min(30.0, timeout_seconds),
        read=timeout_seconds,
        write=30.0,
        pool=30.0,
    )
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            async with client.stream("POST", endpoint, headers=headers, json=payload) as response:
                result.headers_ms = elapsed_ms(start)
                if response.status_code >= 400:
                    body = await response.aread()
                    result.status = "error"
                    result.error = f"HTTP {response.status_code}: {body.decode('utf-8', errors='replace')[:500]}"
                    result.total_ms = elapsed_ms(start)
                    return result

                async for event in iter_sse_events(response):
                    now = time.perf_counter()
                    record_event_timing(result, event, start, now, last_event_at)
                    last_event_at = now
                    if result.terminal_event:
                        break
    except Exception as exc:
        result.status = "error"
        result.error = repr(exc)
    finally:
        result.total_ms = elapsed_ms(start)
    return result


async def benchmark_websocket_once(
    *,
    run: int,
    ws_endpoint: str,
    headers: Dict[str, str],
    payload: Dict[str, Any],
    timeout_seconds: float,
    previous_response_id: Optional[str] = None,
    existing_socket: Optional[Any] = None,
) -> tuple[BenchmarkResult, Optional[str]]:
    import websockets.asyncio.client

    result = BenchmarkResult(transport="ws", run=run, model=str(payload.get("model", "")))
    start = time.perf_counter()
    last_event_at: Optional[float] = None
    socket = existing_socket
    owns_socket = socket is None
    try:
        if socket is None:
            socket = await websockets.asyncio.client.connect(
                ws_endpoint,
                additional_headers=headers,
                max_size=2**24,
                close_timeout=5,
                ping_interval=20,
                ping_timeout=20,
            )
            result.connect_ms = elapsed_ms(start)
        else:
            result.connect_ms = 0.0

        await socket.send(json.dumps(build_websocket_response_create_event(payload, previous_response_id)))

        while True:
            raw = await asyncio.wait_for(socket.recv(), timeout=timeout_seconds)
            now = time.perf_counter()
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8", errors="replace")
            event = json.loads(raw)
            record_event_timing(result, event, start, now, last_event_at)
            last_event_at = now
            if result.terminal_event:
                break
    except Exception as exc:
        result.status = "error"
        result.error = repr(exc)
    finally:
        result.total_ms = elapsed_ms(start)
        if owns_socket and socket is not None:
            await socket.close()
    return result, result.response_id


async def benchmark_websocket_cached(
    *,
    runs: int,
    ws_endpoint: str,
    headers: Dict[str, str],
    payload: Dict[str, Any],
    timeout_seconds: float,
) -> list[BenchmarkResult]:
    import websockets.asyncio.client

    results: list[BenchmarkResult] = []
    previous_response_id: Optional[str] = None
    async with websockets.asyncio.client.connect(
        ws_endpoint,
        additional_headers=headers,
        max_size=2**24,
        close_timeout=5,
        ping_interval=20,
        ping_timeout=20,
    ) as socket:
        for run in range(1, runs + 1):
            result, response_id = await benchmark_websocket_once(
                run=run,
                ws_endpoint=ws_endpoint,
                headers=headers,
                payload=payload,
                timeout_seconds=timeout_seconds,
                previous_response_id=previous_response_id,
                existing_socket=socket,
            )
            result.transport = "ws-cached"
            results.append(result)
            if result.status != "ok":
                break
            previous_response_id = response_id
    return results


def record_event_timing(
    result: BenchmarkResult,
    event: Dict[str, Any],
    start: float,
    now: float,
    last_event_at: Optional[float],
) -> None:
    result.events += 1
    event_type = str(event.get("type") or "")
    if result.first_event_ms is None:
        result.first_event_ms = elapsed_ms(start, now)
    if last_event_at is not None:
        result.event_gaps_ms.append((now - last_event_at) * 1000)

    if isinstance(event.get("response"), dict):
        response_id = event["response"].get("id")
        if response_id:
            result.response_id = str(response_id)

    if event_type in OUTPUT_DELTA_EVENTS:
        result.output_events += 1
        if result.first_output_ms is None:
            result.first_output_ms = elapsed_ms(start, now)
        delta = event.get("delta")
        if isinstance(delta, str):
            result.output_chars += len(delta)

    if event_type in TERMINAL_EVENTS:
        result.terminal_event = event_type
        if event_type == "error":
            result.status = "error"
            result.error = describe_event_error(event)
        if isinstance(event.get("response"), dict):
            response_id = event["response"].get("id")
            if response_id:
                result.response_id = str(response_id)


def describe_event_error(event: Dict[str, Any]) -> str:
    error = event.get("error")
    if isinstance(error, dict):
        message = error.get("message") or error.get("code") or error.get("type")
        if message:
            return str(message)
    return json.dumps(event, ensure_ascii=False, default=str)[:500]


def elapsed_ms(start: float, now: Optional[float] = None) -> float:
    return ((now if now is not None else time.perf_counter()) - start) * 1000


def format_optional_ms(value: Optional[float]) -> str:
    return "-" if value is None else f"{value:.1f}"


def print_result(result: BenchmarkResult) -> None:
    print(
        f"{result.transport:9} run={result.run:<2} status={result.status:<5} "
        f"connect_ms={format_optional_ms(result.connect_ms)} "
        f"headers_ms={format_optional_ms(result.headers_ms)} "
        f"first_event_ms={format_optional_ms(result.first_event_ms)} "
        f"first_output_ms={format_optional_ms(result.first_output_ms)} "
        f"total_ms={format_optional_ms(result.total_ms)} "
        f"events={result.events:<4} output_events={result.output_events:<4} "
        f"avg_gap_ms={format_optional_ms(result.avg_event_gap_ms)} "
        f"max_gap_ms={format_optional_ms(result.max_event_gap_ms)} "
        f"terminal={result.terminal_event or '-'}"
    )
    if result.error:
        print(f"  error: {result.error}")


def print_summary(results: Iterable[BenchmarkResult]) -> None:
    by_transport: Dict[str, list[BenchmarkResult]] = {}
    for result in results:
        if result.status == "ok":
            by_transport.setdefault(result.transport, []).append(result)
    if not by_transport:
        return
    print("\nSummary (successful runs only):")
    for transport, items in by_transport.items():
        first_output = [item.first_output_ms for item in items if item.first_output_ms is not None]
        total = [item.total_ms for item in items if item.total_ms is not None]
        first_event = [item.first_event_ms for item in items if item.first_event_ms is not None]
        print(
            f"{transport:9} runs={len(items):<2} "
            f"median_first_event_ms={median_or_dash(first_event)} "
            f"median_first_output_ms={median_or_dash(first_output)} "
            f"median_total_ms={median_or_dash(total)}"
        )


def median_or_dash(values: list[float]) -> str:
    return "-" if not values else f"{statistics.median(values):.1f}"


def parse_transports(value: str) -> list[str]:
    transports = [item.strip().lower() for item in value.split(",") if item.strip()]
    allowed = {"sse", "ws", "ws-cached"}
    invalid = [item for item in transports if item not in allowed]
    if invalid:
        raise argparse.ArgumentTypeError(
            f"Invalid transport(s): {', '.join(invalid)}. Allowed: {', '.join(sorted(allowed))}"
        )
    return transports


def default_root() -> Path:
    return Path(__file__).resolve().parents[1]


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Benchmark direct Codex Responses SSE/WebSocket transports without local proxy."
    )
    parser.add_argument(
        "--credential",
        type=Path,
        default=None,
        help="Specific Codex OAuth JSON to use. Defaults to auto-scanning oauth_creds/codex_oauth_*.json.",
    )
    parser.add_argument("--model", default=os.getenv("CODEX_BENCH_MODEL", "gpt-5.5"))
    parser.add_argument("--prompt", default="Reply with one concise sentence for a transport benchmark.")
    parser.add_argument("--instructions", default="You are a concise benchmark assistant.")
    parser.add_argument("--reasoning-effort", default="medium")
    parser.add_argument("--service-tier", default=os.getenv("CODEX_BENCH_SERVICE_TIER"))
    parser.add_argument("--session-id", default=f"bench-{uuid.uuid4().hex[:12]}")
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--transports", type=parse_transports, default=parse_transports("sse,ws,ws-cached"))
    parser.add_argument("--endpoint", default=os.getenv("CODEX_RESPONSES_ENDPOINT", DEFAULT_CODEX_RESPONSES_ENDPOINT))
    parser.add_argument("--ws-endpoint", default=os.getenv("CODEX_WS_ENDPOINT", DEFAULT_CODEX_WS_ENDPOINT))
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument(
        "--no-refresh",
        action="store_true",
        help="Load access token directly from credential JSON instead of using provider refresh logic.",
    )
    return parser


async def run_benchmark(args: argparse.Namespace) -> list[BenchmarkResult]:
    auth_selection = await select_auth_for_benchmark(
        credential=args.credential,
        root=default_root(),
        endpoint=args.endpoint,
        model=args.model,
        use_provider_refresh=not args.no_refresh,
        timeout_seconds=args.timeout,
    )
    auth_headers = auth_selection.auth_headers
    account_id = auth_selection.account_id
    payload = build_responses_payload(
        model=args.model,
        prompt=args.prompt,
        instructions=args.instructions,
        reasoning_effort=args.reasoning_effort,
        service_tier=args.service_tier,
        session_id=args.session_id,
    )
    sse_headers = build_sse_headers(auth_headers, account_id=account_id, session_id=args.session_id)
    ws_headers = build_websocket_headers(auth_headers, account_id=account_id, session_id=args.session_id)

    print("Direct Codex transport benchmark")
    print(f"model={payload['model']} runs={args.runs} session_id={args.session_id}")
    print(f"credential={auth_selection.credential_path}")
    print(f"endpoint={args.endpoint}")
    print(f"ws_endpoint={args.ws_endpoint}")
    print("")

    results: list[BenchmarkResult] = []
    if "sse" in args.transports:
        for run in range(1, args.runs + 1):
            result = await benchmark_sse_once(
                run=run,
                endpoint=args.endpoint,
                headers=sse_headers,
                payload=payload,
                timeout_seconds=args.timeout,
            )
            results.append(result)
            print_result(result)

    if "ws" in args.transports:
        for run in range(1, args.runs + 1):
            result, _response_id = await benchmark_websocket_once(
                run=run,
                ws_endpoint=args.ws_endpoint,
                headers=ws_headers,
                payload=payload,
                timeout_seconds=args.timeout,
            )
            results.append(result)
            print_result(result)

    if "ws-cached" in args.transports:
        try:
            cached_results = await benchmark_websocket_cached(
                runs=args.runs,
                ws_endpoint=args.ws_endpoint,
                headers=ws_headers,
                payload=payload,
                timeout_seconds=args.timeout,
            )
        except Exception as exc:
            cached_results = [
                BenchmarkResult(
                    transport="ws-cached",
                    run=1,
                    model=str(payload.get("model", "")),
                    status="error",
                    error=repr(exc),
                    total_ms=0.0,
                )
            ]
        results.extend(cached_results)
        for result in cached_results:
            print_result(result)

    print_summary(results)
    return results


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs must be >= 1")
    try:
        asyncio.run(run_benchmark(args))
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f"benchmark failed: {exc!r}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
