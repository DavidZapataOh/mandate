"""Meta Model API client: Responses API with stateless encrypted replay.

Every call is traced (model, response id, request id, latency, tokens) so
each governed action can name the Meta call that proposed it.
"""

import hashlib
import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

DEFAULT_BASE_URL = "https://api.meta.ai/v1"
_COMMIT_DOMAIN = b"mandate/reasoning/v1\n"

Transport = Callable[[str, dict[str, str], bytes], tuple[int, dict[str, str], bytes]]
Item = dict[str, Any]


class MetaAPIError(RuntimeError):
    """Meta Model API returned an error or an unusable response."""


@dataclass(frozen=True)
class MetaTrace:
    """Audit facts for one Meta Model API call.

    Args:
        model: Model id echoed by the API.
        response_id: Response id (resp_...).
        request_id: x-request-id header when the API sends one.
        latency_ms: Wall time of the HTTP round trip.
        input_tokens: Billed input tokens.
        output_tokens: Billed output tokens.
    """

    model: str
    response_id: str
    request_id: str | None
    latency_ms: float
    input_tokens: int
    output_tokens: int


@dataclass(frozen=True)
class MetaResponse:
    """Parsed Responses API result.

    Args:
        trace: Audit facts for the call.
        output: Raw output items, in order, for stateless replay.
    """

    trace: MetaTrace
    output: tuple[Item, ...]

    @property
    def reasoning_items(self) -> tuple[Item, ...]:
        """Encrypted reasoning items, replayable on the next turn."""
        return tuple(i for i in self.output if i.get("type") == "reasoning")

    @property
    def function_calls(self) -> tuple[Item, ...]:
        """Tool calls the model proposed."""
        return tuple(i for i in self.output if i.get("type") == "function_call")

    @property
    def text(self) -> str:
        """Concatenated assistant output text."""
        parts: list[str] = []
        for item in self.output:
            if item.get("type") != "message":
                continue
            for block in item.get("content") or []:
                if block.get("type") == "output_text":
                    parts.append(str(block.get("text", "")))
        return "".join(parts)


def urllib_transport(
    url: str, headers: dict[str, str], payload: bytes
) -> tuple[int, dict[str, str], bytes]:
    """POST over stdlib urllib; HTTP errors return their status and body."""
    if not url.startswith("https://"):
        raise ValueError(f"refusing non-https url: {url}")
    req = urllib.request.Request(  # noqa: S310 (https enforced above)
        url, data=payload, headers=headers, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310
            return (
                resp.status,
                {k.lower(): v for k, v in resp.headers.items()},
                resp.read(),
            )
    except urllib.error.HTTPError as exc:
        return (exc.code, {k.lower(): v for k, v in exc.headers.items()}, exc.read())


def api_key_from_env(env: Mapping[str, str]) -> str:
    """MODEL_API_KEY (Meta docs name) or META_API_KEY.

    Raises:
        KeyError: When neither is set.
    """
    for name in ("MODEL_API_KEY", "META_API_KEY"):
        value = env.get(name)
        if value:
            return value
    raise KeyError("set MODEL_API_KEY or META_API_KEY")


def reasoning_commitment(items: Iterable[Item]) -> str:
    """SHA-256 commitment over the encrypted reasoning of a turn chain.

    Order-independent across non-reasoning items, order-preserving across
    reasoning items. Domain-separated and length-prefixed.

    Raises:
        ValueError: When a reasoning item lacks encrypted_content.
    """
    blobs: list[bytes] = []
    for item in items:
        if item.get("type") != "reasoning":
            continue
        content = item.get("encrypted_content")
        if not isinstance(content, str) or not content:
            raise ValueError("reasoning item without encrypted_content")
        blobs.append(content.encode("utf-8"))
    digest = hashlib.sha256(_COMMIT_DOMAIN + f"{len(blobs)}\n".encode())
    for blob in blobs:
        digest.update(blob + b"\n")
    return digest.hexdigest()


class MetaClient:
    """Responses API client pinned to stateless encrypted replay.

    Args:
        api_key: Meta Model API key.
        base_url: API base URL.
        transport: HTTP POST function; injectable for tests.
        clock: Monotonic clock in seconds; injectable for tests.
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = DEFAULT_BASE_URL,
        transport: Transport = urllib_transport,
        clock: Callable[[], float] = time.perf_counter,
    ) -> None:
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._transport = transport
        self._clock = clock

    def respond(
        self,
        model: str,
        input: str | list[Item],  # noqa: A002
        *,
        tools: Iterable[Item] = (),
        instructions: str | None = None,
        effort: str = "medium",
    ) -> MetaResponse:
        """One Responses API turn; never stores server-side state.

        Raises:
            MetaAPIError: On HTTP errors, API errors, or bad payloads.
        """
        body: dict[str, Any] = {
            "model": model,
            "input": input,
            "store": False,
            "include": ["reasoning.encrypted_content"],
            "reasoning": {"effort": effort},
        }
        tool_list = list(tools)
        if tool_list:
            body["tools"] = tool_list
        if instructions is not None:
            body["instructions"] = instructions
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        start = self._clock()
        status, resp_headers, raw = self._transport(
            f"{self._base_url}/responses", headers, json.dumps(body).encode()
        )
        latency_ms = (self._clock() - start) * 1000.0
        if status >= 400:
            raise MetaAPIError(f"HTTP {status}: {raw[:300]!r}")
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise MetaAPIError("response undecodable") from exc
        if not isinstance(data, dict):
            raise MetaAPIError("response undecodable")
        if data.get("error"):
            raise MetaAPIError(f"API error: {data['error']}")
        if data.get("status") != "completed":
            raise MetaAPIError(f"response status {data.get('status')}")
        usage = data.get("usage") or {}
        trace = MetaTrace(
            model=str(data.get("model", model)),
            response_id=str(data.get("id", "")),
            request_id=resp_headers.get("x-request-id"),
            latency_ms=latency_ms,
            input_tokens=int(usage.get("input_tokens", 0)),
            output_tokens=int(usage.get("output_tokens", 0)),
        )
        return MetaResponse(trace=trace, output=tuple(data.get("output") or ()))
