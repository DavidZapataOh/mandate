"""Meta Model API client: Responses API with stateless encrypted replay.

Uses the OpenAI SDK pointed at Meta Model API, as the Meta docs prescribe.
Every call is traced (model, response id, request id, latency, tokens) so
each governed action can name the Meta call that proposed it.
"""

import hashlib
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

import httpx2
import openai
from openai import NOT_GIVEN, OpenAI, omit

DEFAULT_BASE_URL = "https://api.meta.ai/v1"
_COMMIT_DOMAIN = b"mandate/reasoning/v1\n"

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
        latency_ms: Wall time of the call.
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
        output: Output items as plain dicts, in order, for stateless replay.
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
        return "".join(
            str(block.get("text", ""))
            for item in self.output
            if item.get("type") == "message"
            for block in item.get("content") or []
            if block.get("type") == "output_text"
        )


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


def check_blob(blob: str) -> None:
    """Validate one encrypted reasoning blob.

    Raises:
        ValueError: When the blob is empty or contains a newline.
    """
    if not blob or "\n" in blob:
        raise ValueError("reasoning blob must be non-empty without newlines")


def reasoning_commitment(items: Iterable[Item]) -> str:
    """SHA-256 commitment over the encrypted reasoning of a turn chain.

    Ignores non-reasoning items, preserves reasoning order, and is
    domain-separated, count-prefixed and newline-delimited; blobs must not
    contain newlines.

    Raises:
        ValueError: When a reasoning item lacks encrypted_content or its
            blob is empty or contains a newline.
    """
    blobs: list[bytes] = []
    for item in items:
        if item.get("type") != "reasoning":
            continue
        content = item.get("encrypted_content")
        if not isinstance(content, str) or not content:
            raise ValueError("reasoning item without encrypted_content")
        check_blob(content)
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
        http_client: Optional HTTP client; injectable for tests.
        max_retries: SDK retry budget for transient failures.
        clock: Monotonic clock in seconds; injectable for tests.
        timeout: Per-request timeout in seconds; None keeps the SDK default.
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = DEFAULT_BASE_URL,
        http_client: httpx2.Client | None = None,
        max_retries: int = 2,
        clock: Callable[[], float] = time.perf_counter,
        timeout: float | None = None,
    ) -> None:
        self._sdk = OpenAI(
            api_key=api_key,
            base_url=base_url,
            http_client=http_client,
            max_retries=max_retries,
            timeout=NOT_GIVEN if timeout is None else timeout,
        )
        self._clock = clock

    def respond(
        self,
        model: str,
        input: str | list[Item],  # noqa: A002
        *,
        tools: Iterable[Item] = (),
        instructions: str | None = None,
        effort: str = "medium",
        text_format: Item | None = None,
    ) -> MetaResponse:
        """One Responses API turn; never stores server-side state.

        Args:
            model: Model id.
            input: Prompt text or replayed items.
            tools: Function tool definitions.
            instructions: System instructions.
            effort: Reasoning effort.
            text_format: Structured-output format (text.format), e.g. a
                json_schema item; omitted when None.

        Raises:
            MetaAPIError: On HTTP errors, API errors, or bad payloads.
        """
        tool_list: Any = list(tools) or omit
        start = self._clock()
        try:
            # SDK types follow OpenAI's catalog; Meta adds values such as
            # effort "max", so the typed overloads cannot match.
            resp = self._sdk.responses.create(  # type: ignore[call-overload]
                model=model,
                input=input,
                store=False,
                include=["reasoning.encrypted_content"],
                reasoning={"effort": effort},
                tools=tool_list,
                instructions=omit if instructions is None else instructions,
                text=omit if text_format is None else {"format": text_format},
            )
        except openai.APIStatusError as exc:
            raise MetaAPIError(f"HTTP {exc.status_code}: {exc.message}") from exc
        except (openai.APIResponseValidationError, ValueError) as exc:
            raise MetaAPIError("response undecodable") from exc
        latency_ms = (self._clock() - start) * 1000.0
        if not hasattr(resp, "status"):
            raise MetaAPIError("response undecodable")
        if resp.error is not None:
            raise MetaAPIError(f"API error: {resp.error.message}")
        if resp.status != "completed":
            raise MetaAPIError(f"response status {resp.status}")
        usage = resp.usage
        trace = MetaTrace(
            model=resp.model,
            response_id=resp.id,
            request_id=resp._request_id,
            latency_ms=latency_ms,
            input_tokens=usage.input_tokens if usage else 0,
            output_tokens=usage.output_tokens if usage else 0,
        )
        output = tuple(item.model_dump(exclude_none=True) for item in resp.output)
        return MetaResponse(trace=trace, output=output)
