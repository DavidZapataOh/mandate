import hashlib
import json
import os

import pytest

from swarm.meta_client import (
    DEFAULT_BASE_URL,
    MetaAPIError,
    MetaClient,
    api_key_from_env,
    reasoning_commitment,
)

REASONING = {
    "type": "reasoning",
    "id": "rs_1",
    "summary": [],
    "encrypted_content": "Q-PaENCRYPTEDblob",
}
CALL = {
    "type": "function_call",
    "call_id": "call_1",
    "name": "pay_bill",
    "arguments": '{"to": "acme-991", "amount_cents": 20000}',
}
MESSAGE = {
    "type": "message",
    "role": "assistant",
    "content": [{"type": "output_text", "text": "Paying the bill."}],
}


def _body(output, **over):
    body = {
        "id": "resp_abc",
        "object": "response",
        "status": "completed",
        "model": "muse-spark-1.3",
        "error": None,
        "output": output,
        "usage": {"input_tokens": 69, "output_tokens": 163, "total_tokens": 232},
    }
    body.update(over)
    return json.dumps(body).encode()


class _Recorder:
    def __init__(self, status=200, body=b"", headers=None):
        self.status = status
        self.body = body
        self.headers = {"x-request-id": "req-77"} if headers is None else headers
        self.calls = []

    def __call__(self, url, headers, payload):
        self.calls.append((url, headers, json.loads(payload)))
        return (self.status, self.headers, self.body)


def _clock():
    ticks = iter([10.0, 10.25])
    return lambda: next(ticks)


def test_request_shape_is_stateless_encrypted_replay():
    rec = _Recorder(body=_body([REASONING, CALL]))
    client = MetaClient("sk-test", transport=rec, clock=_clock())
    tools = ({"type": "function", "name": "pay_bill", "parameters": {}},)
    client.respond(
        "muse-spark-1.3",
        [{"role": "user", "content": "pay"}],
        tools=tools,
        instructions="be exact",
        effort="high",
    )
    url, headers, sent = rec.calls[0]
    assert url == f"{DEFAULT_BASE_URL}/responses"
    assert headers["Authorization"] == "Bearer sk-test"
    assert sent["model"] == "muse-spark-1.3"
    assert sent["store"] is False
    assert sent["include"] == ["reasoning.encrypted_content"]
    assert sent["reasoning"] == {"effort": "high"}
    assert sent["tools"] == [tools[0]]
    assert sent["instructions"] == "be exact"
    assert "previous_response_id" not in sent


def test_response_parsed_and_traced():
    rec = _Recorder(body=_body([REASONING, CALL, MESSAGE]))
    client = MetaClient("sk-test", transport=rec, clock=_clock())
    resp = client.respond("muse-spark-1.3", "pay")
    assert resp.trace.model == "muse-spark-1.3"
    assert resp.trace.response_id == "resp_abc"
    assert resp.trace.request_id == "req-77"
    assert resp.trace.latency_ms == 250.0
    assert (resp.trace.input_tokens, resp.trace.output_tokens) == (69, 163)
    assert resp.reasoning_items == (REASONING,)
    assert resp.function_calls == (CALL,)
    assert resp.text == "Paying the bill."
    assert resp.output == (REASONING, CALL, MESSAGE)


def test_missing_request_id_header_is_none():
    rec = _Recorder(body=_body([MESSAGE]), headers={})
    resp = MetaClient("k", transport=rec, clock=_clock()).respond("m", "x")
    assert resp.trace.request_id is None


@pytest.mark.parametrize(
    ("status", "body", "match"),
    [
        (401, b'{"error": {"message": "bad key"}}', "HTTP 401"),
        (200, _body([], error={"message": "boom"}), "boom"),
        (200, _body([], status="failed"), "status failed"),
        (200, b"not json", "undecodable"),
    ],
)
def test_errors_raise(status, body, match):
    rec = _Recorder(status=status, body=body)
    client = MetaClient("k", transport=rec, clock=_clock())
    with pytest.raises(MetaAPIError, match=match):
        client.respond("m", "x")


def test_reasoning_commitment_binds_encrypted_content():
    other = dict(REASONING, encrypted_content="DIFFERENT")
    first = reasoning_commitment([REASONING, CALL])
    assert len(first) == 64
    assert first == reasoning_commitment([CALL, REASONING])
    assert first != reasoning_commitment([other])
    assert reasoning_commitment([REASONING, REASONING]) != first
    expected = hashlib.sha256(
        b"mandate/reasoning/v1\n1\n" + b"Q-PaENCRYPTEDblob\n"
    ).hexdigest()
    assert first == expected
    empty = hashlib.sha256(b"mandate/reasoning/v1\n0\n").hexdigest()
    assert reasoning_commitment([MESSAGE]) == empty


def test_reasoning_commitment_rejects_redacted_items():
    bare = {"type": "reasoning", "id": "rs_1", "summary": []}
    with pytest.raises(ValueError, match="encrypted_content"):
        reasoning_commitment([bare])


def test_api_key_from_env():
    assert api_key_from_env({"MODEL_API_KEY": "a", "META_API_KEY": "b"}) == "a"
    assert api_key_from_env({"META_API_KEY": "b"}) == "b"
    with pytest.raises(KeyError, match="MODEL_API_KEY or META_API_KEY"):
        api_key_from_env({})


@pytest.mark.live
def test_live_meta_call_commits_reasoning():
    env = dict(os.environ)
    try:
        key = api_key_from_env(env)
    except KeyError:
        pytest.skip("live: set MODEL_API_KEY or META_API_KEY")
    resp = MetaClient(key).respond(
        "muse-spark-1.3",
        "Reply with exactly: MANDATE_OK",
        effort="low",
    )
    assert resp.trace.response_id.startswith("resp_")
    assert resp.trace.model.startswith("muse-spark-1.3")
    assert "MANDATE_OK" in resp.text
    assert resp.reasoning_items, "expected encrypted reasoning items"
    assert len(reasoning_commitment(resp.output)) == 64
