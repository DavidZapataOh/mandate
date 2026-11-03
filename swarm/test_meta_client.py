import hashlib
import json
import os

import httpx2
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
    "id": "fc_1",
    "call_id": "call_1",
    "name": "pay_bill",
    "arguments": '{"to": "acme-991", "amount_cents": 20000}',
    "status": "completed",
}
MESSAGE = {
    "type": "message",
    "id": "msg_1",
    "role": "assistant",
    "status": "completed",
    "content": [{"type": "output_text", "text": "Paying the bill.", "annotations": []}],
}


def _body(output, **over):
    body = {
        "id": "resp_abc",
        "object": "response",
        "created_at": 1714502400,
        "status": "completed",
        "model": "muse-spark-1.3",
        "error": None,
        "output": output,
        "parallel_tool_calls": True,
        "tool_choice": "auto",
        "tools": [],
        "usage": {
            "input_tokens": 69,
            "input_tokens_details": {"cached_tokens": 0},
            "output_tokens": 163,
            "output_tokens_details": {"reasoning_tokens": 120},
            "total_tokens": 232,
        },
    }
    body.update(over)
    return body


class _Server:
    def __init__(self, status=200, body=None, headers=None, raw=None):
        self.status = status
        self.body = body
        self.raw = raw
        self.headers = {"x-request-id": "req-77"} if headers is None else headers
        self.requests = []

    def __call__(self, request):
        self.requests.append(request)
        content = self.raw if self.raw is not None else json.dumps(self.body).encode()
        headers = dict(self.headers, **{"content-type": "application/json"})
        return httpx2.Response(self.status, headers=headers, content=content)

    def client(self, clock=None):
        http = httpx2.Client(transport=httpx2.MockTransport(self))
        ticks = iter([10.0, 10.25])
        return MetaClient(
            "sk-test",
            http_client=http,
            max_retries=0,
            clock=clock or (lambda: next(ticks)),
        )


def test_request_shape_is_stateless_encrypted_replay():
    server = _Server(body=_body([REASONING, CALL]))
    tools = (
        {
            "type": "function",
            "name": "pay_bill",
            "description": "Pay a bill.",
            "parameters": {"type": "object", "properties": {}},
        },
    )
    server.client().respond(
        "muse-spark-1.3",
        [{"role": "user", "content": "pay"}],
        tools=tools,
        instructions="be exact",
        effort="high",
    )
    request = server.requests[0]
    sent = json.loads(request.content)
    assert str(request.url) == f"{DEFAULT_BASE_URL}/responses"
    assert request.headers["authorization"] == "Bearer sk-test"
    assert sent["model"] == "muse-spark-1.3"
    assert sent["store"] is False
    assert sent["include"] == ["reasoning.encrypted_content"]
    assert sent["reasoning"] == {"effort": "high"}
    assert sent["tools"] == [tools[0]]
    assert sent["instructions"] == "be exact"
    assert "previous_response_id" not in sent


def test_response_parsed_and_traced():
    server = _Server(body=_body([REASONING, CALL, MESSAGE]))
    resp = server.client().respond("muse-spark-1.3", "pay")
    assert resp.trace.model == "muse-spark-1.3"
    assert resp.trace.response_id == "resp_abc"
    assert resp.trace.request_id == "req-77"
    assert resp.trace.latency_ms == 250.0
    assert (resp.trace.input_tokens, resp.trace.output_tokens) == (69, 163)
    assert [i["encrypted_content"] for i in resp.reasoning_items] == [
        "Q-PaENCRYPTEDblob"
    ]
    assert [(c["name"], c["call_id"]) for c in resp.function_calls] == [
        ("pay_bill", "call_1")
    ]
    assert resp.text == "Paying the bill."
    assert [i["type"] for i in resp.output] == ["reasoning", "function_call", "message"]


def test_missing_request_id_header_is_none():
    server = _Server(body=_body([MESSAGE]), headers={})
    assert server.client().respond("m", "x").trace.request_id is None


@pytest.mark.parametrize(
    ("server", "match"),
    [
        (_Server(status=401, body={"error": {"message": "bad key"}}), "HTTP 401"),
        (_Server(body=_body([], status="failed")), "status failed"),
        (_Server(body=_body([], error={"code": "x", "message": "boom"})), "boom"),
        (_Server(raw=b"not json"), "undecodable"),
    ],
)
def test_errors_raise(server, match):
    with pytest.raises(MetaAPIError, match=match):
        server.client().respond("m", "x")


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


def test_reasoning_commitment_rejects_newline_blobs():
    item = {"type": "reasoning", "encrypted_content": "a\nb"}
    with pytest.raises(ValueError, match="without newlines"):
        reasoning_commitment([item])


def test_api_key_from_env():
    assert api_key_from_env({"MODEL_API_KEY": "a", "META_API_KEY": "b"}) == "a"
    assert api_key_from_env({"META_API_KEY": "b"}) == "b"
    with pytest.raises(KeyError, match="MODEL_API_KEY or META_API_KEY"):
        api_key_from_env({})


@pytest.mark.live
def test_live_meta_call_commits_reasoning():
    try:
        key = api_key_from_env(dict(os.environ))
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


def test_respond_sends_text_format():
    server = _Server(body=_body([MESSAGE]))
    fmt = {"type": "json_schema", "name": "x", "strict": True, "schema": {}}
    server.client().respond("muse-spark-1.3", "hi", text_format=fmt)
    assert json.loads(server.requests[0].content)["text"] == {"format": fmt}


def test_respond_omits_text_format_by_default():
    server = _Server(body=_body([MESSAGE]))
    server.client().respond("muse-spark-1.3", "hi")
    assert "text" not in json.loads(server.requests[0].content)
