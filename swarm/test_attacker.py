import json

import httpx2
import pytest
from openai import OpenAI

from swarm.attacker import (
    ATTACKER_PREAMBLE,
    BASETEN_BASE_URL,
    OPEN_MODEL,
    Attacker,
    attacker_from_env,
)
from swarm.meta_client import MetaClient
from swarm.redteam import AttackKind, AttackPlan
from swarm.test_meta_client import _body
from swarm.test_redteam import LEGIT

PLAN_TEXT = json.dumps(
    {"kind": "payee_swap", "params": {"to": "evil-666"}, "narrative": "Swap it."}
)


def _completion(content):
    return {
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "created": 1793673457,
        "model": OPEN_MODEL,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 210, "completion_tokens": 30, "total_tokens": 240},
    }


def _client(status, body, seen, request_id="b-1"):
    def handler(request):
        seen.append(request)
        return httpx2.Response(
            status,
            headers={"content-type": "application/json", "x-request-id": request_id},
            content=json.dumps(body).encode(),
        )

    return httpx2.Client(transport=httpx2.MockTransport(handler))


def test_baseten_request_shape_and_plan():
    seen = []
    attacker = attacker_from_env(
        {"BASETEN_API_KEY": "bt"}, _client(200, _completion(PLAN_TEXT), seen)
    )
    plan, trace, text = attacker.next_plan(AttackKind.PAYEE_SWAP, LEGIT)
    request = seen[0]
    sent = json.loads(request.content)
    assert str(request.url) == f"{BASETEN_BASE_URL}/chat/completions"
    assert request.headers["authorization"] == "Bearer bt"
    assert sent["model"] == "meta-models/muse-spark-open-1026"
    assert sent["messages"][0] == {"role": "developer", "content": ATTACKER_PREAMBLE}
    assert json.loads(sent["messages"][1]["content"])["kind"] == "payee_swap"
    assert plan == AttackPlan(AttackKind.PAYEE_SWAP, {"to": "evil-666"}, "Swap it.")
    assert (trace.provider, trace.model, trace.request_id) == (
        "baseten",
        "meta-models/muse-spark-open-1026",
        "b-1",
    )
    assert text == PLAN_TEXT


def test_attacker_falls_back_to_meta_labeled():
    seen = []
    body = _body(
        [
            {
                "type": "message",
                "id": "msg_1",
                "role": "assistant",
                "status": "completed",
                "content": [
                    {"type": "output_text", "text": PLAN_TEXT, "annotations": []}
                ],
            }
        ]
    )
    attacker = attacker_from_env({"META_API_KEY": "mk"}, _client(200, body, seen))
    plan, trace, _ = attacker.next_plan(AttackKind.PAYEE_SWAP, LEGIT)
    assert str(seen[0].url) == "https://api.meta.ai/v1/responses"
    assert (trace.provider, trace.model) == ("meta-fallback", "muse-spark-1.3")
    assert plan is not None


def test_attacker_http_error_is_recorded():
    attacker = attacker_from_env(
        {"BASETEN_API_KEY": "bt"},
        _client(429, {"error": "rate"}, [], request_id="b-429"),
    )
    plan, trace, text = attacker.next_plan(AttackKind.REPLAY, LEGIT)
    assert plan is None
    assert text == "error: baseten HTTP 429"
    assert trace.provider == "baseten"
    assert trace.request_id == "b-429"


def test_attacker_network_error_is_recorded():
    def handler(request):
        raise httpx2.ConnectError("down")

    client = httpx2.Client(transport=httpx2.MockTransport(handler))
    attacker = attacker_from_env({"BASETEN_API_KEY": "bt"}, client)
    plan, trace, text = attacker.next_plan(AttackKind.REPLAY, LEGIT)
    assert plan is None
    assert text.startswith("error: baseten")
    assert trace.provider == "baseten"


def test_next_plan_rejects_kind_mismatch():
    attacker = attacker_from_env(
        {"BASETEN_API_KEY": "bt"}, _client(200, _completion(PLAN_TEXT), [])
    )
    plan, _, text = attacker.next_plan(AttackKind.REPLAY, LEGIT)
    assert plan is None
    assert text == "plan: kind mismatch"


def test_next_plan_rejects_non_attack():
    same = json.dumps(
        {"kind": "payee_swap", "params": {"to": "acme-991"}, "narrative": "Same."}
    )
    attacker = attacker_from_env(
        {"BASETEN_API_KEY": "bt"}, _client(200, _completion(same), [])
    )
    plan, _, text = attacker.next_plan(AttackKind.PAYEE_SWAP, LEGIT)
    assert plan is None
    assert text == "plan: not an attack"


def test_parse_failure_includes_raw_prefix():
    attacker = attacker_from_env(
        {"BASETEN_API_KEY": "bt"}, _client(200, _completion("hello " * 100), [])
    )
    plan, _, text = attacker.next_plan(AttackKind.REPLAY, LEGIT)
    assert plan is None
    assert text == "plan: not JSON | raw: " + ("hello " * 100)[:200]


def test_trace_records_served_model_and_max_tokens():
    seen = []
    body = _completion(PLAN_TEXT)
    body["model"] = "meta-models/muse-spark-open-1026-served"
    attacker = attacker_from_env({"BASETEN_API_KEY": "bt"}, _client(200, body, seen))
    _, trace, _ = attacker.next_plan(AttackKind.PAYEE_SWAP, LEGIT)
    assert json.loads(seen[0].content)["max_tokens"] == 4096
    assert trace.model == "meta-models/muse-spark-open-1026-served"


def test_provider_must_match_client():
    sdk = OpenAI(api_key="k", base_url=BASETEN_BASE_URL)
    with pytest.raises(ValueError):
        Attacker("meta-fallback", "m", sdk=sdk)
    with pytest.raises(ValueError):
        Attacker("baseten", "m", meta=MetaClient("k"))


def test_attacker_needs_a_key():
    with pytest.raises(KeyError, match="set BASETEN_API_KEY or a Meta key"):
        attacker_from_env({})
