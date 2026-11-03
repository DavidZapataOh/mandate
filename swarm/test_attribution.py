import json

from gate.events import DecisionEvent
from gate.policy import Verdict
from gate.shim import Mode
from swarm.attacker import AttackerTrace
from swarm.attribution import (
    Attribution,
    event_v2_json,
    from_attacker,
    from_hook,
    from_trace,
)
from swarm.hookio import ToolCall
from swarm.meta_client import MetaTrace

ANCHOR_1 = "ecdf64cc119eedfb70667704cdb4f24c8c26cdfee47d2f628fd095dc2ab139f6"
TRACE = MetaTrace("muse-spark-1.3", "resp_1", "req-1", 4960.4, 3215, 251)
EVENT = DecisionEvent(
    v=1,
    event_id="evt:n1",
    ts=1800000000,
    mode=Mode.ENFORCE,
    verdict=Verdict.MET,
    action_hash="h1",
    policy_id="payments",
    cert_jti="jti-1",
    reason="ok: executed",
    latency_us=61.0,
)
V1 = (
    '{"v":1,"id":"evt:n1","ts":1800000000,"mode":"ENFORCE","verdict":"MET",'
    '"action":"h1","policy":"payments","cert":"jti-1","reason":"ok: executed",'
    '"lat_us":61.0}'
)


def test_attribution_from_trace():
    assert from_trace(TRACE, ANCHOR_1) == Attribution(
        provider="meta-model-api",
        model="muse-spark-1.3",
        response_id="resp_1",
        request_id="req-1",
        latency_ms=4960.4,
        input_tokens=3215,
        output_tokens=251,
        anchor=ANCHOR_1,
    )


def test_attribution_from_trace_keeps_missing_ids():
    trace = MetaTrace("muse-spark-1.3", "resp_1", None, 1.0, 1, 1)
    assert from_trace(trace, None).request_id is None


def test_v2_wraps_v1_unchanged():
    text = event_v2_json(EVENT, from_trace(TRACE, ANCHOR_1))
    assert text == (
        '{"v":2,"event":' + V1 + ',"meta":{"provider":"meta-model-api",'
        '"model":"muse-spark-1.3","response_id":"resp_1","request_id":"req-1",'
        '"latency_ms":4960.4,"input_tokens":3215,"output_tokens":251,'
        '"anchor":"' + ANCHOR_1 + '"}}'
    )
    assert EVENT.to_json() == V1
    assert json.loads(text)["event"] == json.loads(V1)


def test_v2_without_attribution():
    assert event_v2_json(EVENT, None) == '{"v":2,"event":' + V1 + ',"meta":null}'


def test_attack_attribution_keeps_provider():
    fallback = AttackerTrace("meta-fallback", "muse-spark-1.3", "r-9", 812.0)
    assert from_attacker(fallback) == Attribution(
        "meta-fallback", "muse-spark-1.3", None, "r-9", 812.0, None, None, None
    )


def test_hook_attribution():
    call = ToolCall("child-1", "edit_file", {}, "/w", "muse-spark-1.3", "call_7")
    assert from_hook(call) == Attribution(
        "muse-code", "muse-spark-1.3", None, "call_7", None, None, None, None
    )
