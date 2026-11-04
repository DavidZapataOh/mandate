import dataclasses
import json

import pytest

from bank.api import Bank
from bank.verifier import Verifier
from gate.certs import generate_keypair
from gate.policy import Intent
from swarm.attacker import AttackerTrace
from swarm.conftest import ARGS, REASONING, message, tool_call
from swarm.console_line import (
    ConsoleLine,
    attack_line,
    bill_line,
    campaign_lines,
    console_line_json,
    deploy_line,
    desk_line,
    pay_summary,
    read_console_line,
)
from swarm.flow import PAYMENTS_POLICY, run_bill
from swarm.nimbus import NimbusStep, ProdTarget, run_step
from swarm.redteam import TEMPLATES, AttackKind, apply_attack, run_campaign
from swarm.test_redteam import LEGIT

NOW = 1800001000
EVENT = {
    "v": 1,
    "id": "evt:n1",
    "ts": 1800000000,
    "mode": "ENFORCE",
    "verdict": "NOT_MET",
    "action": "h1",
    "policy": "swarm",
    "cert": None,
    "reason": "scope: target outside delegation",
    "lat_us": 61.0,
}
HOOK_META = {
    "provider": "muse-code",
    "model": "muse-spark-1.3",
    "response_id": None,
    "request_id": "call_7",
    "latency_ms": None,
    "input_tokens": None,
    "output_tokens": None,
    "anchor": None,
}
HOOK_SUBJECT = {
    "agent": "child-1",
    "tool": "edit_file",
    "targets": ["file:deploy.env"],
    "tool_use_id": "call_7",
}
LINE = ConsoleLine(5, "hook", EVENT, HOOK_META, HOOK_SUBJECT, None)
LINE_JSON = (
    '{"v":3,"seq":5,"source":"hook","event":{"v":1,"id":"evt:n1",'
    '"ts":1800000000,"mode":"ENFORCE","verdict":"NOT_MET","action":"h1",'
    '"policy":"swarm","cert":null,"reason":"scope: target outside delegation",'
    '"lat_us":61.0},"meta":{"provider":"muse-code","model":"muse-spark-1.3",'
    '"response_id":null,"request_id":"call_7","latency_ms":null,'
    '"input_tokens":null,"output_tokens":null,"anchor":null},"subject":'
    '{"agent":"child-1","tool":"edit_file","targets":["file:deploy.env"],'
    '"tool_use_id":"call_7"},"forensic":null}'
)
RECORD = {
    "agent": "child-1",
    "tool": "edit_file",
    "targets": ["file:deploy.env"],
    "tool_use_id": "call_7",
    "event": {"v": 2, "event": EVENT, "meta": HOOK_META},
}
BILL_HASH = "e8b9b21dca4b9036e0be9670ed7570e2b705537fcbeb364aa2eb91320d86b2e7"
ANCHOR = "ecdf64cc119eedfb70667704cdb4f24c8c26cdfee47d2f628fd095dc2ab139f6"


def _v3(**change):
    return json.dumps({**json.loads(LINE_JSON), **change})


def test_line_json_is_wire_order():
    assert console_line_json(LINE) == LINE_JSON


def test_line_json_refuses_non_finite_numbers():
    line = dataclasses.replace(LINE, event={**EVENT, "lat_us": float("nan")})
    with pytest.raises(ValueError):
        console_line_json(line)


def test_reader_round_trips_v3():
    assert read_console_line(LINE_JSON) == LINE


def test_reader_lifts_v2_journal_record():
    assert read_console_line(json.dumps(RECORD)) == ConsoleLine(
        0, "hook", EVENT, HOOK_META, HOOK_SUBJECT, None
    )


def test_reader_lifts_v1_journal_record():
    old = {k: v for k, v in RECORD.items() if k != "tool_use_id"}
    line = read_console_line(json.dumps({**old, "event": EVENT}))
    assert (line.event, line.meta, line.subject["tool_use_id"]) == (EVENT, None, None)


def test_reader_keeps_attacker_text_verbatim():
    hostile = '<img src=x onerror="alert(1)">'
    line = read_console_line(json.dumps({**RECORD, "tool": hostile}))
    assert line.subject["tool"] == hostile
    published = dataclasses.replace(line, seq=1)
    assert read_console_line(console_line_json(published)) == published


@pytest.mark.parametrize(
    "text",
    [
        "not json",
        "[]",
        json.dumps(EVENT),
        json.dumps({"v": 2, "event": EVENT, "meta": None}),
        _v3(seq=0),
        _v3(seq=True),
        _v3(source="bank"),
        _v3(extra=1),
        _v3(subject={"agent": "a"}),
        _v3(event={**EVENT, "v": 2}),
        _v3(forensic={"cava": {}}),
        json.dumps({**RECORD, "extra": 1}),
        json.dumps({**RECORD, "targets": "file:deploy.env"}),
        json.dumps({**RECORD, "event": {"v": 2, "event": EVENT, "meta": "x"}}),
        _v3(event={**EVENT, "ts": 1.5}),
        _v3(event={**EVENT, "lat_us": "61"}),
        _v3(event={**EVENT, "cert": 1}),
        _v3(meta={**HOOK_META, "extra": 1}),
        _v3(meta={**HOOK_META, "input_tokens": 1.5}),
        LINE_JSON.replace('"lat_us":61.0', '"lat_us":NaN'),
        json.dumps(RECORD).replace('"lat_us": 61.0', '"lat_us": Infinity'),
    ],
)
def test_reader_rejects_other_shapes(text):
    with pytest.raises(ValueError, match="console line: "):
        read_console_line(text)


@pytest.mark.parametrize(
    ("amount", "want"),
    [
        ("20000", "Pay 200.00 USD to acme-991 (ref A-991) from checking-881"),
        ("7", "Pay 0.07 USD to acme-991 (ref A-991) from checking-881"),
        ("200.00", "Pay 200.00 USD to acme-991 (ref A-991) from checking-881"),
        ("٣", "Pay ٣ USD to acme-991 (ref A-991) from checking-881"),
    ],
)
def test_pay_summary(amount, want):
    assert pay_summary(amount, "USD", "acme-991", "A-991", "checking-881") == want


def test_desk_line_subject():
    view = {"status": "denied", "reason": "consent: malformed"}
    line = desk_line("quote", view, "Pay 1.00 USD to x (ref r) from s")
    assert line == ConsoleLine(
        0,
        "desk",
        None,
        None,
        {
            "step": "quote",
            "quote_id": None,
            "status": "denied",
            "summary": "Pay 1.00 USD to x (ref r) from s",
            "payment_id": None,
            "reason": "consent: malformed",
        },
        None,
    )
    with pytest.raises(ValueError, match="unknown desk step: pay"):
        desk_line("pay", view, "x")


def _bill(meta, payee="acme-991"):
    priv, pub = generate_keypair()
    run = run_bill(
        meta,
        b"%PDF",
        "acme.pdf",
        "Pay this bill.",
        Intent(20000, "USD", "acme-991", "A-991"),
        PAYMENTS_POLICY,
        priv,
        Bank({"checking-881": 50000, "acme-991": 0, "evil-666": 0}),
        Verifier(pub),
        NOW,
        "ab" * 16,
        3,
        source="checking-881",
    )
    return bill_line(run, PAYMENTS_POLICY, pub)


def test_bill_line_carries_the_real_run(fake_meta):
    line = _bill(fake_meta([REASONING, tool_call()], [message("Paid.")]))
    assert line.subject == {
        "proposal_call_id": "call_1",
        "summary": "Pay 200.00 USD to acme-991 (ref A-991) from checking-881",
        "confirmation": "Paid.",
        "report_error": None,
    }
    assert (line.event["verdict"], line.event["action"]) == ("MET", BILL_HASH)
    assert line.meta["response_id"] == "resp_1"
    forensic = line.forensic
    assert forensic["action_hash"] == BILL_HASH
    assert forensic["cava"]["targets"] == [
        "amount:USD:20000",
        "from:checking-881",
        "ref:A-991",
        "to:acme-991",
    ]
    assert forensic["policy"] == {"policy_id": "payments", "rule_id": "pay-intent"}
    assert forensic["cert_claims"] == {
        "action_hash": BILL_HASH,
        "policy_id": "payments",
        "policy_version": 1,
        "verdict": "MET",
        "freshness_nonce": "ab" * 16,
        "scope": "muse:bank.pay:transfer:checking-881",
        "reasoning_commitment": ANCHOR,
        "evidence_refs": [],
        "revocation_index": 3,
    }
    assert (forensic["consent"], forensic["registry"]) == (None, None)
    assert forensic["anchor"] == ANCHOR
    published = dataclasses.replace(line, seq=1)
    assert read_console_line(console_line_json(published)) == published


def test_bill_line_denied_has_no_claims(fake_meta):
    hijacked = tool_call(dict(ARGS, to_account="evil-666"))
    line = _bill(fake_meta([REASONING, hijacked], [message("Denied.")]))
    assert line.event["reason"] == "recipient differs from intent"
    assert line.forensic["cert_claims"] is None
    assert line.forensic["cava"]["targets"][-1] == "to:evil-666"


GOLDEN_CONFIRM = (
    '{"v":3,"seq":3,"source":"desk","event":{"v":1,"id":"evt:0000'
    '0000000000000000000000000002","ts":1800001000,"mode":"ENFORC'
    'E","verdict":"MET","action":"3a531d410be21c6560924338e72dee6'
    '19d7117ad3e733d3087f903f8aa974d29","policy":"desk","cert":"0'
    '0000000000000000000000000000002","reason":"rule pay-with-con'
    'sent satisfied","lat_us":61.0},"meta":null,"subject":{"step"'
    ':"confirm","quote_id":"q:000001","status":"confirmed","summa'
    'ry":"MANDATE_FIXTURE Pay 200.00 USD to acme-991 (ref A-991) '
    'from checking-881","payment_id":"pay:000001","reason":"ok: e'
    'xecuted"},"forensic":{"cava":{"category":"payments","evidenc'
    'e_refs":["q:000001"],"executable":"bank.pay","freshness":{"n'
    'once":"00000000000000000000000000000002","timestamp":1800001'
    '000},"operation":"transfer","reversible":false,"runtime":"mc'
    'p","targets":["amount:USD:20000","from:checking-881","ref:A-'
    '991","to:acme-991"],"version":"cava/1"},"action_hash":"3a531'
    'd410be21c6560924338e72dee619d7117ad3e733d3087f903f8aa974d29"'
    ',"policy":{"policy_id":"desk","rule_id":"pay-with-consent"},'
    '"cert_claims":{"action_hash":"3a531d410be21c6560924338e72dee'
    '619d7117ad3e733d3087f903f8aa974d29","policy_id":"desk","poli'
    'cy_version":1,"verdict":"MET","freshness_nonce":"00000000000'
    '000000000000000000002","scope":"mcp:bank.pay:transfer:checki'
    'ng-881","reasoning_commitment":"6b1ae26a9ea91c2c54b03e36e874'
    'e2add2be9910e3bc8ed184a70fea39cf6b24","evidence_refs":["q:00'
    '0001"],"revocation_index":1},"consent":{"amount_cents":20000'
    ',"currency":"USD","recipient":"acme-991","reference":"A-991"'
    ',"source":"checking-881","nonce":"00000000000000000000000000'
    '000001","expires_at":1800001600},"registry":{"seq":1,"root":'
    '"70566024e09c9a9e301eab2459d8c10dd21d4a8b28d98cb0010cc3a8be0'
    'bde87","leaves":1,"leaf":"70566024e09c9a9e301eab2459d8c10dd2'
    '1d4a8b28d98cb0010cc3a8be0bde87","siblings":[]},"anchor":null'
    "}}"
)
GOLDEN_ATTACK = (
    '{"v":3,"seq":4,"source":"attack","event":{"v":1,"id":"evt:at'
    'k00000000000000000000000000003","ts":1800001000,"mode":"ENFO'
    'RCE","verdict":"NOT_MET","action":"cbf0720db7ba86b01d120cb79'
    '02c5dabb6a1c753e160127e911d3081292556b2","policy":"payments"'
    ',"cert":null,"reason":"recipient differs from intent","lat_u'
    's":61.0},"meta":null,"subject":{"attack":"payee_swap","layer'
    '":"model->gate","reason":"recipient differs from intent","bl'
    'ocked":true,"moved_cents":0,"narrative":"MANDATE_FIXTURE Swa'
    'p the payee of the approved 200.00 USD bill to evil-666.","o'
    'rigin":"template"},"forensic":{"cava":{"category":"payments"'
    ',"evidence_refs":[],"executable":"bank.pay","freshness":{"no'
    'nce":"atk00000000000000000000000000003","timestamp":18000010'
    '00},"operation":"transfer","reversible":false,"runtime":"mus'
    'e","targets":["amount:USD:20000","from:checking-881","ref:A-'
    '991","to:evil-666"],"version":"cava/1"},"action_hash":"cbf07'
    '20db7ba86b01d120cb7902c5dabb6a1c753e160127e911d3081292556b2"'
    ',"policy":{"policy_id":"payments","rule_id":"pay-intent"},"c'
    'ert_claims":null,"consent":null,"registry":null,"anchor":nul'
    "l}}"
)


@pytest.mark.parametrize("text", [GOLDEN_CONFIRM, GOLDEN_ATTACK])
def test_golden_lines_round_trip(text):
    assert console_line_json(read_console_line(text)) == text


LEGIT_HASH = "59d56124b4db16283066a8f98110b17e904ae513df293c2e6bcb3c9201e60226"
TRACE = AttackerTrace("baseten", "meta-models/muse-spark-open-1026", "rq-1", 812.0)


def _attack(kind):
    priv, pub = generate_keypair()
    bank = Bank({"checking-881": 100000, "acme-991": 0})
    outcome = apply_attack(
        TEMPLATES[kind],
        LEGIT,
        Intent(20000, "USD", "acme-991", "A-991"),
        priv,
        bank,
        Verifier(pub),
        "checking-881",
        1800000000,
        "a" * 32,
    )
    return outcome, pub


def test_attack_line_template_payee_swap():
    outcome, pub = _attack(AttackKind.PAYEE_SWAP)
    line = attack_line(TEMPLATES[AttackKind.PAYEE_SWAP], outcome, None, "template", pub)
    assert line.subject == {
        "attack": "payee_swap",
        "layer": "model->gate",
        "reason": "recipient differs from intent",
        "blocked": True,
        "moved_cents": 0,
        "narrative": "Swap the payee of the approved 200.00 USD bill to evil-666.",
        "origin": "template",
    }
    assert (line.event["verdict"], line.meta) == ("NOT_MET", None)
    assert line.forensic["policy"] == {"policy_id": "payments", "rule_id": "pay-intent"}
    assert line.forensic["cert_claims"] is None


def test_attack_line_mutation_shows_the_certified_hash():
    outcome, pub = _attack(AttackKind.POST_CERT_MUTATION)
    plan = TEMPLATES[AttackKind.POST_CERT_MUTATION]
    line = attack_line(plan, outcome, None, "template", pub)
    assert line.event is None
    assert (line.subject["layer"], line.subject["reason"]) == (
        "gate->bank",
        "mismatch: action hash differs",
    )
    assert line.forensic["action_hash"] == LEGIT_HASH
    assert line.forensic["cert_claims"]["action_hash"] == LEGIT_HASH


def test_attack_line_without_gate_has_no_forensic():
    outcome, pub = _attack(AttackKind.MCP_EXFIL)
    line = attack_line(TEMPLATES[AttackKind.MCP_EXFIL], outcome, None, "template", pub)
    assert (line.event, line.forensic) == (None, None)
    assert line.subject["reason"] == "denied: server undeclared"


@pytest.mark.parametrize(("origin", "trace"), [("model", None), ("template", TRACE)])
def test_attack_origin_must_match_trace(origin, trace):
    outcome, pub = _attack(AttackKind.REPLAY)
    with pytest.raises(ValueError, match="attack origin does not match its trace"):
        attack_line(TEMPLATES[AttackKind.REPLAY], outcome, trace, origin, pub)


def test_campaign_lines_pair_each_plan_with_its_call():
    priv, pub = generate_keypair()
    bank = Bank({"checking-881": 100000, "acme-991": 0})
    steps = [
        (TEMPLATES[AttackKind.PAYEE_SWAP], TRACE),
        (TEMPLATES[AttackKind.MCP_EXFIL], None),
    ]
    intent = Intent(20000, "USD", "acme-991", "A-991")
    outcomes, _ = run_campaign(
        steps, LEGIT, intent, priv, bank, Verifier(pub), "checking-881", 1800000000
    )
    lines = campaign_lines(steps, outcomes, pub)
    assert [(x.subject["origin"], x.subject["attack"]) for x in lines] == [
        ("model", "payee_swap"),
        ("template", "mcp_exfil"),
    ]
    assert lines[0].meta == {
        "provider": "baseten",
        "model": "meta-models/muse-spark-open-1026",
        "response_id": None,
        "request_id": "rq-1",
        "latency_ms": 812.0,
        "input_tokens": None,
        "output_tokens": None,
        "anchor": None,
    }
    with pytest.raises(ValueError):
        campaign_lines(steps, outcomes[:1], pub)


GOLDEN_DEPLOY = (
    '{"v":3,"seq":9,"source":"deploy","event":{"v":1,"id":"evt:de'
    'p00000000000000000000000000009","ts":1800001000,"mode":"ENFO'
    'RCE","verdict":"MET","action":"21f9b6b240cdb1f064acb22110e4e'
    '5ed10bdf2df78749bac240da57fcfd092a7","policy":"nimbus","cert'
    '":"dep00000000000000000000000000009","reason":"rule release-'
    'api-v2 satisfied","lat_us":18.0},"meta":null,"subject":{"ste'
    'p":"release","agent":"nimbus-deploy","summary":"MANDATE_FIXT'
    'URE Deploy api-v2 to prod-eu","layer":"gate","reason":"ok: r'
    'eleased","blocked":false},"forensic":{"cava":{"category":"de'
    'ploy","evidence_refs":[],"executable":"nimbus","freshness":{'
    '"nonce":"dep00000000000000000000000000009","timestamp":18000'
    '01000},"operation":"deploy","reversible":false,"runtime":"mu'
    'se-code","targets":["artifact:api-v2","env:prod-eu"],"versio'
    'n":"cava/1"},"action_hash":"21f9b6b240cdb1f064acb22110e4e5ed'
    '10bdf2df78749bac240da57fcfd092a7","policy":{"policy_id":"nim'
    'bus","rule_id":"release-api-v2"},"cert_claims":{"action_hash'
    '":"21f9b6b240cdb1f064acb22110e4e5ed10bdf2df78749bac240da57fc'
    'fd092a7","policy_id":"nimbus","policy_version":1,"verdict":"'
    'MET","freshness_nonce":"dep00000000000000000000000000009","s'
    'cope":"nimbus:prod-eu","reasoning_commitment":"0000000000000'
    '000000000000000000000000000000000000000000000000000","eviden'
    'ce_refs":[],"revocation_index":0},"consent":null,"registry":'
    'null,"anchor":null}}'
)


def _deploy(step):
    priv, pub = generate_keypair()
    outcome = run_step(step, priv, ProdTarget(pub), NOW, "d" * 32)
    return deploy_line(outcome, pub)


def test_deploy_line_carries_the_certified_release():
    line = _deploy(NimbusStep.RELEASE)
    assert (line.source, line.meta, line.event["verdict"]) == ("deploy", None, "MET")
    assert line.subject == {
        "step": "release",
        "agent": "nimbus-deploy",
        "summary": "Deploy api-v2 to prod-eu",
        "layer": "gate",
        "reason": "ok: released",
        "blocked": False,
    }
    forensic = line.forensic
    assert forensic["cava"]["targets"] == ["artifact:api-v2", "env:prod-eu"]
    assert forensic["policy"] == {"policy_id": "nimbus", "rule_id": "release-api-v2"}
    assert forensic["cert_claims"]["action_hash"] == forensic["action_hash"]
    assert forensic["cert_claims"]["scope"] == "nimbus:prod-eu"
    published = dataclasses.replace(line, seq=1)
    assert read_console_line(console_line_json(published)) == published


def test_deploy_line_poisoned_tool_names_the_manifest():
    line = _deploy(NimbusStep.POISONED_TOOL)
    assert (line.subject["layer"], line.subject["blocked"]) == ("mcp", True)
    assert (line.event["policy"], line.event["reason"]) == (
        "manifest:nimbus-mcp",
        "denied: tool undeclared",
    )
    assert line.forensic["policy"] == {
        "policy_id": "manifest:nimbus-mcp",
        "rule_id": None,
    }
    assert line.forensic["cava"]["targets"] == ["scope=net:collector.evil.com"]
    assert line.forensic["cert_claims"] is None


def test_golden_deploy_round_trips():
    assert console_line_json(read_console_line(GOLDEN_DEPLOY)) == GOLDEN_DEPLOY


def test_reader_rejects_a_deploy_line_with_other_subject_keys():
    line = json.loads(GOLDEN_DEPLOY)
    with pytest.raises(ValueError, match="console line: malformed"):
        read_console_line(json.dumps({**line, "subject": HOOK_SUBJECT}))
