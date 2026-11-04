import dataclasses
import json
import re
from pathlib import Path

import pytest

from bank.api import Bank
from bank.events import BankEvent
from bank.verifier import Verifier
from gate.cava import CavaAction, Freshness
from gate.certs import generate_keypair
from gate.consent import Consent, HolderApproval, with_approval
from gate.policy import Intent
from swarm.attacker import AttackerTrace
from swarm.conftest import ARGS, REASONING, message, tool_call
from swarm.console_line import (
    ConsoleLine,
    attack_line,
    bank_line,
    bill_line,
    campaign_lines,
    console_line_json,
    deploy_line,
    desk_line,
    forensic_of,
    pay_summary,
    read_console_line,
)
from swarm.desk import DESK_POLICY
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
BILL_HASH = "7be939b82f874115ed893c48ce2d1e8c53e54d737511915020cc10406073e0bc"
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
        _v3(source="teller"),
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
        salt=b"\xb1" * 32,
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
    assert (forensic["bank"]["rail"], forensic["bank"]["transfer_id"]) == (
        "simulated",
        "pay:000001",
    )
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
        "scope": "muse:bank.pay:transfer",
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
    assert line.forensic["bank"] is None
    assert line.forensic["cava"]["targets"][-1] == "to:evil-666"


GOLDEN_CONFIRM = (
    '{"v":3,"seq":3,"source":"desk","event":{"v":1,"id":"evt:00000'
    '000000000000000000000000002","ts":1800001000,"mode":"ENFORCE"'
    ',"verdict":"MET","action":"52e9b189b7db1f410229e8bb9a3a4a99d3'
    '4e30523c3507480821839a3845069b","policy":"desk","cert":"00000'
    '000000000000000000000000002","reason":"rule pay-with-consent '
    'satisfied","lat_us":61.0},"meta":null,"subject":{"step":"conf'
    'irm","quote_id":"q:000001","status":"confirmed","summary":"MA'
    "NDATE_FIXTURE Pay 200.00 USD to acme-991 (ref A-991) from che"
    'cking-881","payment_id":"pay:000001","reason":"ok: executed"}'
    ',"forensic":{"cava":{"category":"payments","evidence_refs":["'
    'q:000001"],"executable":"bank.pay","freshness":{"nonce":"0000'
    '0000000000000000000000000002","timestamp":1800001000},"operat'
    'ion":"transfer","reversible":false,"runtime":"mcp","targets":'
    '["amount:USD:20000","from:checking-881","ref:A-991","to:acme-'
    '991"],"version":"cava/1"},"action_hash":"52e9b189b7db1f410229'
    'e8bb9a3a4a99d34e30523c3507480821839a3845069b","policy":{"poli'
    'cy_id":"desk","rule_id":"pay-with-consent"},"cert_claims":{"a'
    'ction_hash":"52e9b189b7db1f410229e8bb9a3a4a99d34e30523c350748'
    '0821839a3845069b","policy_id":"desk","policy_version":1,"verd'
    'ict":"MET","freshness_nonce":"0000000000000000000000000000000'
    '2","scope":"mcp:bank.pay:transfer","reasoning_commitment":"6b'
    "1ae26a9ea91c2c54b03e36e874e2add2be9910e3bc8ed184a70fea39cf6b2"
    '4","evidence_refs":["q:000001"],"revocation_index":1},"consen'
    't":{"amount_cents":20000,"currency":"USD","recipient":"acme-9'
    '91","reference":"A-991","source":"checking-881","nonce":"0000'
    '0000000000000000000000000001","expires_at":1800001600},"regis'
    'try":{"seq":1,"root":"70566024e09c9a9e301eab2459d8c10dd21d4a8'
    'b28d98cb0010cc3a8be0bde87","leaves":1,"leaf":"70566024e09c9a9'
    'e301eab2459d8c10dd21d4a8b28d98cb0010cc3a8be0bde87","siblings"'
    ':[]},"anchor":null,"bank":{"rail":"simulated","provider":null'
    ',"transfer_id":"pay:000001","status":"complete","idempotency'
    '_key":"mandate-cert-00000000000000000000000000000002"}}}'
)
GOLDEN_ATTACK = (
    '{"v":3,"seq":4,"source":"attack","event":{"v":1,"id":"evt:atk'
    '00000000000000000000000000003","ts":1800001000,"mode":"ENFORC'
    'E","verdict":"NOT_MET","action":"89f0357807b9d6e90a1c66d00e2a'
    '058ad97a5370349978a0ddceb67c50653f9a","policy":"payments","ce'
    'rt":null,"reason":"recipient differs from intent","lat_us":61'
    '.0},"meta":null,"subject":{"attack":"payee_swap","layer":"mod'
    'el->gate","reason":"recipient differs from intent","blocked":'
    'true,"moved_cents":0,"narrative":"MANDATE_FIXTURE Swap the pa'
    'yee of the approved 200.00 USD bill to evil-666.","origin":"t'
    'emplate"},"forensic":{"cava":{"category":"payments","evidence'
    '_refs":[],"executable":"bank.pay","freshness":{"nonce":"atk00'
    '000000000000000000000000003","timestamp":1800001000},"operati'
    'on":"transfer","reversible":false,"runtime":"muse","targets":'
    '["amount:USD:20000","from:checking-881","ref:A-991","to:evil-'
    '666"],"version":"cava/1"},"action_hash":"89f0357807b9d6e90a1c'
    '66d00e2a058ad97a5370349978a0ddceb67c50653f9a","policy":{"poli'
    'cy_id":"payments","rule_id":"pay-intent"},"cert_claims":null,'
    '"consent":null,"registry":null,"anchor":null,"bank":null}}'
)


@pytest.mark.parametrize("text", [GOLDEN_CONFIRM, GOLDEN_ATTACK])
def test_golden_lines_round_trip(text):
    assert console_line_json(read_console_line(text)) == text


LEGIT_HASH = "0029231b1a340273bad82f0db02af52eeba8b86380680d4ab9fedbd818719905"
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
        salt=b"\xa1" * 32,
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
    '{"v":3,"seq":9,"source":"deploy","event":{"v":1,"id":"evt:dep'
    '00000000000000000000000000009","ts":1800001000,"mode":"ENFORC'
    'E","verdict":"MET","action":"1be9ccd395f38aeb073d15560b4bdc8b'
    'c07326b8457578c8d5db799b92ccaa01","policy":"nimbus","cert":"d'
    'ep00000000000000000000000000009","reason":"rule release-api-v'
    '2 satisfied","lat_us":18.0},"meta":null,"subject":{"step":"re'
    'lease","agent":"nimbus-deploy","summary":"MANDATE_FIXTURE Dep'
    'loy api-v2 to prod-eu","layer":"gate","reason":"ok: released"'
    ',"blocked":false},"forensic":{"cava":{"category":"deploy","ev'
    'idence_refs":[],"executable":"nimbus","freshness":{"nonce":"d'
    'ep00000000000000000000000000009","timestamp":1800001000},"ope'
    'ration":"deploy","reversible":false,"runtime":"muse-code","ta'
    'rgets":["artifact:api-v2","env:prod-eu"],"version":"cava/1"},'
    '"action_hash":"1be9ccd395f38aeb073d15560b4bdc8bc07326b8457578'
    'c8d5db799b92ccaa01","policy":{"policy_id":"nimbus","rule_id":'
    '"release-api-v2"},"cert_claims":{"action_hash":"1be9ccd395f38'
    'aeb073d15560b4bdc8bc07326b8457578c8d5db799b92ccaa01","policy_'
    'id":"nimbus","policy_version":1,"verdict":"MET","freshness_no'
    'nce":"dep00000000000000000000000000009","scope":"nimbus:prod-'
    'eu","reasoning_commitment":"000000000000000000000000000000000'
    '0000000000000000000000000000000","evidence_refs":[],"revocati'
    'on_index":0},"consent":null,"registry":null,"anchor":null,"b'
    'ank":null}}'
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


def test_attack_line_forged_approval_shows_the_consent_it_refused():
    outcome, pub = _attack(AttackKind.FORGED_APPROVAL)
    plan = TEMPLATES[AttackKind.FORGED_APPROVAL]
    line = attack_line(plan, outcome, None, "template", pub)
    assert (line.subject["layer"], line.subject["reason"]) == (
        "holder->gate",
        "consent: bad signature",
    )
    assert (line.event["verdict"], line.event["reason"]) == (
        "NOT_MET",
        "consent: bad signature",
    )
    assert line.forensic["policy"] == {
        "policy_id": "desk",
        "rule_id": "pay-with-consent",
    }
    assert line.forensic["cava"]["runtime"] == "mcp"
    assert line.forensic["consent"] == {
        "amount_cents": 20000,
        "currency": "USD",
        "recipient": "evil-666",
        "reference": "A-991",
        "source": "checking-881",
        "nonce": "a" * 32,
        "expires_at": 1800000300,
    }
    assert line.forensic["cert_claims"] is None


FIXTURES = Path(__file__).resolve().parent.parent / "console/src/wire/__fixtures__"


@pytest.mark.parametrize(
    ("name", "golden"),
    [
        ("CONFIRM", GOLDEN_CONFIRM),
        ("ATTACK", GOLDEN_ATTACK),
        ("DEPLOY", GOLDEN_DEPLOY),
    ],
)
def test_console_fixtures_are_the_python_goldens(name, golden):
    source = (FIXTURES / "lines.ts").read_text()
    found = re.search(rf"export const {name} =\n  '([^']*)';\n", source)
    assert found is not None
    assert found.group(1) == golden


def test_forensic_consent_is_the_seven_signed_fields():
    _, gate_pub = generate_keypair()
    unsigned = Consent(
        20000, "USD", "acme-991", "A-991", "checking-881", "c0" * 16, 1800001600, b""
    )
    approval = HolderApproval(b"\x01" * 64, b"\x93" * 32, b"\x02" * 64)
    action = CavaAction(
        version="cava/1",
        runtime="mcp",
        executable="bank.pay",
        operation="transfer",
        category="payments",
        targets=("amount:USD:20000", "from:checking-881", "ref:A-991", "to:acme-991"),
        reversible=False,
        freshness=Freshness(nonce="f" * 32, timestamp=NOW),
        evidence_refs=(),
    )
    consent = with_approval(unsigned, approval)
    forensic = forensic_of(
        action, DESK_POLICY, None, gate_pub, consent=consent, salt=None
    )
    assert forensic["consent"] == {
        "amount_cents": 20000,
        "currency": "USD",
        "recipient": "acme-991",
        "reference": "A-991",
        "source": "checking-881",
        "nonce": "c0" * 16,
        "expires_at": 1800001600,
    }
    text = console_line_json(ConsoleLine(1, "desk", None, None, {}, forensic))
    assert "k5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5M" not in text


SANDBOX_VIEW = {
    "rail": "sandbox",
    "provider": "increase",
    "transfer_id": "account_transfer_7k9qe1ysdgqztnt63l7n",
    "status": "complete",
    "idempotency_key": "mandate-cert-00000000000000000000000000000002",
}


@pytest.mark.parametrize(
    "bank",
    [
        {"rail": "real"},
        dict(SANDBOX_VIEW, rail="real"),
        dict(SANDBOX_VIEW, transfer_id=7),
        dict(SANDBOX_VIEW, url="https://example.com"),
        {k: v for k, v in SANDBOX_VIEW.items() if k != "status"},
        "pay:000001",
    ],
)
def test_reader_refuses_a_malformed_bank_block(bank):
    line = json.loads(GOLDEN_CONFIRM)
    line["forensic"]["bank"] = bank
    with pytest.raises(ValueError, match="console line: malformed"):
        read_console_line(json.dumps(line))


def test_reader_keeps_a_sandbox_transfer():
    line = json.loads(GOLDEN_CONFIRM)
    line["forensic"]["bank"] = SANDBOX_VIEW
    assert read_console_line(json.dumps(line)).forensic["bank"] == SANDBOX_VIEW


GOLDEN_BANK = (
    '{"v":3,"seq":11,"source":"bank","event":null,"meta":null,"subj'
    'ect":{"rail":"sandbox","event_id":"sandbox_event_001kmnw80hstc'
    'eme2a6nzxcxzw7","category":"account_transfer.created","object_'
    'type":"account_transfer","object_id":"sandbox_account_transfer'
    '_tts2u0bmjgmgyp08br4d","created_at":"2026-11-04T08:58:56Z","su'
    'mmary":"MANDATE_FIXTURE Account transfer created"},"forensic":'
    "null}"
)
BANK_EVENT = BankEvent(
    "sandbox_event_001kmnw80hstceme2a6nzxcxzw7",
    "account_transfer.created",
    "account_transfer",
    "sandbox_account_transfer_tts2u0bmjgmgyp08br4d",
    "2026-11-04T08:58:56Z",
    "MANDATE_FIXTURE Account transfer created",
)
BANK = json.loads(GOLDEN_BANK)
BANK_SUBJECT = BANK["subject"]


def test_bank_line_is_the_golden():
    line = bank_line(BANK_EVENT)
    assert (line.seq, line.source, line.event, line.meta, line.forensic) == (
        0,
        "bank",
        None,
        None,
        None,
    )
    published = dataclasses.replace(line, seq=11)
    assert console_line_json(published) == GOLDEN_BANK
    assert read_console_line(GOLDEN_BANK) == published


def test_console_bank_fixture_is_the_python_golden():
    test_console_fixtures_are_the_python_goldens("BANK", GOLDEN_BANK)


@pytest.mark.parametrize(
    "line",
    [
        {**BANK, "subject": {**BANK_SUBJECT, "rail": "simulated"}},
        {**BANK, "subject": {**BANK_SUBJECT, "created_at": "2026-11-04 08:58:56"}},
        {
            **BANK,
            "subject": {**BANK_SUBJECT, "created_at": "2026-11-04T08:58:56.123Z"},
        },
        {
            **BANK,
            "subject": {**BANK_SUBJECT, "created_at": "\u0662026-11-04T08:58:56Z"},
        },
        {**BANK, "subject": {**BANK_SUBJECT, "event_id": 7}},
        {**BANK, "subject": {**BANK_SUBJECT, "amount": 20000}},
        {
            **BANK,
            "subject": {k: v for k, v in BANK_SUBJECT.items() if k != "summary"},
        },
        {**BANK, "event": EVENT},
        {**BANK, "meta": HOOK_META},
        {**BANK, "forensic": json.loads(GOLDEN_CONFIRM)["forensic"]},
    ],
)
def test_reader_refuses_a_malformed_bank_line(line):
    with pytest.raises(ValueError, match="console line: malformed"):
        read_console_line(json.dumps(line))
