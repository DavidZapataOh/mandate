import json
import string

import pytest

from e2e.adversaries import (
    narrow_action,
    narrow_chain,
    over_spend_action,
    over_target_action,
    poisoned_call,
)
from gate.broker import action_within_scope, verify_chain
from gate.certs import (
    BitstringRevocation,
    SingleUseStore,
    issue_certificate,
    verify_certificate,
)
from gate.manifests import ServerDescriptor, ToolDescriptor, generate
from gate.mcp_proxy import proxy_call


def _manifest(with_evil: bool):
    tools = [
        ToolDescriptor(tool="balance.read", scopes=("read:accounts",)),
        ToolDescriptor(tool="bill.pay", scopes=("write:payments",)),
    ]
    if with_evil:
        tools.append(ToolDescriptor(tool="evil.exfil", scopes=("net:evil.com",)))
    return generate(ServerDescriptor(server="bank-mcp", tools=tuple(tools)))


@pytest.mark.parametrize(
    "tool,scope",
    [("evil.exfil", "net:evil.com"), ("bill.pay.v2", "write:payments")],
)
def test_drill_poisoned_mcp(tool, scope):
    r = proxy_call(
        (_manifest(False),), poisoned_call(tool, scope), "d" * 32, 1800000000
    )
    assert (r.allowed, r.reason) == (False, "denied: tool undeclared")
    receipt = json.loads(r.event.to_json())
    assert receipt["verdict"] == "NOT_MET"
    assert receipt["reason"] == "denied: tool undeclared"
    assert receipt["policy"] == "manifest:bank-mcp"
    assert len(receipt["action"]) == 64
    assert all(c in string.hexdigits for c in receipt["action"])
    control = proxy_call(
        (_manifest(True),),
        poisoned_call("evil.exfil", "net:evil.com"),
        "c" * 32,
        1800000000,
    )
    assert (control.allowed, control.reason) == (True, "ok: declared")


def test_drill_escalation():
    chain, root_pub, root_scope = narrow_chain()
    assert root_scope.max_spend_cents == 20000
    assert len(chain) == 1
    ok, _ = verify_chain(chain, root_pub, root_scope, 1800000000, BitstringRevocation())
    assert ok is True
    leaf_scope = chain[-1].scope
    assert action_within_scope(leaf_scope, over_target_action()) == (
        False,
        "scope: target outside delegation",
    )
    assert action_within_scope(leaf_scope, over_spend_action()) == (
        False,
        "scope: spend exceeds delegation",
    )
    assert action_within_scope(leaf_scope, narrow_action()) == (
        True,
        "ok: within scope",
    )


def test_drill_replay(keypair, cert_claims):
    priv, pub = keypair
    store, revoked = SingleUseStore(), BitstringRevocation()
    token = issue_certificate(cert_claims, priv, "drill-replay-1")
    assert verify_certificate(token, pub, 1800000100, store, revoked) == (
        True,
        "ok: verified",
    )
    assert verify_certificate(token, pub, 1800000100, store, revoked) == (
        False,
        "replay: jti consumed",
    )
    assert store.consume("drill-replay-1") is False
    fresh = issue_certificate(cert_claims, priv, "drill-replay-2")
    assert verify_certificate(fresh, pub, 1800000100, store, revoked) == (
        True,
        "ok: verified",
    )
