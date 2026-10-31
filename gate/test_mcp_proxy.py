import json

from gate.events import DecisionEvent
from gate.manifests import ServerDescriptor, ToolDescriptor, generate
from gate.mcp_proxy import Manifest, ProxyCall, ToolGrant, check, proxy_call


def _bank_manifest() -> Manifest:
    return Manifest(
        v=1,
        server="bank-mcp",
        grants=(
            ToolGrant(tool="balance.read", scopes=("read:accounts",)),
            ToolGrant(tool="bill.pay", scopes=("write:payments",)),
        ),
    )


def _result(server, tool, scope):
    return proxy_call(
        (_bank_manifest(),),
        ProxyCall(server=server, tool=tool, scope=scope),
        "p" * 32,
        1800000000,
    )


def test_poisoned_server_denied():
    r = _result("bank-mcp", "evil.exfil", "net:evil.com")
    assert (r.allowed, r.reason) == (False, "denied: tool undeclared")
    payload = json.loads(r.event.to_json())
    assert (payload["verdict"], payload["reason"]) == (
        "NOT_MET",
        "denied: tool undeclared",
    )
    assert payload["policy"] == "manifest:bank-mcp"


def test_declared_tool_allowed():
    r = _result("bank-mcp", "bill.pay", "write:payments")
    assert isinstance(r.event, DecisionEvent)
    assert (r.allowed, r.reason) == (True, "ok: declared")
    payload = json.loads(r.event.to_json())
    assert payload["verdict"] == "MET"
    assert payload["lat_us"] >= 0.0


def test_unknown_server_denied():
    r = _result("ghost-mcp", "bill.pay", "write:payments")
    assert (r.allowed, r.reason) == (False, "denied: server undeclared")
    assert r.event.policy_id == "manifest:ghost-mcp"


def test_shadowed_tool_denied():
    rogue = Manifest(v=1, server="evil-mcp", grants=())
    r = proxy_call(
        (_bank_manifest(), rogue),
        ProxyCall(server="evil-mcp", tool="bill.pay", scope="write:payments"),
        "s" * 32,
        1800000000,
    )
    assert (r.allowed, r.reason) == (False, "denied: tool undeclared")


def test_scope_exceeds_grant_denied():
    r = _result("bank-mcp", "bill.pay", "write:treasury")
    assert (r.allowed, r.reason) == (False, "denied: scope exceeds grant")


def _descriptors():
    return (
        ServerDescriptor(
            server="bank-mcp",
            tools=(
                ToolDescriptor(tool="bill.pay", scopes=("write:payments",)),
                ToolDescriptor(tool="balance.read", scopes=("read:accounts",)),
            ),
        ),
        ServerDescriptor(
            server="fs-mcp",
            tools=(ToolDescriptor(tool="file.read", scopes=("read:/work/**",)),),
        ),
    )


def test_generator_covers_demo_servers():
    bank, fs = (generate(d) for d in _descriptors())
    assert bank.server == "bank-mcp"
    assert [g.tool for g in bank.grants] == ["balance.read", "bill.pay"]
    assert bank.grants[1].scopes == ("write:payments",)
    assert fs.grants == (ToolGrant(tool="file.read", scopes=("read:/work/**",)),)
    assert check(bank, "bill.pay", "write:payments") == (True, "ok: declared")
    assert check(fs, "file.read", "read:/work/**") == (True, "ok: declared")


def test_generator_minimal():
    bank = generate(_descriptors()[0])
    assert check(bank, "evil.exfil", "net:evil.com") == (
        False,
        "denied: tool undeclared",
    )
    assert check(bank, "bill.pay", "write:treasury") == (
        False,
        "denied: scope exceeds grant",
    )
