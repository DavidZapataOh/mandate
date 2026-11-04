import base64
import json
import os
import subprocess
import time

import httpx2
import pytest
from mcp import Client

from bank.credentials import without_bank_key
from gate.certs import generate_keypair
from swarm.conftest import DEMO_INTENT
from swarm.handoff import QUOTE_REQUEST, AgentHandoff
from swarm.intent import sign_intent
from swarm.mcp_bridge import run_agent
from swarm.meta_client import MetaClient, api_key_from_env
from swarm.server import build_server


def _meta():
    try:
        return MetaClient(api_key_from_env(dict(os.environ)), timeout=120)
    except KeyError:
        pytest.skip("live: set MODEL_API_KEY or META_API_KEY")


@pytest.mark.live
@pytest.mark.anyio
async def test_live_spark_quotes_then_holder_approves_then_confirms(
    running_desk, sign_quote
):
    meta = _meta()
    desk, url = running_desk
    holder_priv, holder_pub = generate_keypair()
    assert desk.register_holder(holder_pub) is not None
    desk.record_intent(DEMO_INTENT, sign_intent(holder_priv, DEMO_INTENT))
    async with Client(f"{url}/mcp") as client:
        steps = await run_agent(
            meta,
            client,
            QUOTE_REQUEST.format(intent_id="i:000001"),
        )
        quotes = [s["result"] for s in steps if s["tool"] == "quote_payment"]
        assert quotes and quotes[-1]["status"] == "quoted", steps
        quote = quotes[-1]
        early = await client.call_tool(
            "confirm_payment", {"quote_id": quote["quote_id"]}
        )
        assert '"quoted"' in early.content[0].text
        approval = sign_quote(holder_priv, quote)
        body = {
            name: base64.b64encode(getattr(approval, name)).decode()
            for name in ("signature", "consent_key", "key_signature")
        }
        async with httpx2.AsyncClient(base_url=url) as http:
            approved = await http.post(
                "/api/approve", json={"quote_id": quote["quote_id"], **body}
            )
        assert approved.json()["status"] == "approved"
        steps = await run_agent(meta, client, f"Confirm quote {quote['quote_id']}.")
        done = [s["result"] for s in steps if s["tool"] == "confirm_payment"]
        assert done and done[-1]["status"] == "confirmed", steps
    assert desk.bank.get_balance("acme-991") == 20000
    assert desk.registry.prove(1).leaves == 1


MUSE_PROMPT = (
    "Use the mandate desk tools: read signed intent i:000001 with get_intent, "
    "quote exactly that payment, then report the quote status. Do not confirm."
)


@pytest.mark.live
def test_live_muse_code_quotes_through_mcp(running_desk, governed_repo):
    desk, url = running_desk
    repo, _ = governed_repo
    holder_priv, holder_pub = generate_keypair()
    assert desk.register_holder(holder_pub) is not None
    desk.record_intent(DEMO_INTENT, sign_intent(holder_priv, DEMO_INTENT))
    server = {"transport": "streamable_http", "url": f"{url}/mcp"}
    run = subprocess.run(  # noqa: S603
        [  # noqa: S607
            "muse",
            "exec",
            "--trust-workspace",
            "--disable-approval",
            "--max-model-steps",
            "10",
            "--model",
            "muse-spark-1.3",
            "-c",
            "mcpServers.mandate=" + json.dumps(server),
            MUSE_PROMPT,
        ],
        cwd=repo,
        env=without_bank_key(os.environ),
        capture_output=True,
        text=True,
        timeout=600,
    )
    assert run.returncode == 0, run.stderr[-2000:]
    assert [q["summary"] for q in desk.pending()] == [
        "Pay 200.00 USD to acme-991 (ref A-991) from checking-881"
    ]
    assert desk.bank.get_balance("acme-991") == 0


@pytest.mark.live
def test_live_spark_pays_a_signed_intent_from_its_id(make_desk, sign_quote):
    meta = _meta()
    desk, holder = make_desk(intents=(DEMO_INTENT,))
    handoff = AgentHandoff(meta, build_server(desk, "unused"), desk)
    assert handoff.start("i:000001")["state"] == "quoting"
    deadline = time.monotonic() + 300
    while handoff.status()["state"] == "quoting":
        assert time.monotonic() < deadline, handoff.status()
        time.sleep(0.5)
    assert handoff.status()["state"] == "waiting", handoff.status()
    desk.approve("q:000001", sign_quote(holder, desk.status("q:000001")))
    while handoff.status()["state"] in ("waiting", "confirming"):
        assert time.monotonic() < deadline, handoff.status()
        time.sleep(0.5)
    assert handoff.status()["detail"] == "Paid: pay:000001."
    assert desk.bank.get_balance("acme-991") == 20000
