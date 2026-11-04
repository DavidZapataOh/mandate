"""Test-only desk for the holder page's browser tests: scripted Spark, fake ears.

Everything real but the model and speech recognition: the desk, gate, bank,
statement, routes, hub and the agent handoff over the desk's MCP tools.
"""

import argparse
import itertools
import json
import re
import secrets
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import uvicorn

from bank.api import Bank
from bank.verifier import Verifier
from gate.certs import generate_keypair
from swarm.desk import PaymentDesk
from swarm.hub import EventHub
from swarm.intake import IntentIntake
from swarm.intent import PayeeBook
from swarm.meta_client import Item, MetaResponse, MetaTrace
from swarm.server import build_server
from swarm.voice import Transcript

PAIR = "e2e-pair-token"
HEARD = "Pay my Acme Corp bill A-991, 200 USD."
DRAFT = {
    "payee_name": "Acme Corp",
    "amount_cents": 20000,
    "currency": "USD",
    "reference": "A991",
}
_ids = itertools.count(1)


def _trace() -> MetaTrace:
    return MetaTrace("muse-spark-1.3", f"resp_e2e_{next(_ids)}", None, 1.0, 1, 1)


def _call(name: str, args: dict[str, Any]) -> Item:
    n = next(_ids)
    return {
        "type": "function_call",
        "id": f"fc_e2e_{n}",
        "call_id": f"call_e2e_{n}",
        "name": name,
        "arguments": json.dumps(args),
        "status": "completed",
    }


def _say(text: str) -> Item:
    content = [{"type": "output_text", "text": text, "annotations": []}]
    return {"type": "message", "role": "assistant", "content": content}


class ScriptedSpark:
    """Test fake for MetaClient: drafts the demo bill and walks the desk tools."""

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
        if isinstance(input, str):
            return MetaResponse(_trace(), (_say(json.dumps(DRAFT)),))
        outputs = [i for i in input if i.get("type") == "function_call_output"]
        found = re.search(r"[iq]:\d{6}", str(input[0]["content"]))
        ref = "" if found is None else found.group()
        if ref.startswith("q:"):
            step = _call("confirm_payment", {"quote_id": ref})
            return MetaResponse(_trace(), (step,) if not outputs else (_say("Done."),))
        if not outputs:
            return MetaResponse(_trace(), (_call("get_intent", {"intent_id": ref}),))
        if len(outputs) == 1:
            seen = json.loads(outputs[0]["output"])
            args = {
                "intent_id": seen["intent_id"],
                "to_account": seen["recipient"],
                "amount_cents": seen["amount_cents"],
                "currency": seen["currency"],
                "reference": seen["reference"],
            }
            return MetaResponse(_trace(), (_call("quote_payment", args),))
        return MetaResponse(_trace(), (_say("Quoted."),))


def _ears(audio: bytes, keywords: tuple[str, ...]) -> Transcript:
    return Transcript(HEARD, "sess-e2e", 1000, 1.0)


def main() -> None:
    """Serve the test desk: `intent_server.py --port P --console-dir DIR`."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--console-dir", type=Path, required=True)
    args = parser.parse_args()
    gate_key, gate_pub = generate_keypair()
    hub = EventHub()
    desk = PaymentDesk(
        source="checking-881",
        bank=Bank({"checking-881": 10_000_000, "acme-991": 0}),
        verifier=Verifier(gate_pub),
        gate_key=gate_key,
        clock=lambda: int(time.time()),
        nonces=lambda: secrets.token_hex(16),
        publish=hub.publish,
    )
    spark = ScriptedSpark()
    book = PayeeBook.from_json(
        {"acme corp": {"account": "acme-991", "open_invoices": ["A-991"]}}
    )
    app = build_server(
        desk,
        PAIR,
        hub=hub,
        console_dir=args.console_dir,
        intake=IntentIntake(spark, book, _ears),
        agent=spark,
    ).streamable_http_app()
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
