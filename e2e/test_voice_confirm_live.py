import base64
import os
from pathlib import Path

import httpx2
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from swarm.meta_client import api_key_from_env
from swarm.server import build_server
from swarm.voice import VOICE_SIG_HEADER, transcriber_from_env, voice_bytes

CLIP = Path(__file__).resolve().parent.parent / "demo" / "voice" / "pay-acme.wav"


@pytest.mark.live
@pytest.mark.anyio
async def test_live_spoken_confirmation_is_words_only(make_desk):
    env = dict(os.environ)
    try:
        api_key_from_env(env)
    except KeyError:
        pytest.skip("live: set MODEL_API_KEY or META_API_KEY")
    desk, holder = make_desk()
    desk.quote("acme-991", 20000, "USD", "A-991")
    clip = CLIP.read_bytes()
    signer = Ed25519PrivateKey.from_private_bytes(holder)
    raw = signer.sign(voice_bytes("q:000001", clip))
    sig = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    voice = transcriber_from_env(env, enabled=True)
    app = build_server(desk, "pair-live", voice=voice).streamable_http_app()
    transport = httpx2.ASGITransport(app=app)
    async with httpx2.AsyncClient(
        transport=transport, base_url="http://localhost", timeout=90
    ) as http:
        resp = await http.post(
            "/api/voice",
            params={"quote": "q:000001"},
            content=clip,
            headers={"content-type": "audio/wav", VOICE_SIG_HEADER: sig},
        )
    assert resp.status_code == 200, resp.text
    assert list(resp.json()) == ["transcript"]
    assert "acme" in resp.json()["transcript"].lower()
    assert desk.status("q:000001")["status"] == "quoted"
