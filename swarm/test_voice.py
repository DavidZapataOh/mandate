import io
import json
import threading
import wave
from pathlib import Path

import httpx2
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gate.certs import generate_keypair
from swarm.voice import (
    ASR_URL,
    NO_VOICE_KEY,
    VOICE_OFF,
    Transcriber,
    VoiceAPIError,
    VoiceBusyError,
    check_wav,
    transcribe,
    transcriber_from_env,
    verify_voice,
    voice_bytes,
)

CLIP = Path(__file__).resolve().parent.parent / "demo" / "voice" / "pay-acme.wav"
RESPONSE = {
    "sessionId": "voyager/transcribe/12F0",
    "transcript": "Pay my Acme Corp internet bill. $200. Invoice A991.",
    "audioDurationMs": 5520,
    "turns": [],
}


def _wav(channels=1, width=2, rate=24000, frames=10):
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(channels)
        w.setsampwidth(width)
        w.setframerate(rate)
        w.writeframes(b"\x00" * width * channels * frames)
    return buf.getvalue()


def _client(status, body, seen):
    def handler(request):
        seen.append(request)
        return httpx2.Response(
            status,
            headers={"content-type": "application/json"},
            content=json.dumps(body).encode(),
        )

    return httpx2.Client(transport=httpx2.MockTransport(handler))


def _clock():
    ticks = iter([5.0, 5.75])
    return lambda: next(ticks)


def test_transcribe_multipart_shape():
    seen = []
    audio = CLIP.read_bytes()
    transcribe("vk", audio, ("Acme", "A-991"), _client(200, RESPONSE, seen), _clock())
    request = seen[0]
    body = request.read()
    assert str(request.url) == ASR_URL
    assert request.headers["authorization"] == "Bearer vk"
    assert request.headers["content-type"].startswith("multipart/form-data")
    expected = json.dumps(
        {
            "mode": "PUSH_TO_TALK",
            "model": "muse-voice-transcribe-1.0",
            "audioEncoding": "WAV",
            "keywords": ["Acme", "A-991"],
        }
    ).encode()
    assert expected in body
    assert b'name="audio"' in body and audio in body


def test_transcribe_parses_response():
    t = transcribe("vk", _wav(), (), _client(200, RESPONSE, []), _clock())
    assert t.text == "Pay my Acme Corp internet bill. $200. Invoice A991."
    assert (t.session_id, t.duration_ms, t.latency_ms) == (
        "voyager/transcribe/12F0",
        5520,
        750.0,
    )


@pytest.mark.parametrize("status", [400, 413, 429])
def test_transcribe_http_errors(status):
    client = _client(status, {"error": "x"}, [])
    with pytest.raises(VoiceAPIError, match=f"HTTP {status}"):
        transcribe("vk", _wav(), (), client, _clock())


@pytest.mark.parametrize(
    ("audio", "detail"),
    [
        (b"RIFFnope", "not a wav file"),
        (_wav(channels=2), "channels=2"),
        (_wav(rate=44100), "rate=44100"),
        (_wav(rate=16000, frames=9_600_001), "longer than 600 s"),
        (_wav(rate=24000, frames=14_400_001), "longer than 600 s"),
        (b"RIFF" + b"\x00" * 30_999_997, "larger than 31000000 bytes"),
    ],
)
def test_check_wav_rejects_unsupported(audio, detail):
    with pytest.raises(ValueError, match=f"unsupported wav: {detail}"):
        check_wav(audio)
    seen = []
    with pytest.raises(ValueError):
        transcribe("vk", audio, (), _client(200, RESPONSE, seen), _clock())
    assert seen == []


@pytest.mark.parametrize(("rate", "size"), [(16000, 19_200_044), (24000, 28_800_044)])
def test_check_wav_accepts_ten_minutes(rate, size):
    audio = _wav(rate=rate, frames=600 * rate)
    assert len(audio) == size
    check_wav(audio)


@pytest.mark.parametrize(
    "patch",
    [
        {"transcript": None},
        {"sessionId": 5},
        {"audioDurationMs": True},
        {"audioDurationMs": "5520"},
    ],
)
def test_transcribe_rejects_wrong_types(patch):
    body = {**RESPONSE, **patch}
    with pytest.raises(VoiceAPIError, match="response undecodable"):
        transcribe("vk", _wav(), (), _client(200, body, []), _clock())


PAGE_WAV = bytes.fromhex(
    "524946462c00000057415645666d74201000000001000100c05d000080bb0000"
    "0200100064617461080000000000ff3f0080ff7f"
)


def test_check_wav_accepts_the_holder_page_encoding():
    check_wav(PAGE_WAV)
    with wave.open(io.BytesIO(PAGE_WAV), "rb") as w:
        assert (w.getframerate(), w.getnframes()) == (24000, 4)


VOICE_SIGNED = (
    b"mandate/voice/v1\nq:000001\n"
    b"51758465b504b589a7d1b54e6c134af3"
    b"76c6a98482f803b8b5e57d76e461bfe5"
)


def test_voice_bytes_bind_the_quote_and_the_clip():
    assert voice_bytes("q:000001", PAGE_WAV) == VOICE_SIGNED


def test_any_paired_key_may_sign_a_clip():
    priv, pub = generate_keypair()
    _, other = generate_keypair()
    sig = Ed25519PrivateKey.from_private_bytes(priv).sign(VOICE_SIGNED)
    assert verify_voice("q:000001", PAGE_WAV, sig, (other, pub))
    assert not verify_voice("q:000001", PAGE_WAV, sig, (other,))
    assert not verify_voice("q:000001", PAGE_WAV + b"\x00", sig, (pub,))
    assert not verify_voice("q:000002", PAGE_WAV, sig, (pub,))
    assert not verify_voice("q:000001", PAGE_WAV, sig[:63], (pub,))


@pytest.mark.parametrize(
    ("env", "enabled", "reason"),
    [
        ({"META_API_KEY": "mk"}, False, VOICE_OFF),
        ({}, True, NO_VOICE_KEY),
        ({"MODEL_API_KEY": "vk"}, True, None),
    ],
)
def test_transcriber_from_env(env, enabled, reason):
    voice = transcriber_from_env(env, enabled=enabled)
    assert (voice.available, voice.reason) == (reason is None, reason)


def test_one_transcription_at_a_time():
    gate, entered, seen, done = threading.Event(), threading.Event(), [], []

    def handler(request):
        seen.append(request)
        entered.set()
        gate.wait(5)
        return httpx2.Response(200, content=json.dumps(RESPONSE).encode())

    client = httpx2.Client(transport=httpx2.MockTransport(handler))
    voice = Transcriber("vk", http_client=client)
    worker = threading.Thread(target=lambda: done.append(voice.transcribe(_wav())))
    worker.start()
    assert entered.wait(5)
    with pytest.raises(VoiceBusyError, match="voice busy"):
        voice.transcribe(_wav())
    gate.set()
    worker.join(5)
    assert (len(seen), done[0].text) == (1, RESPONSE["transcript"])
