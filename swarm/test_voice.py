import io
import json
import wave
from pathlib import Path

import httpx2
import pytest

from swarm.voice import ASR_URL, VoiceAPIError, check_wav, transcribe

CLIP = Path(__file__).resolve().parent.parent / "demo" / "voice" / "pay-acme.wav"
RESPONSE = {
    "sessionId": "voyager/transcribe/12F0",
    "transcript": "Pay my Acme Corp internet bill. $200. Invoice A991.",
    "audioDurationMs": 5520,
    "turns": [],
}


def _wav(channels=1, width=2, rate=24000):
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(channels)
        w.setsampwidth(width)
        w.setframerate(rate)
        w.writeframes(b"\x00" * width * channels * 10)
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
    ],
)
def test_check_wav_rejects_unsupported(audio, detail):
    with pytest.raises(ValueError, match=f"unsupported wav: {detail}"):
        check_wav(audio)
    seen = []
    with pytest.raises(ValueError):
        transcribe("vk", audio, (), _client(200, RESPONSE, seen), _clock())
    assert seen == []


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
