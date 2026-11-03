"""Client for Meta's Muse Voice Transcribe REST endpoint.

The account holder says the payment out loud; this module turns a local WAV
into text. Audio the endpoint would reject is refused locally before upload.
"""

import io
import json
import time
import wave
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import httpx2

ASR_URL = "https://api.meta.ai/v1/asr/transcribe"
ASR_MODEL = "muse-voice-transcribe-1.0"
_RATES = (16000, 24000)
_TIMEOUT_S = 60.0


class VoiceAPIError(RuntimeError):
    """Raised when the transcription endpoint fails or answers badly."""


@dataclass(frozen=True)
class Transcript:
    """One transcription result.

    Attributes:
        text: Transcribed speech.
        session_id: Server-side session identifier.
        duration_ms: Audio duration reported by the service.
        latency_ms: Wall-clock request latency.
    """

    text: str
    session_id: str
    duration_ms: int
    latency_ms: float


def check_wav(audio: bytes) -> None:
    """Validate that audio is a mono 16-bit WAV at 16 or 24 kHz.

    Raises:
        ValueError: With ``unsupported wav: <detail>`` when it is not.
    """
    try:
        with wave.open(io.BytesIO(audio), "rb") as w:
            channels, width, rate = w.getnchannels(), w.getsampwidth(), w.getframerate()
    except (wave.Error, EOFError) as exc:
        raise ValueError("unsupported wav: not a wav file") from exc
    if channels != 1:
        raise ValueError(f"unsupported wav: channels={channels}")
    if width != 2:
        raise ValueError(f"unsupported wav: sample width={width}")
    if rate not in _RATES:
        raise ValueError(f"unsupported wav: rate={rate}")


def transcribe(
    api_key: str,
    audio: bytes,
    keywords: tuple[str, ...] = (),
    http_client: httpx2.Client | None = None,
    clock: Callable[[], float] = time.perf_counter,
) -> Transcript:
    """Transcribe a WAV clip in push-to-talk mode.

    Args:
        api_key: Meta API key, sent as a bearer token.
        audio: Mono 16-bit PCM WAV bytes at 16000 or 24000 Hz.
        keywords: Words to bias recognition toward.
        http_client: Injectable client for tests.
        clock: Monotonic clock in seconds; injectable for tests.

    Returns:
        The transcript with service and wall-clock timings.

    Raises:
        ValueError: If the audio is not an accepted WAV.
        VoiceAPIError: On HTTP errors or an undecodable response.
    """
    check_wav(audio)
    req = {
        "mode": "PUSH_TO_TALK",
        "model": ASR_MODEL,
        "audioEncoding": "WAV",
        "keywords": list(keywords),
    }
    files: Any = {
        "request": (None, json.dumps(req), "application/json"),
        "audio": ("audio.wav", audio, "audio/wav"),
    }
    client = http_client or httpx2.Client(timeout=_TIMEOUT_S)
    start = clock()
    try:
        resp = client.post(
            ASR_URL, headers={"Authorization": f"Bearer {api_key}"}, files=files
        )
    except httpx2.HTTPError as exc:
        raise VoiceAPIError(f"transport error: {type(exc).__name__}") from exc
    finally:
        if http_client is None:
            client.close()
    latency_ms = (clock() - start) * 1000.0
    if resp.status_code >= 400:
        raise VoiceAPIError(f"HTTP {resp.status_code}: {resp.text[:200]}")
    try:
        data = resp.json()
        text, session_id = data["transcript"], data["sessionId"]
        duration = data["audioDurationMs"]
    except (ValueError, KeyError, TypeError) as exc:
        raise VoiceAPIError("response undecodable") from exc
    if (
        not isinstance(text, str)
        or not isinstance(session_id, str)
        or type(duration) is not int
    ):
        raise VoiceAPIError("response undecodable")
    return Transcript(
        text=text, session_id=session_id, duration_ms=duration, latency_ms=latency_ms
    )
