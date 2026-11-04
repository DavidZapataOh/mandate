"""Client for Meta's Muse Voice Transcribe REST endpoint.

The account holder says the payment out loud; this module turns a local WAV
into text. Audio the endpoint would reject is refused locally before upload.
A transcript is a confirmation shown to the holder, never proof of who spoke:
push-to-talk mode returns no speaker attribution.
"""

import hashlib
import io
import json
import threading
import time
import wave
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

import httpx2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from swarm.meta_client import api_key_from_env

ASR_URL = "https://api.meta.ai/v1/asr/transcribe"
ASR_MODEL = "muse-voice-transcribe-1.0"
_RATES = (16000, 24000)
MAX_AUDIO_S = 600
# The service caps the request body at 32 MB; the margin covers multipart
# framing and the request JSON whether MB means 10^6 or 2^20.
MAX_WAV_BYTES = 31_000_000
_TIMEOUT_S = 60.0
VOICE_OFF = "voice off: start the desk with --voice"
NO_VOICE_KEY = "set MODEL_API_KEY or META_API_KEY"
VOICE_SIG_HEADER = "x-mandate-voice-sig"
# A domain distinct from the consent prefix, so a voice signature can never
# stand in for a consent signature, nor a consent signature for a voice one.
_VOICE_DOMAIN = b"mandate/voice/v1\n"
_KEY_LEN = 32
_SIGNATURE_LEN = 64


class VoiceAPIError(RuntimeError):
    """Raised when the transcription endpoint fails or answers badly."""


class VoiceBusyError(RuntimeError):
    """Raised when another transcription is already in flight."""


class VoiceUnavailableError(RuntimeError):
    """Raised when transcription is off or has no API key."""


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

    The size is checked first, then the format, then the duration, which
    must not exceed ``MAX_AUDIO_S`` seconds. Raises when the audio is larger
    than ``MAX_WAV_BYTES`` bytes.

    Raises:
        ValueError: With ``unsupported wav: <detail>`` when it is not.
    """
    if len(audio) > MAX_WAV_BYTES:
        raise ValueError(f"unsupported wav: larger than {MAX_WAV_BYTES} bytes")
    try:
        with wave.open(io.BytesIO(audio), "rb") as w:
            channels, width, rate = w.getnchannels(), w.getsampwidth(), w.getframerate()
            frames = w.getnframes()
    except (wave.Error, EOFError) as exc:
        raise ValueError("unsupported wav: not a wav file") from exc
    if channels != 1:
        raise ValueError(f"unsupported wav: channels={channels}")
    if width != 2:
        raise ValueError(f"unsupported wav: sample width={width}")
    if rate not in _RATES:
        raise ValueError(f"unsupported wav: rate={rate}")
    if frames > MAX_AUDIO_S * rate:
        raise ValueError(f"unsupported wav: longer than {MAX_AUDIO_S} s")


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


class Transcriber:
    """Transcribes one spoken confirmation at a time.

    The transcript is a confirmation the holder reads, not proof of who
    spoke: push-to-talk mode returns no speaker attribution.

    Args:
        api_key: Meta API key, or None when transcription is unavailable.
        reason: Why it is unavailable, reported when ``api_key`` is None.
        http_client: Injectable client for tests.
    """

    def __init__(
        self,
        api_key: str | None,
        reason: str = NO_VOICE_KEY,
        http_client: httpx2.Client | None = None,
    ) -> None:
        self._api_key = api_key
        self._reason = reason
        self._http_client = http_client
        self._lock = threading.Lock()

    @property
    def available(self) -> bool:
        """True when a key is configured."""
        return self._api_key is not None

    @property
    def reason(self) -> str | None:
        """Why transcription is unavailable, or None when it is available."""
        return None if self.available else self._reason

    def transcribe(self, audio: bytes, keywords: tuple[str, ...] = ()) -> Transcript:
        """Transcribe one clip unless another call is in flight.

        Args:
            audio: Mono 16-bit PCM WAV bytes at 16000 or 24000 Hz.
            keywords: Words to bias recognition toward.

        Returns:
            The transcript.

        Raises:
            VoiceUnavailableError: Without an API key.
            VoiceBusyError: While another transcription runs.
            ValueError: If the audio is not an accepted WAV.
            VoiceAPIError: On HTTP errors or an undecodable response.
        """
        if self._api_key is None:
            raise VoiceUnavailableError(self._reason)
        if not self._lock.acquire(blocking=False):
            raise VoiceBusyError("voice busy")
        try:
            return transcribe(
                self._api_key, audio, keywords, http_client=self._http_client
            )
        finally:
            self._lock.release()


def transcriber_from_env(
    env: Mapping[str, str], enabled: bool, http_client: httpx2.Client | None = None
) -> Transcriber:
    """Build the desk's transcriber; only an operator opt-in spends calls.

    Args:
        env: Environment holding MODEL_API_KEY or META_API_KEY.
        enabled: Whether the operator asked for voice.
        http_client: Injectable client for tests.

    Returns:
        An available transcriber, or one that reports why it is not.
    """
    if not enabled:
        return Transcriber(None, VOICE_OFF, http_client)
    try:
        key = api_key_from_env(env)
    except KeyError:
        return Transcriber(None, NO_VOICE_KEY, http_client)
    return Transcriber(key, http_client=http_client)


def voice_bytes(quote_id: str, audio: bytes) -> bytes:
    """Bytes the holder device signs to upload one clip for one quote.

    Args:
        quote_id: The quote shown beside the clip.
        audio: The exact WAV bytes uploaded.

    Returns:
        ``mandate/voice/v1``, the quote id and the clip's sha256 hex, one per line.
    """
    digest = hashlib.sha256(audio).hexdigest().encode("ascii")
    return _VOICE_DOMAIN + quote_id.encode("ascii") + b"\n" + digest


def verify_voice(
    quote_id: str, audio: bytes, signature: bytes, holder_keys: tuple[bytes, ...]
) -> bool:
    """True when a paired holder key signed this clip for this quote.

    The signature authenticates the uploading device, not the speaker, and
    is never a consent.

    Args:
        quote_id: The quote the clip is for.
        audio: The WAV bytes received.
        signature: Raw 64-byte Ed25519 signature.
        holder_keys: Raw 32-byte public keys of the paired holders.

    Returns:
        Whether any paired key verifies the signature.
    """
    if type(signature) is not bytes or len(signature) != _SIGNATURE_LEN:
        return False
    message = voice_bytes(quote_id, audio)
    for key in holder_keys:
        if type(key) is not bytes or len(key) != _KEY_LEN:
            continue
        try:
            Ed25519PublicKey.from_public_bytes(key).verify(signature, message)
        except (InvalidSignature, ValueError):
            continue
        return True
    return False
