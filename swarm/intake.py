"""Turn the holder's words, typed or spoken, into a drafted payment intent."""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from swarm.agent import Responder
from swarm.intent import IntentError, PayeeBook, draft_intent
from swarm.voice import Transcript, check_wav


@dataclass(frozen=True)
class IntentIntake:
    """Drafts intents for the holder to review; it signs and pays nothing.

    Args:
        meta: Model that names the payee and invoice as spoken.
        book: The holder's payees; the account and invoice come from here.
        transcriber: Speech to text for a WAV clip, given the book's keywords.
    """

    meta: Responder
    book: PayeeBook
    transcriber: Callable[[bytes, tuple[str, ...]], Transcript]

    def from_text(self, text: str) -> dict[str, Any]:
        """Draft an intent from the holder's words.

        Returns:
            ``drafted`` with the four intent fields, or ``denied`` with the
            reason the draft did not match the book.

        Raises:
            MetaAPIError: When the model call fails.
        """
        try:
            intent, _ = draft_intent(self.meta, text, self.book)
        except IntentError as err:
            return {"status": "denied", "transcript": text, "reason": str(err)}
        return {
            "status": "drafted",
            "transcript": text,
            "intent": {
                "amount_cents": intent.amount_cents,
                "currency": intent.currency,
                "recipient": intent.recipient,
                "reference": intent.reference,
            },
        }

    def from_voice(self, audio: bytes) -> dict[str, Any]:
        """Transcribe a WAV clip, then draft from what was said.

        Raises:
            ValueError: When the clip is refused; nothing is sent.
            VoiceAPIError: When transcription fails.
            MetaAPIError: When the model call fails.
        """
        check_wav(audio)
        spoken = self.transcriber(audio, self.book.keywords())
        return self.from_text(spoken.text)
