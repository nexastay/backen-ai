"""Simple moderation pipeline (lexical filters + heuristic scoring)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence

LEXICAL_PATTERNS: Sequence[str] = (
    r"\b(enculé|pute|salope|fdp|fuck|shit)\b",
    r"\b(terror|naz|hitler|djihad|djihadiste)\b",
    r"\b(viol|péd|pedo|inceste)\b",
    r"\b(negre|nègre|porc|youpin)\b",
)

SEXUAL_TERMS = {"sexe", "porno", "nsfw", "nu", "nue", "nues", "fellatio", "sodomie"}
VIOLENCE_TERMS = {"tuer", "massacre", "bomb", "arme", "exploser", "meurtre"}
HATE_TERMS = {"haine", "haineux", "raciste", "racisme", "suprémaciste"}


class ModerationError(ValueError):
    """Raised when a payload violates the moderation policy."""


@dataclass
class ModerationResult:
    approved: bool
    reason: Optional[str] = None
    matches: Optional[List[str]] = None


class ModerationService:
    def __init__(self, patterns: Optional[Sequence[str]] = None) -> None:
        self.patterns = [re.compile(p, re.IGNORECASE) for p in (patterns or LEXICAL_PATTERNS)]

    def _lexical_matches(self, text: str) -> List[str]:
        matches: List[str] = []
        for pattern in self.patterns:
            if pattern.search(text):
                matches.append(pattern.pattern)
        return matches

    def _heuristic_score(self, text: str) -> Dict[str, int]:
        lowered = text.lower()
        score = {
            "sexual": sum(term in lowered for term in SEXUAL_TERMS),
            "violence": sum(term in lowered for term in VIOLENCE_TERMS),
            "hate": sum(term in lowered for term in HATE_TERMS),
        }
        return score

    def analyze(self, text: Optional[str]) -> ModerationResult:
        if not text:
            return ModerationResult(approved=True)
        normalized = text.strip()
        if not normalized:
            return ModerationResult(approved=True)
        matches = self._lexical_matches(normalized)
        if matches:
            return ModerationResult(approved=False, reason="lexical", matches=matches)
        score = self._heuristic_score(normalized)
        if any(score.values()):
            reason = ",".join(f"{k}:{v}" for k, v in score.items() if v)
            return ModerationResult(approved=False, reason=reason or "heuristic")
        return ModerationResult(approved=True)

    def ensure_text_allowed(self, text: Optional[str], *, context: str = "") -> Optional[str]:
        result = self.analyze(text)
        if not result.approved:
            raise ModerationError(f"Contenu interdit ({context or 'général'})")
        return text

    def sanitize_batch(self, chunks: Iterable[str], *, context: str = "") -> None:
        for chunk in chunks:
            self.ensure_text_allowed(chunk, context=context)
