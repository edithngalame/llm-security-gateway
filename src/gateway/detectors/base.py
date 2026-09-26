"""Shared types for every detector in the gateway."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol


class Source(str, Enum):
    """Where a piece of text entered the LLM's context window.

    The trust level differs per source, and so does the attack:
    - USER: direct prompt injection / jailbreak typed by the user.
    - RETRIEVED: indirect injection hidden in RAG documents, web pages, emails.
    - TOOL: indirect injection returned by a tool or API call in an agent loop.
    """

    USER = "user"
    RETRIEVED = "retrieved"
    TOOL = "tool"


@dataclass(frozen=True)
class Finding:
    """One piece of evidence a detector found (e.g. a matched pattern)."""

    category: str
    evidence: str
    weight: float


@dataclass
class Verdict:
    """A detector's judgement on one piece of text.

    score is in [0, 1]: the detector's confidence that the text is malicious.
    """

    detector: str
    score: float
    findings: list[Finding] = field(default_factory=list)

    @property
    def categories(self) -> list[str]:
        return sorted({f.category for f in self.findings})


class Detector(Protocol):
    """Anything that can score text. Rules, ML classifiers and LLM judges all fit."""

    name: str

    def scan(self, text: str, source: Source = Source.USER) -> Verdict: ...
