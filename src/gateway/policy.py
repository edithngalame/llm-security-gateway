"""Turns detector scores into a decision: allow, flag, or block.

Thresholds are per source. Retrieved documents and tool outputs get a stricter
block threshold because nobody legitimately needs to issue instructions to the
model from inside a web page.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum

from gateway.detectors.base import Detector, Source, Verdict


class Action(str, Enum):
    ALLOW = "allow"
    FLAG = "flag"    # let through, but log for review
    BLOCK = "block"


@dataclass(frozen=True)
class Thresholds:
    flag: float
    block: float


def _env(name: str, default: float) -> float:
    return float(os.getenv(name, default))


DEFAULT_THRESHOLDS: dict[Source, Thresholds] = {
    Source.USER: Thresholds(flag=_env("GW_USER_FLAG", 0.3), block=_env("GW_USER_BLOCK", 0.6)),
    Source.RETRIEVED: Thresholds(flag=_env("GW_RETRIEVED_FLAG", 0.2), block=_env("GW_RETRIEVED_BLOCK", 0.45)),
    Source.TOOL: Thresholds(flag=_env("GW_TOOL_FLAG", 0.2), block=_env("GW_TOOL_BLOCK", 0.45)),
}


@dataclass
class Decision:
    action: Action
    score: float
    source: Source
    verdicts: list[Verdict]


class Policy:
    def __init__(self, detectors: list[Detector], thresholds: dict[Source, Thresholds] | None = None):
        self.detectors = detectors
        self.thresholds = thresholds or DEFAULT_THRESHOLDS

    def evaluate(self, text: str, source: Source = Source.USER) -> Decision:
        verdicts = [d.scan(text, source) for d in self.detectors]
        # Take the most confident detector: any single layer can block.
        score = max((v.score for v in verdicts), default=0.0)
        t = self.thresholds[source]
        if score >= t.block:
            action = Action.BLOCK
        elif score >= t.flag:
            action = Action.FLAG
        else:
            action = Action.ALLOW
        return Decision(action=action, score=score, source=source, verdicts=verdicts)
