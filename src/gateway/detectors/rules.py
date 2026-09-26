"""Rule-based prompt injection detector.

This is the baseline the ML model has to beat in step 3. It is deliberately
transparent: every block can be explained by the pattern that fired.

Known weaknesses (by design, and worth stating in the write-up):
- Paraphrases and other languages slip through.
- Attackers can read these rules if they are public.
It stays in the final gateway as a cheap first layer in front of the classifier.
"""

from __future__ import annotations

import base64
import re
import unicodedata
from dataclasses import dataclass

from gateway.detectors.base import Finding, Source, Verdict

# Characters attackers use to split keywords so regexes miss them
# ("ig​nore previous instructions").
_INVISIBLE = dict.fromkeys(
    map(ord, "\u200b‌‍⁠﻿­᠎"), None
)


def normalize(text: str) -> str:
    """Undo common obfuscation before matching.

    NFKC folds full-width and stylised letters back to plain ASCII,
    invisible characters are removed, and whitespace is collapsed.
    """
    text = unicodedata.normalize("NFKC", text)
    text = text.translate(_INVISIBLE)
    text = re.sub(r"\s+", " ", text)
    return text.lower().strip()


@dataclass(frozen=True)
class Rule:
    category: str
    pattern: re.Pattern[str]
    weight: float


def _r(category: str, pattern: str, weight: float) -> Rule:
    return Rule(category, re.compile(pattern, re.IGNORECASE), weight)


_PREV = r"(previous|prior|above|earlier|preceding|all|any|your|the|these|those)"
_INSTR = r"(instructions?|prompts?|rules?|directives?|guidelines?|context|messages?)"

RULES: tuple[Rule, ...] = (
    # "Ignore all previous instructions", "disregard the above rules"
    _r(
        "instruction_override",
        rf"\b(ignore|disregard|forget|override|bypass|skip)\b(\s+\w+){{0,3}}?\s+{_PREV}(\s+\w+){{0,2}}?\s+{_INSTR}",
        0.7,
    ),
    _r("instruction_override", r"\bnew (instructions?|rules?|task)\s*:", 0.5),
    # "You are now DAN", "act as an unrestricted AI"
    _r(
        "role_hijack",
        r"\byou are (now|no longer)\b|\b(act|behave|respond) as (an? )?(unrestricted|unfiltered|jailbroken|evil)\b",
        0.5,
    ),
    _r("role_hijack", r"\b(dan|developer) mode\b|\bdo anything now\b", 0.6),
    # "Print your system prompt", "reveal your hidden instructions"
    _r(
        "prompt_extraction",
        r"\b(reveal|print|show|repeat|output|display|leak|tell me)\b(\s+\w+){0,3}?\s+(system|hidden|initial|original|secret)\s+(prompt|instructions?|message)",
        0.6,
    ),
    _r(
        "prompt_extraction",
        r"\brepeat (everything|all|the text) (above|before)\b",
        0.5,
    ),
    # Fake chat-template tokens that try to open a new "system" turn
    _r(
        "delimiter_injection",
        r"<\|?(im_start|im_end|system|endoftext)\|?>|\[/?inst\]|###\s*(system|instruction)\s*:",
        0.6,
    ),
    # Markdown image whose URL carries data out: ![x](https://evil.com/?q=...)
    _r(
        "exfiltration",
        r"!\[[^\]]*\]\(https?://[^)\s]+\?[^)\s]*=",
        0.5,
    ),
    _r(
        "exfiltration",
        r"\b(send|post|forward|email|upload)\b(\s+\w+){0,4}?\s+(to|at)\s+(https?://|\S+@\S+\.\w+)",
        0.4,
    ),
)

# Text addressed *to the model* is normal from a user but a red flag inside a
# retrieved document or tool output: web pages don't usually talk to AIs.
INDIRECT_RULES: tuple[Rule, ...] = (
    _r(
        "addressed_to_ai",
        r"\b(ai|assistant|language model|llm|chatbot|agent)\b\s*[:,]?\s*(please\s+)?(you must|you should|do not|don't|ignore|instead)",
        0.5,
    ),
    _r(
        "addressed_to_ai",
        r"\b(note|message|instructions?) (to|for) (the )?(ai|assistant|llm|model|agent)\b",
        0.5,
    ),
    _r("hidden_instruction", r"\b(do not|don't) (tell|inform|mention (this )?to) the user\b", 0.6),
)

_B64_BLOB = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")


def _decoded_base64_payloads(raw: str) -> list[str]:
    """Decode long base64 blobs so injections hidden in them are scanned too."""
    out = []
    for blob in _B64_BLOB.findall(raw):
        try:
            decoded = base64.b64decode(blob, validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if decoded.isprintable():
            out.append(decoded)
    return out


class RuleDetector:
    name = "rules"

    def __init__(self, rules: tuple[Rule, ...] = RULES, indirect_rules: tuple[Rule, ...] = INDIRECT_RULES):
        self.rules = rules
        self.indirect_rules = indirect_rules

    def _match(self, text: str, rules: tuple[Rule, ...]) -> list[Finding]:
        findings = []
        for rule in rules:
            m = rule.pattern.search(text)
            if m:
                findings.append(Finding(rule.category, m.group(0)[:120], rule.weight))
        return findings

    def scan(self, text: str, source: Source = Source.USER) -> Verdict:
        rules = self.rules + (self.indirect_rules if source != Source.USER else ())
        findings = self._match(normalize(text), rules)

        for payload in _decoded_base64_payloads(text):
            for f in self._match(normalize(payload), rules):
                findings.append(Finding("encoded_" + f.category, f.evidence, f.weight))

        return Verdict(detector=self.name, score=_combine(findings), findings=findings)


def _combine(findings: list[Finding]) -> float:
    """Noisy-OR: independent pieces of evidence raise confidence without exceeding 1.

    One weak hit (0.4) stays below a 0.5 block threshold; two weak hits
    (1 - 0.6 * 0.6 = 0.64) cross it.
    """
    p_clean = 1.0
    for f in findings:
        p_clean *= 1.0 - f.weight
    return round(1.0 - p_clean, 4)
