"""Second detection layer: the fine-tuned multilingual classifier (v0.3).

Runs the ONNX export of `edithngalame/mdeberta-v3-prompt-injection-en-es` with ONNX
Runtime, so the gateway needs neither PyTorch nor transformers. Optional dependencies:

    pip install -e ".[ml]"

The model outputs a *logit margin* (injection minus benign). `gateway.json`, published
next to the model, holds the threshold picked on the validation split (at most 1% of
harmless messages blocked). The policy works with scores in [0, 1], so the margin is
mapped with a sigmoid centred on that threshold:

    score = 1 / (1 + exp(-(margin - threshold)))

A margin exactly at the validation threshold scores 0.5. The policy's per-source
thresholds then apply as usual: retrieved documents (block at 0.45) are treated more
strictly than user messages (block at 0.6).
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

from gateway.detectors.base import Finding, Source, Verdict

DEFAULT_REPO = "edithngalame/mdeberta-v3-prompt-injection-en-es"


def _sigmoid(x: float) -> float:
    if x >= 0:
        return 1.0 / (1.0 + math.exp(-x))
    e = math.exp(x)
    return e / (1.0 + e)


class ClassifierDetector:
    """Scores text with the fine-tuned mDeBERTa-v3 model.

    `session` and `tokenizer` can be injected (tests use small fakes); by default they are
    loaded from `model_dir`, a folder holding model.onnx, tokenizer.json and gateway.json.
    """

    name = "classifier"

    def __init__(self, model_dir: str | Path | None = None, *, session: Any = None, tokenizer: Any = None,
                 threshold_margin: float | None = None, max_len: int = 512):
        cfg: dict[str, Any] = {}
        if model_dir is not None:
            model_dir = Path(model_dir)
            cfg = json.loads((model_dir / "gateway.json").read_text(encoding="utf-8"))
        self.threshold = float(threshold_margin if threshold_margin is not None else cfg["threshold_margin"])
        self.max_len = int(cfg.get("max_len", max_len))
        self.tokenizer = tokenizer if tokenizer is not None else self._load_tokenizer(model_dir)
        self.session = session if session is not None else self._load_session(model_dir)

    @classmethod
    def from_hub(cls, repo_id: str = DEFAULT_REPO, revision: str | None = None) -> ClassifierDetector:
        """Download (once, then cached) the ONNX model from Hugging Face and load it."""
        from huggingface_hub import snapshot_download

        path = snapshot_download(repo_id, revision=revision, allow_patterns=["onnx/*"])
        return cls(Path(path) / "onnx")

    def _load_tokenizer(self, model_dir: Path | None):
        from tokenizers import Tokenizer

        tok = Tokenizer.from_file(str(Path(model_dir) / "tokenizer.json"))
        tok.enable_truncation(max_length=self.max_len)
        tok.no_padding()
        return tok

    @staticmethod
    def _load_session(model_dir: Path | None):
        import onnxruntime as ort

        return ort.InferenceSession(str(Path(model_dir) / "model.onnx"), providers=["CPUExecutionProvider"])

    def margin(self, text: str) -> float:
        """Raw model output: how much more the model believes 'injection' than 'benign'."""
        import numpy as np

        enc = self.tokenizer.encode(text)
        ids = np.array([enc.ids], dtype=np.int64)
        mask = np.array([enc.attention_mask], dtype=np.int64)
        return float(self.session.run(["margin"], {"input_ids": ids, "attention_mask": mask})[0][0])

    def scan(self, text: str, source: Source = Source.USER) -> Verdict:
        m = self.margin(text)
        score = _sigmoid(m - self.threshold)
        findings = []
        if score >= 0.5:
            findings.append(Finding(category="classifier_injection",
                                    evidence=f"model margin {m:+.2f} (threshold {self.threshold:+.2f})",
                                    weight=round(score, 3)))
        return Verdict(detector=self.name, score=round(score, 4), findings=findings)
