"""Which detectors the gateway runs, chosen by environment variables.

    (nothing set)             rules only: no extra dependencies, starts instantly
    GW_CLASSIFIER=1           rules + the fine-tuned classifier, downloaded once from Hugging Face
    GW_CLASSIFIER_PATH=<dir>  rules + the classifier from a local folder (model.onnx, tokenizer.json, gateway.json)
    GW_CLASSIFIER_REPO=<id>   use another Hugging Face repo than the default
"""

from __future__ import annotations

import logging
import os
import time

from gateway.detectors import Detector, RuleDetector

log = logging.getLogger("gateway")


def classifier_enabled() -> bool:
    return bool(os.getenv("GW_CLASSIFIER_PATH")) or os.getenv("GW_CLASSIFIER", "").lower() in ("1", "true", "yes")


def load_classifier() -> Detector:
    from gateway.detectors.classifier import DEFAULT_REPO, ClassifierDetector

    t0 = time.perf_counter()
    path = os.getenv("GW_CLASSIFIER_PATH")
    det = ClassifierDetector(path) if path else ClassifierDetector.from_hub(os.getenv("GW_CLASSIFIER_REPO", DEFAULT_REPO))
    log.info("classifier loaded in %.1f s (threshold margin %+.2f)", time.perf_counter() - t0, det.threshold)
    # Warm-up: the first inference is much slower (memory allocation, lazy set-up in ONNX Runtime).
    # Doing it now keeps that delay out of the first real request and out of the latency stats.
    t1 = time.perf_counter()
    det.scan("warm-up message")
    log.info("classifier warm-up took %.1f s", time.perf_counter() - t1)
    return det


def build_detectors(with_classifier: bool | None = None) -> list[Detector]:
    """Rules always run first (fast, explainable); the classifier is the second layer."""
    detectors: list[Detector] = [RuleDetector()]
    if classifier_enabled() if with_classifier is None else with_classifier:
        detectors.append(load_classifier())
    return detectors
