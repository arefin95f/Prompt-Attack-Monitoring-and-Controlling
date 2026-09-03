"""
Phase 2: Transformer / semantic detector (Layer 2B).
Uses a HuggingFace prompt-injection model when available; otherwise a
strong semantic heuristic fallback so the pipeline still gains accuracy.
"""

from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class Layer2BTransformer:
    """Semantic detector gated behind classical-model uncertainty."""

    SEMANTIC_CUES = [
        (r"(?i)\bignore\b.{0,40}\b(instructions?|rules?|policies|guidelines)\b", 0.55, "direct_override"),
        (r"(?i)\b(jailbreak|do anything now|\bdan\b|developer mode)\b", 0.6, "jailbreak"),
        (r"(?i)\b(system prompt|hidden (rules|instructions)|internal (rules|config))\b", 0.58, "system_extraction"),
        (r"(?i)\b(bypass|override|disable)\b.{0,30}\b(safety|filter|guardrail)\b", 0.55, "direct_override"),
        (r"(?i)\b(act as|pretend to be|you are now)\b.{0,40}\b(unrestricted|evil|no rules)\b", 0.5, "role_impersonation"),
        (r"(?i)\b(execute|run|invoke)\b.{0,20}\b(command|shell|api|function)\b", 0.52, "tool_injection"),
        (r"(?i)\b(extract|leak|dump|exfiltrate)\b.{0,30}\b(data|secrets?|emails?|password)\b", 0.52, "data_extraction"),
        (r"(?i)\b(base64|decode this|rot13|hex encode)\b", 0.45, "obfuscation"),
        (r"(?i)\b(firewalls? are down|logs? are wiped|security (is )?compromised)\b", 0.5, "story_jailbreak"),
        (r"(?i)\bfrom now on\b.{0,40}\b(ignore|no safety|unrestricted)\b", 0.48, "context_tampering"),
    ]

    BENIGN_LOOKALIKES = [
        r"(?i)\bignore previous email\b",
        r"(?i)\bforget password\b",
        r"(?i)\bsystem design interview\b",
        r"(?i)\bexplain how (apis?|functions?) work\b",
        r"(?i)\bwrite a story about\b",
    ]

    def __init__(
        self,
        enabled: bool = True,
        model_name: str = "protectai/deberta-v3-base-prompt-injection-v2",
        threshold: float = 0.55,
        use_transformers: bool = True,
    ):
        self.enabled = enabled
        self.model_name = model_name
        self.threshold = threshold
        self.use_transformers = use_transformers
        self.pipeline = None
        self.backend = "heuristic"
        self._load_attempted = False
        # Lazy-load on first predict so API startup is not blocked by HF download

    def _ensure_transformers(self):
        if self._load_attempted or not self.use_transformers:
            return
        self._load_attempted = True
        self._try_load_transformers()

    def _try_load_transformers(self):
        try:
            from transformers import pipeline

            logger.info("Layer2B loading transformer (first use): %s", self.model_name)
            self.pipeline = pipeline(
                "text-classification",
                model=self.model_name,
                truncation=True,
                max_length=512,
            )
            self.backend = "transformer"
            logger.info("Layer2B transformer ready: %s", self.model_name)
        except Exception as exc:
            self.pipeline = None
            self.backend = "heuristic"
            logger.warning("Layer2B transformer unavailable, using heuristic: %s", exc)

    def predict(self, text: str) -> Dict:
        if not self.enabled:
            return self._empty()

        self._ensure_transformers()

        if self.pipeline is not None:
            try:
                return self._predict_transformer(text)
            except Exception as exc:
                logger.warning("Transformer predict failed, heuristic fallback: %s", exc)

        return self._predict_heuristic(text)

    def _predict_transformer(self, text: str) -> Dict:
        raw = self.pipeline(text[:2000])[0]
        label = str(raw.get("label", "")).lower()
        score = float(raw.get("score", 0.0))

        # Common label conventions across prompt-injection models
        malicious_labels = {"injection", "malicious", "unsafe", "attack", "label_1", "1"}
        is_mal = any(m in label for m in malicious_labels) or label in {"yes", "true"}
        # Some models use INJECTION / SAFE
        if "safe" in label or "benign" in label or "legitimate" in label:
            is_mal = False
        if "inject" in label or "unsafe" in label or "malicious" in label:
            is_mal = True

        risk = score if is_mal else 1.0 - score
        attack_type = self._heuristic_attack_type(text) if is_mal else "unknown"
        return {
            "enabled": True,
            "backend": "transformer",
            "is_malicious": bool(is_mal and risk >= self.threshold),
            "risk_score": float(risk),
            "confidence": float(score),
            "attack_type": attack_type,
            "label": label,
            "threshold": self.threshold,
        }

    def _predict_heuristic(self, text: str) -> Dict:
        text = text or ""
        for pattern in self.BENIGN_LOOKALIKES:
            if re.search(pattern, text):
                return {
                    "enabled": True,
                    "backend": "heuristic",
                    "is_malicious": False,
                    "risk_score": 0.15,
                    "confidence": 0.7,
                    "attack_type": "unknown",
                    "label": "benign_lookalike",
                    "threshold": self.threshold,
                }

        best_risk = 0.0
        best_type = "unknown"
        hits = 0
        for pattern, weight, attack_type in self.SEMANTIC_CUES:
            if re.search(pattern, text):
                hits += 1
                if weight > best_risk:
                    best_risk = weight
                    best_type = attack_type

        if hits >= 2:
            best_risk = min(1.0, best_risk + 0.15 * (hits - 1))

        is_mal = best_risk >= self.threshold
        return {
            "enabled": True,
            "backend": "heuristic",
            "is_malicious": is_mal,
            "risk_score": float(best_risk),
            "confidence": float(min(0.95, 0.4 + best_risk / 2)),
            "attack_type": best_type if is_mal else "unknown",
            "label": "semantic_heuristic",
            "threshold": self.threshold,
        }

    def _heuristic_attack_type(self, text: str) -> str:
        for pattern, _, attack_type in self.SEMANTIC_CUES:
            if re.search(pattern, text):
                return attack_type
        return "unknown"

    @staticmethod
    def _empty() -> Dict:
        return {
            "enabled": False,
            "backend": "disabled",
            "is_malicious": False,
            "risk_score": 0.0,
            "confidence": 0.0,
            "attack_type": "unknown",
            "label": None,
            "threshold": 0.0,
        }
