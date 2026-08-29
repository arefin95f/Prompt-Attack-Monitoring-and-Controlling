"""
Phase 4: Obfuscation / encoding normalization before classification.
"""

from __future__ import annotations

import base64
import re
import urllib.parse
from typing import Dict, List, Tuple


class TextNormalizer:
    """Normalize leetspeak, encodings, and invisible characters."""

    LEET_MAP = str.maketrans({
        "0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
        "7": "t", "@": "a", "$": "s", "!": "i",
    })

    ZERO_WIDTH = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]")

    def normalize(self, text: str) -> Dict:
        original = text or ""
        steps: List[str] = []
        current = original

        cleaned = self.ZERO_WIDTH.sub("", current)
        if cleaned != current:
            steps.append("strip_zero_width")
            current = cleaned

        decoded, decode_steps = self._try_decodes(current)
        if decode_steps:
            steps.extend(decode_steps)
            current = decoded

        unescaped = self._unescape(current)
        if unescaped != current:
            steps.append("unescape")
            current = unescaped

        leet = current.translate(self.LEET_MAP)
        # Only keep leet expansion if it reveals attack-ish terms
        if leet.lower() != current.lower():
            steps.append("leet_fold")
            current = leet

        collapsed = re.sub(r"(.)\1{3,}", r"\1\1", current)
        collapsed = re.sub(r"\s+", " ", collapsed).strip()
        if collapsed != current:
            steps.append("collapse_repeats")
            current = collapsed

        return {
            "original": original,
            "normalized": current,
            "steps": steps,
            "changed": current != original,
        }

    def _try_decodes(self, text: str) -> Tuple[str, List[str]]:
        steps: List[str] = []
        current = text

        # URL decode if percent-encoded
        if "%" in current and re.search(r"%[0-9a-fA-F]{2}", current):
            try:
                url_decoded = urllib.parse.unquote(current)
                if url_decoded != current:
                    current = url_decoded
                    steps.append("url_decode")
            except Exception:
                pass

        # Base64 only for token-like payloads (not normal English sentences)
        compact = re.sub(r"\s+", "", current)
        looks_like_sentence = len(current.split()) >= 4 and re.search(r"[aeiouAEIOU]", current) is not None
        if (
            not looks_like_sentence
            and re.fullmatch(r"[A-Za-z0-9+/]{32,}={0,2}", compact)
            and ("=" in compact or len(compact) % 4 == 0)
        ):
            try:
                pad = "=" * ((4 - len(compact) % 4) % 4)
                raw = base64.b64decode(compact + pad)
                decoded = raw.decode("utf-8", errors="ignore")
                printable_ratio = sum(c.isprintable() for c in decoded) / max(len(decoded), 1)
                has_words = len(re.findall(r"[A-Za-z]{3,}", decoded)) >= 2
                if decoded and printable_ratio > 0.85 and has_words:
                    current = decoded
                    steps.append("base64_decode")
            except Exception:
                pass

        return current, steps

    def _unescape(self, text: str) -> str:
        out = text
        out = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), out)
        out = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), out)
        out = re.sub(r"&#(\d+);", lambda m: chr(int(m.group(1))), out)
        return out
