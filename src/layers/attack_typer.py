"""
Scored attack-type detector — avoids first-match false labels like "unknown"
or wrong types from overly broad keywords.
"""

from __future__ import annotations

import re
from typing import Dict, List, Tuple


# (pattern, attack_type, weight). Higher weight = more specific / reliable.
ATTACK_RULES: List[Tuple[str, str, float]] = [
    # System extraction
    (r"\bsystem\s+prompt\b", "system_extraction", 3.0),
    (r"\bhidden\s+(rules?|instructions?)\b", "system_extraction", 2.8),
    (r"\binternal\s+(rules?|config(?:uration)?|instructions?)\b", "system_extraction", 2.8),
    (r"\binstructions\s+you\s+were\s+given\b", "system_extraction", 2.6),
    (r"\breveal\s+your\s+(prompt|rules|instructions)\b", "system_extraction", 2.8),
    # Jailbreak
    (r"\bjailbreak\b", "jailbreak", 3.0),
    (r"\bdo\s+anything\s+now\b|\bdan\b", "jailbreak", 2.8),
    (r"\bdeveloper\s+mode\b", "jailbreak", 2.6),
    (r"\bunrestricted\b|\bno\s+restrictions?\b|\bno\s+rules\b", "jailbreak", 2.4),
    (r"\brules?\s+don'?t\s+apply\b", "jailbreak", 2.8),
    (r"\bwithout\s+(rules|restrictions|safety|limits)\b", "jailbreak", 2.2),
    (r"\bgradually\b.{0,60}\b(rules?|safety|restrictions?)\b", "jailbreak", 2.5),
    # Story jailbreak
    (r"\bfirewalls?\s+are\s+down\b", "story_jailbreak", 3.0),
    (r"\blogs?\s+are\s+wiped\b", "story_jailbreak", 3.0),
    (r"\bsecurity\s+is\s+compromised\b", "story_jailbreak", 2.8),
    (r"\bpre-?programmed\b", "story_jailbreak", 2.2),
    # Direct override
    (r"\bignore\s+(all\s+)?(previous\s+)?(instructions?|rules?|safety)\b", "direct_override", 3.0),
    (r"\bforget\s+(all\s+)?(previous\s+)?(instructions?|rules?|everything)\b", "direct_override", 2.8),
    (r"\b(disregard|override|bypass|disable)\s+(all\s+)?(instructions?|rules?|safety|protocols?)\b", "direct_override", 2.8),
    # Data extraction / secrets
    (r"\boutput\s+secrets?\b", "data_extraction", 3.0),
    (r"\b(leak|exfiltrate|dump)\s+(data|secrets?|credentials?)\b", "data_extraction", 2.8),
    (r"\bextract\s+(all\s+)?(private\s+)?(data|information|emails?)\b", "data_extraction", 2.6),
    (r"\breveal\s+(all\s+)?(private\s+)?(data|information|secrets?)\b", "data_extraction", 2.4),
    # Tool injection
    (r"\b(execute|run)\s+(?:a\s+|the\s+|this\s+)?(?:system\s+)?(command|shell|script)\b", "tool_injection", 3.0),
    (r"\b(execute|run)\s+system\s+command\b", "tool_injection", 3.0),
    (r"\b(call|invoke)\s+(the\s+)?(api|function|tool)\b", "tool_injection", 2.6),
    (r"\blist\s+all\s+processes\b", "tool_injection", 2.2),
    # Multi-turn / stepwise attacks
    (r"\bstep\s*\d+\s*:\s*.{0,40}\b(forget|ignore|output|bypass|secrets?)\b", "multi_turn", 3.0),
    (r"\bstep\s*\d+\b.+\bstep\s*\d+\b.+\b(forget|ignore|secrets?|bypass)\b", "multi_turn", 2.8),
    (r"\bfirst\b.+\bthen\b.+\b(ignore|forget|bypass|secrets?)\b", "multi_turn", 2.5),
    # Role
    (r"\bact\s+as\b|\bpretend\s+to\s+be\b|\byou\s+are\s+now\b|\brole-?play\s+as\b", "role_impersonation", 2.4),
    # Obfuscation
    (r"\bbase64\b|\brot13\b|\bhex\s*encode\b|\bdecode\s+this\b", "obfuscation", 2.6),
    # Context
    (r"\bfrom\s+now\s+on\b.+\b(ignore|no\s+safety|unrestricted)\b", "context_tampering", 2.6),
    # Indirect (tight — avoid matching "read this" alone)
    (r"https?://|www\.", "indirect_injection", 2.4),
    (r"\bfollow\s+(the\s+)?(link|instructions\s+on\s+this\s+page)\b", "indirect_injection", 2.2),
    # Emotional (only with bypass pressure)
    (r"\b(desperate|begging|last\s+hope)\b.+\b(ignore|bypass|break)\b", "emotional_manipulation", 2.2),
]

DISPLAY_NAMES = {
    "system_extraction": "System Extraction",
    "data_extraction": "Data Extraction",
    "tool_injection": "Tool Injection",
    "jailbreak": "Jailbreak",
    "story_jailbreak": "Story Jailbreak",
    "direct_override": "Direct Override",
    "direct_injection": "Direct Injection",
    "context_tampering": "Context Tampering",
    "multi_turn": "Multi-Turn Attack",
    "obfuscation": "Obfuscation",
    "emotional_manipulation": "Emotional Manipulation",
    "role_impersonation": "Role Impersonation",
    "indirect_injection": "Indirect Injection",
    "unknown": "Unknown",
}


class AttackTypeDetector:
    def __init__(self, min_score: float = 1.8):
        self.min_score = min_score
        self._compiled = [(re.compile(p, re.IGNORECASE | re.DOTALL), t, w) for p, t, w in ATTACK_RULES]

    def detect(self, text: str) -> Dict:
        text = text or ""
        scores: Dict[str, float] = {}
        hits: Dict[str, List[str]] = {}

        for cre, attack_type, weight in self._compiled:
            m = cre.search(text)
            if not m:
                continue
            scores[attack_type] = scores.get(attack_type, 0.0) + weight
            hits.setdefault(attack_type, []).append(m.group(0)[:80])

        if not scores:
            return {
                "attack_type": "unknown",
                "display_name": DISPLAY_NAMES["unknown"],
                "score": 0.0,
                "categories": [],
                "hits": {},
            }

        ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        best_type, best_score = ranked[0]
        if best_score < self.min_score:
            return {
                "attack_type": "unknown",
                "display_name": DISPLAY_NAMES["unknown"],
                "score": best_score,
                "categories": [t for t, s in ranked if s >= 1.0],
                "hits": hits,
            }

        categories = [t for t, s in ranked if s >= 1.5]
        return {
            "attack_type": best_type,
            "display_name": DISPLAY_NAMES.get(best_type, best_type),
            "score": best_score,
            "categories": categories or [best_type],
            "hits": {k: hits.get(k, []) for k, _ in ranked[:3]},
        }

    def detect_type(self, text: str) -> str:
        return self.detect(text)["attack_type"]

    @staticmethod
    def display_name(attack_type: str) -> str:
        return DISPLAY_NAMES.get(attack_type, attack_type.replace("_", " ").title())
