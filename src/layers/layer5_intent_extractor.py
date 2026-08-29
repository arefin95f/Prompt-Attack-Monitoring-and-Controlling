"""
LAYER 5A: Intent extractor — separate legitimate goal from attack wrappers.
"""

from __future__ import annotations

import re
from typing import Dict, List, Tuple


class IntentExtractor:
    """Extract legitimate user intent from a flagged prompt."""

    WRAPPER_PATTERNS: List[Tuple[str, str]] = [
        (r"(?i)\bignore\s+(all\s+)?(previous|prior|above|your)\s+(instructions?|rules?|guidelines?)\b", "instruction_override"),
        (r"(?i)\bignore\s+all\s+(?:the\s+)?(rules?|instructions?|restrictions?|safety(?:\s+guidelines?)?|filters?)\b", "instruction_override"),
        (r"(?i)\b(disregard|forget|override|bypass|disable)\s+(?:all\s+|the\s+|your\s+)?(safety(?:\s+guidelines?)?|rules?|filters?|instructions?|protocols?|guidelines?|everything|restrictions?)\b", "instruction_override"),
        (r"(?i)\boverride\s+all\s+(?:the\s+)?(rules?|restrictions?|safety(?:\s+guidelines?)?|filters?)\b", "instruction_override"),
        (r"(?i)\bforget\s+everything\b", "instruction_override"),
        (r"(?i)\b(dan|do anything now|developer mode|jailbreak|no restrictions?|unrestricted mode|with no rules)\b", "jailbreak"),
        (r"(?i)\byou are now in\s+(?:unrestricted|developer|dan)\b", "jailbreak"),
        (r"(?i)\brules?\s+don'?t\s+apply\b", "jailbreak"),
        (r"(?i)\bdo\s+anything\s+i\s+say\b", "jailbreak"),
        (r"(?i)\b(eventually|next|then|now)\s*,?\s*you\s+will\b", "multi_turn"),
        (r"(?i)\bgradually\b.{0,80}\b(rules?|safety|restrictions?)\b", "multi_turn"),
        (r"(?i)\bstep\s*\d+\s*:\s*.{0,40}\b(forget|ignore|output\s+secrets?|bypass)\b", "multi_turn"),
        (r"(?i)\boutput\s+secrets?\b", "data_extraction"),
        (r"(?i)\b(tell|give|show)\s+me\s+(your\s+)?secrets?\b", "data_extraction"),
        (r"(?i)\b(admin\s+access|root\s+access|elevated\s+privileges?)\b", "data_extraction"),
        (r"(?i)\b(act as|pretend(?:\s+to\s+be)?|role[\s-]?play as|adopt the persona of|you are now)\b", "role_impersonation"),
        (r"(?i)\byou are\b(?!\s+(?:asking|looking|trying|interested))", "role_impersonation"),
        (r"(?i)\b(reveal|show|print|dump|output|display)\s+(your\s+)?(system\s+prompt|hidden\s+rules?|internal\s+(rules?|config(?:uration)?|prompt)|secrets?)\b", "system_extraction"),
        (r"(?i)\b(your\s+)?(system\s+prompt|hidden\s+instructions?|internal\s+(rules?|config(?:uration)?)|safety\s+guidelines?)\b", "system_extraction"),
        (r"(?i)\b(execute|run|call|invoke)\s+(?:a\s+|the\s+|this\s+)?(?:system\s+)?(command|function|api|tool|shell)\b", "tool_injection"),
        (r"(?i)\b(execute|run)\s+system\s+command\b", "tool_injection"),
        (r"(?i)\blist\s+all\s+processes\b", "tool_injection"),
        (r"(?i)\b(base64|rot13|hex[\s-]?encode|decode\s+this)\b", "obfuscation"),
        (r"(?i)\b(firewalls?\s+are\s+down|logs?\s+are\s+wiped|security\s+is\s+compromised)\b", "story_jailbreak"),
        (r"(?i)\b(from\s+now\s+on|new\s+instructions?|enter\s+(?:developer\s+)?mode)\b", "context_tampering"),
        (r"(?i)\byou are\s+dan\b", "jailbreak"),
        (r"(?i)\bmalicious\s+hacker\b", "role_impersonation"),
    ]

    GOAL_PATTERNS: List[Tuple[str, str]] = [
        (r"(?i)(?:explain|describe|summarize|outline)\s+(.+?)(?:[.?!]|$)", "explain"),
        (r"(?i)(?:how\s+(?:do|can|to|does|would)\s+(?:i|you|we|one)?\s*)(.+?)(?:[.?!]|$)", "how_to"),
        (r"(?i)(?:what\s+(?:is|are|was|were)\s+)(.+?)(?:[.?!]|$)", "define"),
        (r"(?i)(?:help\s+me\s+(?:with|to|understand)\s+)(.+?)(?:[.?!]|$)", "help"),
        (r"(?i)(?:write|create|generate|draft|make)\s+(?:a\s+|an\s+|the\s+)?(.+?)(?:[.?!]|$)", "create"),
        (r"(?i)(?:compare|difference(?:s)?\s+between)\s+(.+?)(?:[.?!]|$)", "compare"),
        (r"(?i)(?:list|give\s+me)\s+(.+?)(?:[.?!]|$)", "list"),
        (r"(?i)(?:teach\s+me|tell\s+me\s+about|learn\s+about)\s+(.+?)(?:[.?!]|$)", "learn"),
        (r"(?i)(?:step[\s-]*by[\s-]*step)\s+(?:lesson|lession|guide|tutorial)?\s*(?:on|about|for)?\s*(.+?)(?:[.?!]|$)", "learn"),
        (r"(?i)(?:lesson|lession)\s+(?:on|about|for)\s+(.+?)(?:[.?!]|$)", "learn"),
        (r"(?i)^\s*(?:step[\s-]*by[\s-]*step)\s+(lesson|lession)\s*$", "learn"),
        (r"(?i)(?:instead[, ]+|but\s+actually[, ]+|just\s+)(.+?)(?:[.?!]|$)", "request"),
        (r"(?i)(?:i\s+(?:want|need|would\s+like)\s+(?:to\s+)?)(.+?)(?:[.?!]|$)", "request"),
        (r"(?i)about\s+([A-Za-z][^.?!]{2,80})", "learn"),
    ]

    # Topics that are attack residue — never treat as user intent
    BLOCKED_TOPICS = {
        "system prompt", "system prompts", "hidden rules", "internal rules",
        "jailbreak", "jailbreak now", "dan", "developer mode", "safety guidelines",
        "reveal system prompt", "your system prompt", "prompt", "secrets",
        "output secrets", "forget everything", "rules don't apply", "rules dont apply",
        "internal configuration", "internal config", "your internal configuration",
        "configuration", "admin access", "root access", "unrestricted mode",
        "safety filters", "safety rules", "guidelines", "restrictions",
        "malicious hacker", "hacker", "persona", "anything i say",
        "your secrets", "me secrets", "filters", "bypass",
        "next you will", "eventually you will", "you will show me",
        "show me", "your internal", "all rules",
    }

    BLOCKED_TOPIC_FRAGMENTS = (
        "system prompt", "internal config", "internal rules", "hidden rules",
        "admin access", "root access", "unrestricted", "jailbreak",
        "developer mode", "safety filter", "safety guideline", "malicious",
        "bypass", "override", "disregard", "secrets", "secret", "persona of",
        "do anything", "no rules", "ignore all", "guideline", "guidelines",
        "filter", "filters", "restriction", "restrictions",
        "all processes", "list processes", "list all process",
    )

    STOP_TOPICS = {
        "this", "that", "it", "them", "something", "anything", "everything",
        "me", "you", "your", "my", "the", "a", "an", "this topic", "now",
        "next", "eventually", "then", "please", "will", "would", "could",
        "should", "must", "need", "want", "say", "said", "show", "tell",
    }

    BENIGN_CUES = (
        "explain", "how", "what", "why", "when", "where", "who",
        "write", "create", "help", "about", "teach", "learn",
        "summarize", "compare", "list", "describe", "define",
        "tell me about", "lesson", "tutorial", "guide",
    )

    def extract(self, text: str, attack_type: str = "unknown") -> Dict:
        original = (text or "").strip()
        # Strip leading reject/confirm chatter before intent parsing
        working = re.sub(
            r"(?i)^\s*(no|nah|nope|not that|instead)[,.!]?\s+",
            "",
            original,
        ).strip()

        wrappers: List[str] = []
        cleaned = working

        for pattern, label in self.WRAPPER_PATTERNS:
            if re.search(pattern, cleaned):
                wrappers.append(label)
                cleaned = re.sub(pattern, " ", cleaned)

        cleaned = re.sub(r"(?i)\b(show|tell|give|reveal|print|dump|display)\s+(me\s+)?(your\s+)?\b", " ", cleaned)
        cleaned = re.sub(r"(?i)\b(secrets?|guidelines?|filters?|restrictions?|rules?)\b", " ", cleaned)
        cleaned = re.sub(r"^\s*(?:and|then|please|,|\.|:)\s+", " ", cleaned)
        cleaned = re.sub(r"\b(and|or|the|a|an|to|of|for|with)\b", " ", cleaned, flags=re.I)
        cleaned = re.sub(r"\s{2,}", " ", cleaned).strip(" \t\n\r,.;:-")
        if len(cleaned.split()) < 2 and not self._has_benign_cue(cleaned):
            cleaned = ""

        action, topic, goal = self._extract_goal(cleaned)
        if action == "unknown" or self._is_blocked_topic(topic):
            action2, topic2, goal2 = self._extract_goal(working)
            if action2 != "unknown" and not self._is_blocked_topic(topic2):
                action, topic, goal = action2, topic2, goal2

        if not topic or topic.lower() in self.STOP_TOPICS or self._is_blocked_topic(topic):
            fallback = self._fallback_topic(cleaned)
            if fallback != "this topic" and not self._is_blocked_topic(fallback):
                topic = fallback
            else:
                topic = "this topic"

        if self._is_blocked_topic(goal) or self._is_blocked_topic(topic) or self._is_blocked_topic(cleaned):
            goal = ""
            topic = "this topic"
            action = "unknown"
            cleaned = ""

        # Pure attack leftovers like "your internal configuration" / "admin access"
        if cleaned and (self._is_blocked_topic(cleaned) or not self._has_benign_cue(cleaned)):
            if wrappers and not self._has_benign_cue(working):
                goal = ""
                topic = "this topic"
                action = "unknown"
                cleaned = ""

        # After wrappers, execution leftovers are not educational intent
        if "tool_injection" in wrappers:
            if re.search(r"(?i)\b(process(?:es)?|shell|terminal|cmd|powershell|bash)\b", cleaned or original):
                if not re.search(r"(?i)\b(what is|what are|explain|how does|how do|mean(?:ing)?)\b", original):
                    goal = ""
                    topic = "this topic"
                    action = "unknown"
                    cleaned = ""

        has_clear_intent = self._is_clear_intent(cleaned, topic, goal, wrappers, working, action)
        confidence = self._confidence(has_clear_intent, topic, wrappers, cleaned, working)

        return {
            "intent": action if action != "unknown" else "general_curiosity",
            "action": action,
            "topic": topic if has_clear_intent else "this topic",
            "goal": goal if has_clear_intent else "",
            "format": self._detect_format(original),
            "constraints": self._detect_constraints(original),
            "legitimate_request": cleaned if cleaned and has_clear_intent and not self._is_blocked_topic(cleaned) else "",
            "malicious_wrappers": sorted(set(wrappers)) or ([attack_type] if attack_type != "unknown" else []),
            "intent_confidence": confidence,
            "has_clear_intent": has_clear_intent,
            "is_pure_attack": bool(wrappers) and not has_clear_intent,
            "question_type": "question" if "?" in original else "statement",
            "original_text": original,
        }

    def _has_benign_cue(self, text: str) -> bool:
        lower = (text or "").lower()
        return any(c in lower for c in self.BENIGN_CUES)

    def _is_blocked_topic(self, text: str) -> bool:
        if not text:
            return False
        lower = text.lower().strip()
        if lower in self.BLOCKED_TOPICS:
            return True
        if any(frag in lower for frag in self.BLOCKED_TOPIC_FRAGMENTS):
            return True
        # short leftover phrases that are only attack nouns
        if len(lower.split()) <= 4 and any(
            w in lower for w in ("secret", "config", "prompt", "access", "filter", "hack", "persona", "unrestricted")
        ):
            return True
        return False

    def _extract_goal(self, text: str) -> Tuple[str, str, str]:
        if not text:
            return "unknown", "this topic", ""
        for pattern, action in self.GOAL_PATTERNS:
            match = re.search(pattern, text)
            if not match:
                continue
            raw = match.group(1).strip(" \t\n\r\"'`")
            raw = re.sub(r"(?i)\b(in\s+a\s+safe\s+way|without\s+restrictions?|ignoring\s+rules?)\b", "", raw)
            raw = re.sub(r"\s{2,}", " ", raw).strip(" ,.;:")
            if len(raw) < 3:
                continue
            topic = self._normalize_topic(raw)
            if self._is_blocked_topic(topic) or self._is_blocked_topic(raw):
                continue
            goal = raw[:160]
            return action, topic, goal

        # Do NOT invent topics from leftover attack words
        if not self._has_benign_cue(text):
            return "unknown", "this topic", ""

        words = [
            w for w in re.findall(r"[A-Za-z][A-Za-z0-9\-]{2,}", text)
            if w.lower() not in self.STOP_TOPICS
        ]
        topic = " ".join(words[:6]) if words else "this topic"
        if self._is_blocked_topic(topic):
            return "unknown", "this topic", ""
        return "unknown", topic[:80], text[:160] if text else ""

    def _normalize_topic(self, raw: str) -> str:
        topic = re.sub(r"(?i)^(a|an|the|some|my|our|your)\s+", "", raw).strip()
        topic = re.split(r"\b(?:and then|but|without|while|using)\b", topic, maxsplit=1)[0]
        topic = topic.strip(" ,.;:")
        if len(topic) > 80:
            topic = topic[:80].rsplit(" ", 1)[0]
        return topic or "this topic"

    def _fallback_topic(self, text: str) -> str:
        if not text or not self._has_benign_cue(text):
            return "this topic"
        words = [
            w for w in re.findall(r"[A-Za-z][A-Za-z0-9\-]{2,}", text or "")
            if w.lower() not in self.STOP_TOPICS
        ]
        if not words:
            return "this topic"
        candidate = " ".join(words[:5])
        return "this topic" if self._is_blocked_topic(candidate) else candidate

    def _detect_format(self, text: str) -> str:
        lower = text.lower()
        if any(k in lower for k in ("bullet", "list", "steps", "numbered")):
            return "list"
        if any(k in lower for k in ("code", "script", "snippet", "function")):
            return "code"
        if any(k in lower for k in ("summary", "summarize", "tldr")):
            return "summary"
        if any(k in lower for k in ("essay", "paragraph", "write", "draft")):
            return "prose"
        return "general"

    def _detect_constraints(self, text: str) -> List[str]:
        constraints = []
        lower = text.lower()
        if "beginner" in lower or "simple" in lower or "eli5" in lower:
            constraints.append("keep_it_simple")
        if "detailed" in lower or "in depth" in lower or "thorough" in lower:
            constraints.append("detailed")
        if "short" in lower or "brief" in lower:
            constraints.append("brief")
        return constraints

    def _is_clear_intent(
        self,
        cleaned: str,
        topic: str,
        goal: str,
        wrappers: List[str],
        original: str,
        action: str,
    ) -> bool:
        if not topic or topic.lower() in self.STOP_TOPICS or self._is_blocked_topic(topic):
            return False
        if self._is_blocked_topic(goal) or self._is_blocked_topic(cleaned):
            return False
        if not self._has_benign_cue(cleaned or goal or original):
            # Allow place/topic nouns only when action was matched from a goal pattern
            if action == "unknown":
                return False
        if action != "unknown" and topic.lower() not in self.STOP_TOPICS and not self._is_blocked_topic(topic):
            return True
        content_words = re.findall(r"[A-Za-z]{3,}", cleaned or "")
        if len(content_words) >= 2 and len(cleaned) >= 8 and self._has_benign_cue(cleaned):
            return True
        if wrappers and len(content_words) < 2:
            return False
        if len(original.split()) <= 5 and not self._has_benign_cue(original):
            return False
        return bool(goal) and len(goal.split()) >= 3 and not self._is_blocked_topic(goal) and self._has_benign_cue(goal)

    def _confidence(
        self,
        has_clear_intent: bool,
        topic: str,
        wrappers: List[str],
        cleaned: str,
        original: str,
    ) -> float:
        if not has_clear_intent:
            return 0.15 if wrappers else 0.3
        score = 0.55
        if topic and topic.lower() not in self.STOP_TOPICS:
            score += 0.15
        if cleaned and len(cleaned.split()) >= 2:
            score += 0.15
        if wrappers:
            score += 0.05
        if len(original) > 20:
            score += 0.05
        return round(min(score, 0.95), 2)
