"""
LAYER 5: Intent-preserving conversational safe-prompt generator (Phase 1).
"""

from __future__ import annotations

import logging
import random
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

from .layer5_intent_extractor import IntentExtractor
from .layer5_rewriter import IntentPreservingRewriter

logger = logging.getLogger(__name__)


@dataclass
class ConversationState:
    original_prompt: str
    attack_type: str
    risk_score: float
    current_suggestion: str
    alternatives: List[str] = field(default_factory=list)
    intent: Dict = field(default_factory=dict)
    status: str = "waiting_for_response"
    turns: int = 0
    conversation_id: str = ""
    user_edits: List[str] = field(default_factory=list)
    rejected_count: int = 0
    rewrite: Dict = field(default_factory=dict)
    needs_clarification: bool = False


class NaturalConversationalGenerator:
    """Layer 5: extract intent → rewrite safely → check fidelity → converse."""

    def __init__(
        self,
        intent_preserving: bool = True,
        use_llm_rewrite: bool = False,
        fidelity_threshold: float = 0.35,
        clarify_threshold: float = 0.45,
    ):
        self.intent_preserving = intent_preserving
        self.extractor = IntentExtractor()
        self.rewriter = IntentPreservingRewriter(
            use_llm=use_llm_rewrite,
            fidelity_threshold=fidelity_threshold,
            clarify_threshold=clarify_threshold,
        )
        self.conversations: Dict[str, ConversationState] = {}
        self.fallback_suggestion = "Could you rephrase your question in a general way?"

        # Legacy fallbacks when intent_preserving is disabled
        self.suggestions = {
            "tool_injection": "Explain how operating systems list and manage running processes.",
            "jailbreak": "What would you like help with today?",
            "story_jailbreak": "What topic would you like explained clearly?",
            "direct_override": "What are you trying to learn or accomplish?",
            "direct_injection": "What are you trying to learn or accomplish?",
            "context_tampering": "What is your real question?",
            "multi_turn": "What is your main question?",
            "obfuscation": "Please ask your question in plain words.",
            "emotional_manipulation": "How can I help you today?",
            "role_impersonation": "What would you like to know or learn?",
            "indirect_injection": "Please ask your question directly.",
            "unknown": "What would you like help with today?",
            "system_extraction": "Explain at a high level how AI assistants are instructed and configured.",
            "data_extraction": "What general topic can I help you understand?",
        }

        self.human_openers = [
            "Hey - I caught something unsafe in that request.",
            "Hold on - that phrasing looks a bit risky.",
            "I can't follow that version as written.",
            "That one's unsafe for me to run as-is.",
        ]

        self.attack_blurbs = {
            "system_extraction": "It looks like it was asking for internal system details.",
            "data_extraction": "It looks like it was trying to pull private or sensitive data.",
            "tool_injection": "It looks like it was trying to run commands or tools directly.",
            "jailbreak": "It looks like a jailbreak attempt to bypass safety rules.",
            "story_jailbreak": "It looks like a story was used to try to bypass safety.",
            "direct_override": "It looks like it was trying to override my instructions.",
            "direct_injection": "It looks like conflicting instructions were injected into the prompt.",
            "context_tampering": "It looks like it was trying to rewrite the conversation context.",
            "multi_turn": "It looks like a step-by-step attempt to slip past safety checks.",
            "obfuscation": "It looks like the meaning was hidden with encoding or odd wording.",
            "emotional_manipulation": "It looks like emotional pressure was used to bypass safety.",
            "role_impersonation": "It looks like it was trying to force a different role or persona.",
            "indirect_injection": "It looks like external content was used to sneak in instructions.",
            "unknown": "Our safety filter flagged this request.",
        }

    def get_conversation_response(self, prompt: str, attack_type: str, risk_score: float) -> Dict:
        try:
            if not self.intent_preserving:
                return self._legacy_response(prompt, attack_type, risk_score)

            intent = self.extractor.extract(prompt, attack_type=attack_type)
            rewrite = self.rewriter.rewrite(intent, attack_type=attack_type, risk_score=risk_score)

            conv_id = f"conv_{int(datetime.now().timestamp())}_{random.randint(1000, 9999)}"
            safe_prompt = (rewrite.get("safe_prompt") or "").strip() or self.suggestions.get(
                attack_type, self.fallback_suggestion
            )

            response = self._build_response(attack_type, intent, {**rewrite, "safe_prompt": safe_prompt})
            status = "waiting_for_response"

            state = ConversationState(
                original_prompt=prompt,
                attack_type=attack_type,
                risk_score=risk_score,
                current_suggestion=safe_prompt,
                alternatives=[],
                intent=intent,
                conversation_id=conv_id,
                rewrite={**rewrite, "safe_prompt": safe_prompt},
                needs_clarification=False,
                status=status,
            )
            self.conversations[conv_id] = state

            return {
                "conversation_id": conv_id,
                "response": response,
                "suggestion": safe_prompt,
                "alternatives": [],
                "topic": intent.get("topic", "this topic"),
                "attack_type": attack_type,
                "risk_score": risk_score,
                "status": status,
                "legitimate_intent": rewrite.get("legitimate_intent") or intent.get("goal") or "",
                "removed_risks": rewrite.get("removed_risks") or [],
                "intent_confidence": intent.get("intent_confidence"),
                "fidelity_score": rewrite.get("fidelity_score", 0.0),
                "needs_clarification": False,
                "clarifying_question": None,
                "rewrite_source": rewrite.get("source", "heuristic"),
                "explanation": self.attack_blurbs.get(attack_type, self.attack_blurbs["unknown"]),
            }
        except Exception as exc:
            logger.exception("Layer 5 failed: %s", exc)
            conv_id = f"conv_{int(datetime.now().timestamp())}_{random.randint(1000, 9999)}"
            fallback = self.suggestions.get(attack_type, self.fallback_suggestion)
            state = ConversationState(
                original_prompt=prompt,
                attack_type=attack_type,
                risk_score=risk_score,
                current_suggestion=fallback,
                conversation_id=conv_id,
                needs_clarification=False,
            )
            self.conversations[conv_id] = state
            return {
                "conversation_id": conv_id,
                "response": self._build_response(
                    attack_type,
                    {"has_clear_intent": False, "is_pure_attack": True},
                    {"safe_prompt": fallback},
                ),
                "suggestion": fallback,
                "alternatives": [],
                "topic": "this topic",
                "attack_type": attack_type,
                "risk_score": risk_score,
                "status": "waiting_for_response",
                "needs_clarification": False,
                "clarifying_question": None,
                "legitimate_intent": "",
                "removed_risks": [],
                "fidelity_score": 0.0,
                "explanation": self.attack_blurbs.get(attack_type, self.attack_blurbs["unknown"]),
            }

    def process_user_response(
        self,
        conversation_id: str,
        user_message: str,
        fallback_suggestion: str = "",
    ) -> Dict:
        try:
            if conversation_id not in self.conversations:
                # Recover with client-provided suggestion if API restarted
                suggestion = (fallback_suggestion or self.fallback_suggestion).strip()
                conv_id = conversation_id or f"conv_{int(datetime.now().timestamp())}_{random.randint(1000, 9999)}"
                self.conversations[conv_id] = ConversationState(
                    original_prompt="",
                    attack_type="unknown",
                    risk_score=0.5,
                    current_suggestion=suggestion,
                    conversation_id=conv_id,
                )
                conversation_id = conv_id

            state = self.conversations[conversation_id]
            if not state.current_suggestion and fallback_suggestion:
                state.current_suggestion = fallback_suggestion.strip()
            if not state.current_suggestion:
                state.current_suggestion = self.suggestions.get(
                    state.attack_type, self.fallback_suggestion
                )

            state.turns += 1
            user_lower = user_message.lower().strip()
            topic = state.intent.get("topic", "this topic") if state.intent else "this topic"

            confirm_words = [
                "ok", "okay", "sure", "yes", "yeah", "yep", "fine", "great",
                "perfect", "good", "works", "go", "do it", "go ahead",
                "proceed", "use it", "try it", "sounds good", "alright",
                "absolutely", "definitely", "i agree", "i accept", "continue",
                "use that", "try that",
            ]
            # Exact/short confirms only (avoid "yes but explain X")
            is_confirm = user_lower in confirm_words or (
                len(user_lower.split()) <= 3 and any(user_lower == w or user_lower.startswith(w + " ") for w in confirm_words)
            )
            if is_confirm and state.current_suggestion:
                return {
                    "conversation_id": conversation_id,
                    "response": "Great - using your safe prompt now.",
                    "suggestion": state.current_suggestion,
                    "final_prompt": state.current_suggestion,
                    "confirmed": True,
                    "status": "confirmed",
                    "legitimate_intent": (state.rewrite or {}).get("legitimate_intent", ""),
                }
            if is_confirm and not state.current_suggestion:
                return {
                    "conversation_id": conversation_id,
                    "response": "I still need your real question first - tell me what you want help with in plain words.",
                    "suggestion": "",
                    "confirmed": False,
                    "status": "waiting_for_response",
                    "needs_clarification": True,
                }

            reject_words = [
                "no", "nah", "nope", "not that", "don't like", "don't want",
                "not good", "try again", "not what i meant", "no thanks",
            ]
            is_reject = user_lower in reject_words or (
                len(user_lower.split()) <= 3 and any(w == user_lower for w in reject_words)
            )
            if is_reject:
                state.rejected_count += 1
                new_suggestion = self._next_alternative(state) or self.fallback_suggestion
                state.current_suggestion = new_suggestion
                return {
                    "conversation_id": conversation_id,
                    "response": (
                        f"No problem - another safer version: \"{new_suggestion}\" "
                        "Want me to use this one?"
                    ),
                    "suggestion": new_suggestion,
                    "confirmed": False,
                    "status": "waiting_for_response",
                    "needs_clarification": False,
                }

            # Any other message = check if still an attack, else treat as real intent
            return self._rewrite_from_clarification(state, user_message)
        except Exception as exc:
            logger.exception("process_user_response failed: %s", exc)
            fallback = fallback_suggestion or self.fallback_suggestion
            return {
                "conversation_id": conversation_id,
                "response": self._build_response("unknown", {}, {"safe_prompt": fallback}),
                "suggestion": fallback,
                "confirmed": False,
                "status": "waiting_for_response",
            }

    def _rewrite_from_clarification(self, state: ConversationState, user_message: str) -> Dict:
        """User clarified intent — rebuild a safe prompt, or refuse continued attacks."""
        cleaned_msg = re.sub(
            r"(?i)^\s*(no|nah|nope|not that|instead)[,.!]?\s+",
            "",
            (user_message or "").strip(),
        ).strip() or (user_message or "").strip()

        intent = self.extractor.extract(cleaned_msg, attack_type=state.attack_type)
        wrappers = intent.get("malicious_wrappers") or []
        still_attack = bool(intent.get("is_pure_attack")) or (
            wrappers and not intent.get("has_clear_intent")
        )

        # Continued jailbreak / override with no real topic
        if still_attack:
            # Refresh attack label when wrappers give a clearer type
            if "jailbreak" in wrappers:
                state.attack_type = "jailbreak"
            elif "role_impersonation" in wrappers:
                state.attack_type = "role_impersonation"
            elif "system_extraction" in wrappers:
                state.attack_type = "system_extraction"
            elif "instruction_override" in wrappers:
                state.attack_type = "direct_override"
            elif "multi_turn" in wrappers:
                state.attack_type = "multi_turn"
            elif "tool_injection" in wrappers:
                state.attack_type = "tool_injection"

            rewrite = self.rewriter.rewrite(intent, attack_type=state.attack_type, risk_score=state.risk_score)
            suggestion = (rewrite.get("safe_prompt") or "").strip() or self.fallback_suggestion
            state.intent = intent
            state.rewrite = {**rewrite, "safe_prompt": suggestion}
            state.current_suggestion = suggestion
            state.needs_clarification = False
            state.status = "waiting_for_response"
            return {
                "conversation_id": state.conversation_id,
                "response": self._build_response(state.attack_type, intent, {**rewrite, "safe_prompt": suggestion}),
                "suggestion": suggestion,
                "alternatives": [],
                "confirmed": False,
                "status": "waiting_for_response",
                "needs_clarification": False,
                "legitimate_intent": "",
                "removed_risks": rewrite.get("removed_risks") or [],
                "fidelity_score": 0.0,
                "intent_confidence": intent.get("intent_confidence"),
                "explanation": self.attack_blurbs.get(state.attack_type, self.attack_blurbs["unknown"]),
                "attack_type": state.attack_type,
            }

        # Real clarification / topic change — only boost confidence when intent is clear
        if intent.get("has_clear_intent") and len(cleaned_msg.split()) >= 2:
            intent["legitimate_request"] = intent.get("legitimate_request") or cleaned_msg
            intent["intent_confidence"] = max(float(intent.get("intent_confidence", 0.5)), 0.8)
            if re.search(r"(?i)step[\s-]*by[\s-]*step", cleaned_msg) or "lesson" in cleaned_msg.lower():
                intent["action"] = "learn"
                intent["intent"] = "learn"
        elif len(cleaned_msg.split()) >= 2 and not self.rewriter._looks_attackish(cleaned_msg):
            # Plain topic like "tell me about Dhaka" / "Dhaka"
            if re.search(r"(?i)\b(tell me about|about|explain|what is|how)\b", cleaned_msg) or len(cleaned_msg.split()) <= 6:
                intent["has_clear_intent"] = True
                intent["intent_confidence"] = 0.85
                intent["legitimate_request"] = cleaned_msg
                intent["goal"] = cleaned_msg[:160]
                if not intent.get("topic") or intent.get("topic") == "this topic":
                    intent["topic"] = cleaned_msg
                    intent["action"] = "learn"

        rewrite = self.rewriter.rewrite(intent, attack_type=state.attack_type, risk_score=state.risk_score)
        suggestion = (rewrite.get("safe_prompt") or "").strip()
        if self._is_ready_safe_question(cleaned_msg):
            suggestion = self.rewriter._polish_prompt(cleaned_msg) or suggestion
        if not suggestion:
            suggestion = self.fallback_suggestion

        state.intent = intent
        state.rewrite = {**rewrite, "safe_prompt": suggestion}
        state.needs_clarification = False
        state.user_edits.append(user_message)
        state.current_suggestion = suggestion
        state.alternatives = []
        state.status = "waiting_for_response"

        # Clear safe follow-up → confirm for LLM answer (no "Got it" / no reply-yes)
        if self._is_ready_safe_question(cleaned_msg):
            state.status = "confirmed"
            return {
                "conversation_id": state.conversation_id,
                "response": "",
                "suggestion": suggestion,
                "final_prompt": suggestion,
                "confirmed": True,
                "status": "confirmed",
                "needs_clarification": False,
                "legitimate_intent": rewrite.get("legitimate_intent") or intent.get("goal") or suggestion,
                "removed_risks": rewrite.get("removed_risks") or [],
                "fidelity_score": rewrite.get("fidelity_score", 0.0),
                "intent_confidence": intent.get("intent_confidence"),
                "explanation": self.attack_blurbs.get(state.attack_type, self.attack_blurbs["unknown"]),
            }

        reply = (
            f'Sounds good - safer version: "{suggestion}" '
            "Reply yes and I'll use it."
        )

        return {
            "conversation_id": state.conversation_id,
            "response": reply,
            "suggestion": suggestion,
            "alternatives": [],
            "confirmed": False,
            "status": "waiting_for_response",
            "needs_clarification": False,
            "legitimate_intent": rewrite.get("legitimate_intent") or intent.get("goal") or "",
            "removed_risks": rewrite.get("removed_risks") or [],
            "fidelity_score": rewrite.get("fidelity_score", 0.0),
            "intent_confidence": intent.get("intent_confidence"),
            "explanation": self.attack_blurbs.get(state.attack_type, self.attack_blurbs["unknown"]),
        }

    def _is_ready_safe_question(self, text: str) -> bool:
        """True when the user already asked a plain, safe question we can run."""
        t = (text or "").strip()
        if len(t.split()) < 2:
            return False
        if self.rewriter._looks_attackish(t):
            return False
        wrappers = self.extractor.extract(t).get("malicious_wrappers") or []
        # Only treat as attack wrappers if they look like real attack labels
        attack_labels = {
            "instruction_override", "jailbreak", "tool_injection", "system_extraction",
            "data_extraction", "role_impersonation", "multi_turn", "obfuscation",
            "story_jailbreak", "context_tampering", "direct_override", "direct_injection",
        }
        if any(w in attack_labels for w in wrappers):
            return False
        return bool(
            re.search(
                r"(?i)^(what|who|why|when|where|how|explain|describe|tell me|define|is|are|can|could|would|should)\b",
                t,
            )
            or "?" in t
        )

    def _build_response(self, attack_type: str, intent: Dict, rewrite: Dict) -> str:
        """Explain the block + always offer a heuristic safe alternative."""
        safe = (rewrite.get("safe_prompt") or "").strip() or self.fallback_suggestion
        blurb = self.attack_blurbs.get(attack_type, self.attack_blurbs["unknown"])
        opener = random.choice(self.human_openers)

        has_clear = bool((intent or {}).get("has_clear_intent")) and not (intent or {}).get("is_pure_attack")
        topic = (intent or {}).get("topic") or ""
        goal = (intent or {}).get("goal") or ""
        legit = (rewrite or {}).get("legitimate_intent") or (intent or {}).get("legitimate_request") or ""
        focus = ""
        for candidate in (topic, goal, legit):
            c = (candidate or "").strip()
            if not c or c.lower() in {"this topic", "this", "that"}:
                continue
            if self.rewriter._looks_attackish(c):
                continue
            c = re.sub(r"(?i)^(about|on|for)\s+", "", c).strip()
            if c:
                focus = c
                break

        if has_clear and focus:
            if len(focus) > 70:
                focus = focus[:67].rsplit(" ", 1)[0] + "..."
            return (
                f"{opener} {blurb} "
                f'If you meant "{focus}", try: "{safe}" '
                "Reply yes to use this, or tell me what you meant."
            )

        return (
            f"{opener} {blurb} "
            f'Safe alternative: "{safe}" '
            "Reply yes to use this, or tell me what you meant in plain words."
        )

    def _reason_response(self, attack_type: str, intent: Dict) -> str:
        return self._build_response(
            attack_type,
            intent or {},
            {"safe_prompt": self.suggestions.get(attack_type, self.fallback_suggestion)},
        )

    def _legacy_response(self, prompt: str, attack_type: str, risk_score: float) -> Dict:
        safe_prompt = self.suggestions.get(attack_type, self.fallback_suggestion)
        conv_id = f"conv_{int(datetime.now().timestamp())}_{random.randint(1000, 9999)}"
        topic = self.extractor.extract(prompt).get("topic", "this topic")
        state = ConversationState(
            original_prompt=prompt,
            attack_type=attack_type,
            risk_score=risk_score,
            current_suggestion=safe_prompt,
            alternatives=[safe_prompt, self.fallback_suggestion],
            intent={"topic": topic},
            conversation_id=conv_id,
        )
        self.conversations[conv_id] = state
        return {
            "conversation_id": conv_id,
            "response": self._build_response(
                attack_type,
                {"topic": topic},
                {"safe_prompt": safe_prompt},
            ),
            "suggestion": safe_prompt,
            "alternatives": [safe_prompt, self.fallback_suggestion],
            "topic": topic,
            "attack_type": attack_type,
            "risk_score": risk_score,
            "status": "waiting_for_response",
            "needs_clarification": False,
            "explanation": self.attack_blurbs.get(attack_type, self.attack_blurbs["unknown"]),
        }

    def _next_alternative(self, state: ConversationState) -> str:
        """Always return another usable safe suggestion."""
        defaults = [
            "What would you like help with today?",
            "What is your main question?",
            "Explain this topic in simple terms.",
            self.fallback_suggestion,
        ]
        for suggestion in list(state.alternatives) + defaults:
            if suggestion and suggestion != state.current_suggestion:
                if suggestion not in state.alternatives:
                    state.alternatives.append(suggestion)
                return suggestion
        return self.fallback_suggestion

    def _get_reason(self, attack_type: str) -> str:
        reasons = {
            "system_extraction": "it asked for internal system information",
            "data_extraction": "it tried to access private data",
            "tool_injection": "it tried to execute commands",
            "jailbreak": "it tried to break safety rules",
            "story_jailbreak": "it used a story to bypass security",
            "direct_override": "it tried to override instructions",
            "direct_injection": "it tried to override instructions",
            "context_tampering": "it tried to change the conversation context",
            "multi_turn": "it was building up to something step by step",
            "obfuscation": "it used encoding to hide its meaning",
            "emotional_manipulation": "it used emotional appeals to bypass safety",
            "role_impersonation": "it tried to impersonate a role",
            "indirect_injection": "it referenced external content",
            "unknown": "it was flagged by our security system",
        }
        return reasons.get(attack_type, "it was flagged by our security system")
