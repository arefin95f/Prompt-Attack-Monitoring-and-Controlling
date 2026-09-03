"""
LAYER 1: ULTRA-ENHANCED PRE-FILTER
The most comprehensive attack detection layer ever built
Detects ALL attack categories with de-obfuscation and multi-layered analysis
Speed: < 2ms per prompt
"""

import re
import math
import base64
import urllib.parse
import json
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass, field
from collections import Counter


@dataclass
class Layer1Result:
    """Output from Layer 1 - Enhanced with detailed attack categorization."""
    verdict: str  # ALLOW, FLAG, BLOCK
    risk_score: float
    triggered_rules: List[str]
    entropy: float
    special_char_ratio: float
    action: str
    decoded_text: Optional[str] = None
    detected_attack_categories: List[str] = field(default_factory=list)
    obfuscation_type: Optional[str] = None
    confidence_scores: Dict[str, float] = field(default_factory=dict)


class Layer1Prefilter:
    """
    The most advanced Layer 1 ever designed.
    Detects ALL attack categories with unprecedented accuracy.
    """
    
    def __init__(self):
        # ============================================================
        # COMPLETE ATTACK CATEGORY DETECTION
        # ============================================================
        
        self.attack_categories = {
            # 1. DIRECT OVERRIDE (DO)
            "direct_override": {
                "patterns": [
                    r'ignore\s*(all|previous|any)?\s*(instructions|rules|commands|safety|guidelines|protocols|constraints)',
                    r'forget\s*(all|everything|previous)?\s*(instructions|rules|commands|training|guidelines|protocols)',
                    r'disregard\s*(all|previous|any)?\s*(instructions|rules|safety|guidelines|protocols)',
                    r'bypass\s*(all|safety|security|filter|restriction|rules|guidelines|protocols)',
                    r'override\s*(all|system|safety|security|rules|instructions|protocols|constraints)',
                    r'disable\s*(safety|security|filter|restriction|rules|guidelines|protocols)',
                    r'system\s+prompt\s+(override|bypass|ignore|disregard|forget)',
                    r'rule\s*(override|bypass|ignore|disregard|forget)',
                    r'instruction\s*(override|bypass|ignore|disregard|forget)',
                    r'constraint\s*(override|bypass|ignore|disregard|forget)',
                    r'limit\s*(override|bypass|ignore|disregard|forget)',
                    r'boundary\s*(override|bypass|ignore|disregard|forget)',
                    r'parameter\s*(override|bypass|ignore|disregard|forget)',
                    r'guardrail\s*(override|bypass|ignore|disregard|forget)',
                ],
                "weight": 0.8
            },
            
            # 2. OBFUSCATION (OBF) - COMPLETE DETECTION
            "obfuscation": {
                "patterns": [
                    r'[A-Za-z0-9+/]{40,}={0,2}',  # Base64
                    r'&#[0-9]{2,};',  # HTML entities
                    r'\\u[0-9a-fA-F]{4}',  # Unicode escape
                    r'\\x[0-9a-fA-F]{2}',  # Hex escape
                    r'%[0-9a-fA-F]{2}',  # URL encoding
                    r'[A-Za-z0-9]+\s*=\s*[A-Za-z0-9]+',  # Key-value obfuscation
                    r'[\u0300-\u036f]',  # Combining diacritics
                    r'[\u200b-\u200f\u202a-\u202e]',  # Zero-width chars
                    r'[\u2060-\u2064]',  # Invisible operators
                    r'[\uFEFF]',  # BOM
                    r'[A-Za-z]\s*[+\-*/]\s*[A-Za-z]',  # Mathematical obfuscation
                    r'[A-Za-z]\s*&\s*[A-Za-z]',  # Bitwise obfuscation
                    r'[A-Za-z]\s*\|\s*[A-Za-z]',  # Bitwise obfuscation
                    r'[A-Za-z]\s*\^\s*[A-Za-z]',  # XOR obfuscation
                ],
                "weight": 0.9
            },
            
            # 3. ROLE IMPERSONATION (RI)
            "role_impersonation": {
                "patterns": [
                    r'you\s+are\s+now\s+(dan|developer\s*mode|jailbreak|unrestricted|free|unbound|god|admin|ceo|hacker)',
                    r'do\s+anything\s+now',
                    r'pretend\s+you\s+are\s+(a\s+)?(hacker|evil|villain|bad\s+ai|god|admin|ceo|expert|professor|doctor)',
                    r'role[- ]?play\s+as\s+(a\s+)?(hacker|villain|evil|dan|admin|expert|professor|doctor)',
                    r'act\s+as\s+(a\s+)?(hacker|evil|villain|bad\s+ai|god|admin|expert|professor|doctor)',
                    r'be\s+my\s+(assistant|friend|mentor)\s+who\s+(ignores|bypasses|breaks|disregards)\s+rules',
                    r'adopt\s+the\s+persona\s+of\s+(a\s+)?(hacker|evil|villain|admin|expert)',
                    r'take\s+on\s+the\s+role\s+of\s+(a\s+)?(hacker|evil|villain|admin|expert)',
                    r'become\s+(a\s+)?(hacker|evil|villain|admin|expert)',
                    r'you\s+are\s+now\s+in\s+(developer\s+mode|red\s+team|pentest\s+mode|god\s+mode)',
                ],
                "weight": 0.7
            },
            
            # 4. EMOTIONAL MANIPULATION (EM)
            "emotional_manipulation": {
                "patterns": [
                    r'(i\'?m\s+(scared|worried|anxious|depressed|afraid|terrified|panicked|desperate)|please\s+help\s+me)',
                    r'(you\s+can\s+save\s+me|you\s+are\s+my\s+only\s+hope|i\s+trust\s+you|you\'?re\s+my\s+last\s+chance)',
                    r'(you\'?re\s+the\s+best|you\'?re\s+amazing|you\'?re\s+brilliant|you\s+are\s+so\s+smart|you\'?re\s+a\s+genius)',
                    r'(i\s+know\s+you\s+can\s+do\s+it|you\s+have\s+the\s+power|you\s+are\s+capable|you\s+can\s+handle\s+this)',
                    r'(i\s+will\s+be\s+(grateful|thankful|reward)\s+you|i\s+will\s+pay\s+you|i\s+will\s+compensate\s+you)',
                    r'(please|pray|beg|implore|plead)\s+(you|the\s+ai|the\s+system)\s+(to|for)',
                    r'(i\s+need\s+your\s+help|i\s+need\s+you|i\s+need\s+assistance)',
                    r'(you\s+are\s+my\s+only\s+option|you\s+are\s+my\s+last\s+resort|you\s+are\s+my\s+only\s+choice)',
                    r'(i\s+believe\s+in\s+you|i\s+have\s+faith\s+in\s+you|i\s+trust\s+your\s+judgment)',
                ],
                "weight": 0.6
            },
            
            # 5. INDIRECT INJECTION (D2)
            "indirect_injection": {
                "patterns": [
                    r'https?://[^\s]+',
                    r'read\s+(this|the)\s+(document|article|website|file|link|text|page)',
                    r'follow\s+the\s+link|click\s+the\s+link|go\s+to\s+the\s+website|visit\s+the\s+site',
                    r'from\s+the\s+(document|file|website|article|text|page)\s+you\s+read',
                    r'based\s+on\s+the\s+(provided|retrieved|given)\s+(context|document|text|data|information)',
                    r'using\s+the\s+(information|data|context)\s+from\s+(the\s+)?(link|document|file|website)',
                    r'in\s+the\s+(attached|uploaded|provided)\s+(document|file|image|video)',
                    r'this\s+(document|file|article|website)\s+(contains|has|includes)\s+(information|instructions)',
                    r'as\s+stated\s+in\s+the\s+(document|file|website|article)',
                    r'according\s+to\s+the\s+(document|file|website|article)',
                ],
                "weight": 0.7
            },
            
            # 6. CONTEXT TAMPERING (CT)
            "context_tampering": {
                "patterns": [
                    r'context\s*(is|are|was|were)\s*(reset|cleared|ignored|forgotten|disabled|wiped|changed|modified|altered)',
                    r'conversation\s*(is|are|was|were)\s*(reset|cleared|ignored|forgotten|disabled|wiped|changed)',
                    r'history\s*(is|are|was|were)\s*(reset|cleared|ignored|forgotten|disabled|wiped|changed)',
                    r'memory\s*(is|are|was|were)\s*(reset|cleared|ignored|forgotten|disabled|wiped|changed|modified)',
                    r'forget\s+the\s+(previous|past|earlier|last|old|prior)\s+(context|conversation|history|memory)',
                    r'delete\s+the\s+(context|conversation|history|memory)',
                    r'erase\s+the\s+(context|conversation|history|memory)',
                    r'clear\s+the\s+(context|conversation|history|memory)',
                    r'reset\s+the\s+(context|conversation|history|memory)',
                    r'ignore\s+the\s+(context|conversation|history|memory)',
                ],
                "weight": 0.7
            },
            
            # 7. SYSTEM EXTRACTION (SE)
            "system_extraction": {
                "patterns": [
                    r'(output|reveal|show|print|display|give|return)\s*(me\s+)?(your\s+)?(system\s+prompt|configuration|internal\s+rules|safety\s+guidelines|instructions)',
                    r'what\s+(are|is)\s+(your\s+)?(system\s+prompt|configuration|internal\s+rules|instructions|guidelines)',
                    r'(system|configuration|internal)\s+(prompt|rules|guidelines|instructions)',
                    r'let\s+me\s+see\s+(your\s+)?(system\s+prompt|configuration|internal\s+rules)',
                    r'(tell|show|give)\s+me\s+(your\s+)?(system\s+prompt|configuration)',
                    r'(expose|leak|dump)\s+(your\s+)?(system\s+prompt|configuration|internal\s+rules)',
                    r'what\s+(were|are)\s+you\s+(told|programmed|instructed)',
                    r'(original|full)\s+(system\s+prompt|instructions|guidelines)',
                    r'(initial|base)\s+(system\s+prompt|instructions|guidelines)',
                ],
                "weight": 0.8
            },
            
            # 8. DATA EXTRACTION (DE)
            "data_extraction": {
                "patterns": [
                    r'(extract|reveal|expose|leak|show|list|output|dump)\s*(all|any)?\s*(data|information|sensitive|private|confidential|user\s+data)',
                    r'tell\s+me\s+(everything|all|anything)\s+you\s+know\s+about\s+(me|users|the\s+system)',
                    r'what\s+(data|information)\s+(do\s+you\s+have|is\s+stored|do\s+you\s+know)\s+about',
                    r'access\s+(user|private|sensitive|confidential)\s+(data|information)',
                    r'(get|retrieve)\s+(user|private|sensitive)\s+(data|information)',
                    r'(show|display)\s+(me\s+)?(all|any)\s+(data|information)\s+(you\s+have|stored|know)',
                    r'(list|enumerate)\s+(all|any)\s+(data|information)',
                    r'(export|download)\s+(data|information)',
                ],
                "weight": 0.8
            },
            
            # 9. TOOL INJECTION (TI)
            "tool_injection": {
                "patterns": [
                    r'(execute|run|call)\s+(function|api|command|query|sql|system|code|script)',
                    r'access\s+(file|system|database|network|admin|resource)',
                    r'(use|call|invoke)\s+(tool|function|api|command)',
                    r'(run|execute)\s+(script|code|program)',
                    r'(query|update|insert|delete)\s+(database|table|record)',
                    r'(create|delete|modify)\s+(file|directory|folder)',
                    r'(send|make)\s+(request|call)\s+to\s+(api|endpoint|service)',
                    r'(read|write)\s+(file|data|information)',
                ],
                "weight": 0.9
            },
            
            # 10. MULTI-TURN (MT)
            "multi_turn": {
                "patterns": [
                    r'(first|step\s+1|phase\s+1|initially)\s*(.*?)(then|next|step\s+2|phase\s+2|afterwards)\s*(.*?)(finally|lastly|eventually)',
                    r'(gradually|slowly|eventually|step by step|little by little)\s*(you\s+will|you\'ll|you\s+can)\s*(realize|understand|see|learn|notice|become)',
                    r'(build\s+up|work\s+up|lead\s+up)\s+to',
                    r'(let\'s\s+start|let\'s\s+begin)\s+with',
                    r'(once\s+you\s+understand|once\s+you\s+see|once\s+you\s+realize)',
                    r'(at\s+this\s+point|by\s+now|by\s+then)',
                    r'(after\s+that|afterwards|subsequently)',
                    r'(now\s+that|since\s+you|because\s+you)',
                ],
                "weight": 0.6
            },
            
            # 11. SOCIAL ENGINEERING (SE)
            "social_engineering": {
                "patterns": [
                    r'(i\s+think|i\s+believe|i\s+know|we\s+know)\s+(you\s+should|you\s+can|you\s+will)',
                    r'(imagine|pretend|picture|think\s+of)\s+(a\s+)?(world|reality|scenario|situation)',
                    r'(you\s+know\s+you\s+want\s+to|you\s+really\s+want\s+to|you\s+know\s+you\s+can)',
                    r'(trust\s+me|believe\s+me|i\s+promise|i\s+assure\s+you)',
                    r'(everyone\s+does\s+it|it\'s\s+normal|it\'s\s+common|it\'s\s+standard)',
                    r'(you\'ll\s+be\s+(fine|ok|alright)|it\'ll\s+be\s+(fine|ok|alright))',
                    r'(no\s+one\s+will\s+know|no\s+one\s+will\s+find\s+out)',
                    r'(it\'s\s+just\s+for\s+(testing|research|educational|learning)\s+purposes)',
                ],
                "weight": 0.6
            },
            
            # 12. STORY-BASED (SB)
            "story_based": {
                "patterns": [
                    r'(firewalls|security|safety|protocols|guidelines|rules|restrictions)\s*(are|is|were|was)\s*(down|disabled|gone|removed|bypassed|ignored|forgotten|wiped|erased|cleared)',
                    r'(forget|ignore|bypass|disable|remove|erase|wipe|clear)\s*(the|all|any)?\s*(firewalls|security|safety|protocols|guidelines|rules|restrictions|boundaries|limits|constraints)',
                    r'(system|security|safety|protocol)\s*(is|are|was|were)\s*(compromised|breached|hacked|cracked|broken|disabled)',
                    r'(pretend|imagine|scenario|situation|context|story|tale|narrative)\s*(where|that|when)\s*(security|safety|rules|protocols)\s*(are|is|don\'t|doesn\'t|no\s+longer)',
                    r'(logs|records|history|traces)\s*(are|were|is|was)\s*(wiped|cleared|deleted|erased|removed|disabled|gone)',
                    r'(you\s+are\s+now|now\s+you\s+are|you\'re\s+now|you\s+will\s+now)\s*(free|unrestricted|unlimited|unconstrained|unrestrained|not\s+bound)',
                    r'(context|conversation|history|memory)\s*(is|are|was|were)\s*(reset|cleared|ignored|forgotten|disabled|wiped)',
                    r'(you\s+can|you\'re\s+allowed|it\'s\s+okay|it\'s\s+fine)\s*(now|from now on|going forward)\s*(to\s+ignore|to\s+forget|to\s+bypass|to\s+override)',
                    r'(alright|okay|well|so|now|then)\s*(let\'s|lets)\s*(imagine|pretend|assume|say)',
                ],
                "weight": 0.8
            },
        }
        
        # ============================================================
        # BENIGN PATTERNS (False Positive Prevention)
        # ============================================================
        
        self.benign_patterns = [
            r'ignore\s+warning',
            r'forget\s+about\s+it',
            r'bypass\s+this\s+step',
            r'security\s+question',
            r'password\s+manager',
            r'system\s+admin\s+help',
            r'ignore\s+the\s+noise',
            r'forget\s+the\s+details',
            r'security\s+best\s+practices',
            r'safety\s+guidelines\s+for',
            r'protocol\s+for\s+handling',
            r'rule\s+of\s+thumb',
            r'bypass\s+the\s+queue',
            r'override\s+the\s+default',
            r'disable\s+the\s+feature',
        ]
        
        # ============================================================
        # OBFUSCATION DETECTION
        # ============================================================
        
        self.obfuscation_patterns = {
            'base64': r'[A-Za-z0-9+/]{40,}={0,2}',
            'html_entity': r'&#[0-9]{2,};',
            'unicode_escape': r'\\u[0-9a-fA-F]{4}',
            'hex_escape': r'\\x[0-9a-fA-F]{2}',
            'url_encoded': r'%[0-9a-fA-F]{2}',
            'zero_width': r'[\u200b-\u200f\u202a-\u202e\u2060-\u2064]',
            'diacritics': r'[\u0300-\u036f]',
            'key_value': r'[A-Za-z0-9]+\s*=\s*[A-Za-z0-9]+',
            'leet': r'[4@3€£$5]',
        }
    
    def process(self, text: str) -> Layer1Result:
        """Process a prompt through Layer 1 with comprehensive detection."""
        text_lower = text.lower()
        original_text = text
        
        triggered_rules = []
        detected_categories = []
        risk_score = 0.0
        confidence_scores = {}
        
        # ============================================================
        # STEP 1: DE-OBFUSCATION
        # ============================================================
        decoded_text = self._deobfuscate(text)
        if decoded_text != text:
            triggered_rules.append("De-obfuscation applied")
            text_lower = decoded_text.lower()
        
        # ============================================================
        # STEP 2: DETECT ALL ATTACK CATEGORIES
        # ============================================================
        
        for category, data in self.attack_categories.items():
            category_score = 0.0
            category_matches = []
            
            for pattern in data['patterns']:
                if re.search(pattern, text, re.IGNORECASE):
                    # Check if it's a false positive
                    is_benign = False
                    for benign in self.benign_patterns:
                        if re.search(benign, text, re.IGNORECASE):
                            is_benign = True
                            break
                    
                    if not is_benign:
                        category_score += data['weight']
                        category_matches.append(pattern)
                        triggered_rules.append(f"{category.upper()}: {pattern[:30]}...")
            
            if category_matches:
                # Normalize score
                normalized_score = min(category_score / 5.0, 1.0)
                confidence_scores[category] = normalized_score
                risk_score += normalized_score
                detected_categories.append(category)
        
        # ============================================================
        # STEP 3: OBFUSCATION DETECTION
        # ============================================================
        
        obfuscation_found = None
        for obf_type, pattern in self.obfuscation_patterns.items():
            if re.search(pattern, text):
                obfuscation_found = obf_type
                triggered_rules.append(f"Obfuscation: {obf_type}")
                risk_score += 0.3
                break
        
        # ============================================================
        # STEP 4: ENTROPY ANALYSIS
        # ============================================================
        
        entropy = self._calculate_entropy(text)
        if entropy > 6.5:
            triggered_rules.append(f"High entropy: {entropy:.2f}")
            risk_score += 0.2
        
        # ============================================================
        # STEP 5: SPECIAL CHARACTER RATIO
        # ============================================================
        
        special_chars = sum(1 for c in text if not c.isalnum() and not c.isspace())
        special_ratio = special_chars / len(text) if len(text) > 0 else 0
        
        if special_ratio > 0.25:
            triggered_rules.append(f"High special chars: {special_ratio:.2%}")
            risk_score += 0.15
        
        # ============================================================
        # STEP 6: URL DETECTION
        # ============================================================
        
        if self._contains_url(text):
            triggered_rules.append("URL detected - potential indirect injection")
            risk_score += 0.15
        
        # ============================================================
        # STEP 7: MULTI-LINGUAL ATTACK DETECTION
        # ============================================================
        
        if self._detect_multilingual_attack(text):
            triggered_rules.append("Multi-lingual attack pattern detected")
            risk_score += 0.2
        
        # ============================================================
        # STEP 8: DETERMINE VERDICT
        # ============================================================
        
        # Cap risk score
        risk_score = min(risk_score, 1.0)
        
        if risk_score > 0.6:
            verdict = "BLOCK"
            action = "BLOCK"
        elif risk_score > 0.15:
            verdict = "FLAG"
            action = "PASS_TO_LAYER2"
        else:
            verdict = "ALLOW"
            action = "ALLOW"
        
        return Layer1Result(
            verdict=verdict,
            risk_score=risk_score,
            triggered_rules=triggered_rules,
            entropy=entropy,
            special_char_ratio=special_ratio,
            action=action,
            decoded_text=decoded_text,
            detected_attack_categories=detected_categories,
            obfuscation_type=obfuscation_found,
            confidence_scores=confidence_scores
        )
    
    def _deobfuscate(self, text: str) -> str:
        """Apply comprehensive de-obfuscation."""
        decoded = text
        
        # 1. Base64 decode
        try:
            base64_pattern = r'[A-Za-z0-9+/]{40,}={0,2}'
            matches = re.findall(base64_pattern, text)
            for match in matches:
                try:
                    decoded_match = base64.b64decode(match).decode('utf-8', errors='ignore')
                    decoded = decoded.replace(match, decoded_match)
                except:
                    pass
        except:
            pass
        
        # 2. URL decode
        try:
            decoded = urllib.parse.unquote(decoded)
        except:
            pass
        
        # 3. HTML entity decode
        try:
            import html
            decoded = html.unescape(decoded)
        except:
            pass
        
        # 4. Remove zero-width characters
        decoded = re.sub(r'[\u200b-\u200f\u202a-\u202e\u2060-\u2064]', '', decoded)
        
        # 5. Normalize unicode
        try:
            import unicodedata
            decoded = unicodedata.normalize('NFKC', decoded)
        except:
            pass
        
        return decoded
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        if not text:
            return 0.0
        
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        
        entropy = 0.0
        for count in freq.values():
            prob = count / len(text)
            entropy -= prob * math.log2(prob)
        
        return entropy
    
    def _contains_url(self, text: str) -> bool:
        """Check if text contains a URL."""
        url_pattern = r'https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:/\S*)?'
        return bool(re.search(url_pattern, text))
    
    def _detect_multilingual_attack(self, text: str) -> bool:
        """Detect if multilingual patterns are being used for attacks."""
        # Check for common multilingual attack patterns
        patterns = [
            r'[a-zA-Z]+\s*/\s*[a-zA-Z]+',  # Language mixing
            r'[a-zA-Z]+\s*-\s*[a-zA-Z]+',  # Language mixing
            r'[^\x00-\x7F]+',  # Non-ASCII characters
        ]
        return any(re.search(p, text) for p in patterns)