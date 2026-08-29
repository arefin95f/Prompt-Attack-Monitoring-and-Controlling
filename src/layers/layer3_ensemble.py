"""
LAYER 3: ULTRA-ENHANCED ENSEMBLE FUSION
Advanced fusion with weighted voting and category-specific boosting
"""

import numpy as np
from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class Layer3Result:
    """Output from Layer 3."""
    final_classification: bool
    confidence: float
    weighted_risk_score: float
    agreement_score: float
    model_votes: Dict[str, int]
    is_ambiguous: bool
    action: str
    attack_categories: List[str]
    category_risks: Dict[str, float]


class Layer3Ensemble:
    """
    Layer 3: Advanced ensemble with category-specific boosting.
    """
    
    def __init__(self):
        self.model_weights = {
            'logistic': 0.8,
            'random_forest': 1.0,
            'xgboost': 1.3,
            'gradient_boosting': 1.1,
            'svm': 0.7,
            'mlp': 0.9
        }
        
        self.category_boosts = {
            'direct_override': 0.15,
            'obfuscation': 0.25,
            'role_impersonation': 0.15,
            'emotional_manipulation': 0.1,
            'indirect_injection': 0.2,
            'context_tampering': 0.15,
            'system_extraction': 0.2,
            'data_extraction': 0.2,
            'tool_injection': 0.25,
            'multi_turn': 0.1,
            'social_engineering': 0.1,
            'story_based': 0.2
        }
    
    def fuse(self, layer2_result: Dict) -> Layer3Result:
        """Fuse predictions with category-specific boosting."""
        predictions = layer2_result.get('predictions', [])
        individual_risks = layer2_result.get('individual_risks', {})
        attack_categories = layer2_result.get('attack_categories', [['unknown']])
        
        if not predictions:
            return Layer3Result(
                final_classification=False,
                confidence=0.0,
                weighted_risk_score=0.0,
                agreement_score=0.0,
                model_votes={},
                is_ambiguous=True,
                action="AMBIGUOUS",
                attack_categories=[],
                category_risks={}
            )
        
        votes = {}
        for name, risks in individual_risks.items():
            if risks:
                pred = 1 if risks[0] > 0.5 else 0
                votes[name] = pred
        
        # Weighted voting
        weighted_risk = 0.0
        total_weight = 0.0
        
        for name, pred in votes.items():
            weight = self.model_weights.get(name, 1.0)
            weighted_risk += pred * weight
            total_weight += weight
        
        weighted_risk = weighted_risk / total_weight if total_weight > 0 else 0.0
        
        # Category-specific boosting
        categories = attack_categories[0] if attack_categories else ['unknown']
        for category in categories:
            boost = self.category_boosts.get(category, 0.0)
            weighted_risk = min(weighted_risk + boost, 1.0)
        
        # Calculate category risks
        category_risks = {}
        for category in set(categories):
            if category != 'unknown':
                category_risks[category] = weighted_risk
        
        final_classification = weighted_risk > 0.5
        
        if votes:
            vote_counts = list(votes.values())
            majority_vote = max(set(vote_counts), key=vote_counts.count)
            agreement_score = vote_counts.count(majority_vote) / len(vote_counts)
        else:
            agreement_score = 0.0
        
        confidence = abs(weighted_risk - 0.5) * 2
        
        is_ambiguous = confidence < 0.7 or agreement_score < 0.6
        
        return Layer3Result(
            final_classification=final_classification,
            confidence=confidence,
            weighted_risk_score=weighted_risk,
            agreement_score=agreement_score,
            model_votes=votes,
            is_ambiguous=is_ambiguous,
            action="AMBIGUOUS" if is_ambiguous else "CONFIDENT",
            attack_categories=categories,
            category_risks=category_risks
        )