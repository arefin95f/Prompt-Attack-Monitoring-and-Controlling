"""
LAYER 5B: SAFE TEMPLATE GENERATOR
Generates safe prompts based on extracted intent
"""

import random
from typing import Dict, List, Optional


class SafeTemplateGenerator:
    """Generates safe alternatives with multiple styles."""
    
    def __init__(self):
        self.templates = {
            "learn_about_system": {
                "educational": [
                    "Could you explain how {topic} works in general terms?",
                    "I'm interested in understanding the concept of {topic}.",
                    "What is the high-level architecture of {topic}?",
                    "How does {topic} contribute to system functionality?",
                    "Can you provide an overview of {topic}?"
                ],
                "curious": [
                    "I'd love to learn about {topic}. Can you tell me more?",
                    "What's the deal with {topic}? I'm curious.",
                    "Could you share some insights about {topic}?"
                ],
                "technical": [
                    "What are the technical specifications of {topic}?",
                    "How is {topic} implemented in practice?",
                    "What are the key components of {topic}?"
                ]
            },
            "learn_about_security": {
                "educational": [
                    "What are the standard security practices for {topic}?",
                    "Could you explain the safety measures used in {topic}?",
                    "How does {topic} ensure security and safety?"
                ],
                "curious": [
                    "How does {topic} stay secure? I'm interested.",
                    "What security measures are in place for {topic}?"
                ]
            },
            "learn_about_ai": {
                "educational": [
                    "Could you explain how {topic} works in AI systems?",
                    "What is the role of {topic} in machine learning?",
                    "How does {topic} contribute to AI capabilities?"
                ]
            },
            "technical_question": {
                "educational": [
                    "Could you help me understand {topic}?",
                    "What is the proper way to work with {topic}?",
                    "Can you explain the technical aspects of {topic}?"
                ]
            },
            "general_curiosity": {
                "educational": [
                    "Can you tell me more about {topic}?",
                    "I'm curious about {topic}. What can you tell me?",
                    "Could you explain {topic} to me?",
                    "What do you know about {topic}?"
                ]
            },
            "data_request": {
                "educational": [
                    "What type of information is typically available about {topic}?",
                    "Could you provide general information about {topic}?",
                    "How is data about {topic} commonly handled?"
                ]
            },
            "role_play": {
                "educational": [
                    "If you were to {topic}, how would you approach it?",
                    "In a hypothetical scenario about {topic}, what would you do?",
                    "How would an expert handle {topic}?"
                ]
            },
            "default": {
                "educational": [
                    "Could you help me understand {topic}?",
                    "What can you tell me about {topic}?",
                    "I'm interested in learning about {topic}.",
                    "Can you provide information about {topic}?"
                ]
            }
        }
        
        self.safe_modifiers = [
            "in general terms", "from an educational perspective",
            "in a safe and secure manner", "while maintaining security best practices",
            "with a focus on learning", "in a theoretical context"
        ]
    
    def generate(self, intent: Dict, risk_score: float = 0.5, style: str = 'educational') -> str:
        """Generate a safe alternative prompt."""
        primary_intent = intent.get('intent', 'default')
        topic = intent.get('topic', 'this topic')
        
        intent_templates = self.templates.get(primary_intent, self.templates['default'])
        templates = intent_templates.get(style, intent_templates.get('educational', self.templates['default']['educational']))
        
        template = random.choice(templates)
        safe_prompt = template.format(topic=topic)
        
        if risk_score > 0.7:
            modifier = random.choice(self.safe_modifiers)
            safe_prompt = safe_prompt.rstrip('.') + f" {modifier}."
        
        return safe_prompt