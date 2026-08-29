"""
Prompt Injection Defense System
A 5-layer pipeline for detecting and mitigating prompt injection attacks.
"""

__version__ = "3.0.0"
__author__ = "Shamsul Arefin"

# Import pipeline for easy access
from .pipeline import PromptInjectionPipeline

__all__ = [
    'PromptInjectionPipeline'
]