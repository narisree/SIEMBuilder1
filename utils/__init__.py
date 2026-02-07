"""
Utility modules for SIEM Onboarding Assistant.
"""

from .kb_loader import KBLoader
from .ai_client import AIClientFactory, ClaudeClient, GroqClient, HuggingFaceClient, OllamaClient
from .usecase_loader import UseCaseLoader

# Detection engine is optional (requires pysigma)
try:
    from .detection_engine import DetectionEngine
except ImportError:
    DetectionEngine = None

__all__ = [
    'KBLoader',
    'AIClientFactory',
    'ClaudeClient',
    'GroqClient',
    'HuggingFaceClient',
    'OllamaClient',
    'UseCaseLoader',
    'DetectionEngine',
]
