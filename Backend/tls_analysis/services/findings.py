"""
TLS Security Finding Model & Definitions
"""
from typing import Dict, Any


class TlsFinding:
    def __init__(
        self,
        id: str,
        title: str,
        category: str,
        severity: str,
        confidence: float,
        description: str,
        evidence: Dict[str, Any],
        recommendation: str
    ):
        self.id = id
        self.title = title
        self.category = category  # tls, certificate, protocol, cipher
        self.severity = severity  # info, low, medium, high
        self.confidence = confidence  # 0.50 - 0.99
        self.description = description
        self.evidence = evidence
        self.recommendation = recommendation

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "confidence": round(self.confidence, 2),
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation
        }
