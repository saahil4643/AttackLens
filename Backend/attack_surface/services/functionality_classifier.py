"""
High-Level Application Functionality Classifier.
"""
import re
from typing import List, Dict, Any
from .models import FunctionalityCategoryRecord


def build_functionality_map(
    endpoints: List[Dict[str, Any]],
    forms: List[Dict[str, Any]],
    api_endpoints: List[Dict[str, Any]],
    admin_surfaces: List[Dict[str, Any]],
    upload_surfaces: List[Dict[str, Any]],
    doc_surfaces: List[Dict[str, Any]],
    operational_endpoints: List[Dict[str, Any]],
) -> List[FunctionalityCategoryRecord]:
    """
    Synthesizes discovered routes, forms, APIs, and services into an application functionality map.
    """
    buckets: Dict[str, Dict[str, Any]] = {
        "authentication": {"endpoints": [], "evidence": [], "confidence": 0.95},
        "account_management": {"endpoints": [], "evidence": [], "confidence": 0.88},
        "administration": {"endpoints": [], "evidence": [], "confidence": 0.90},
        "api": {"endpoints": [], "evidence": [], "confidence": 0.96},
        "search": {"endpoints": [], "evidence": [], "confidence": 0.90},
        "file_upload": {"endpoints": [], "evidence": [], "confidence": 0.95},
        "payments": {"endpoints": [], "evidence": [], "confidence": 0.85},
        "profile": {"endpoints": [], "evidence": [], "confidence": 0.85},
        "documentation": {"endpoints": [], "evidence": [], "confidence": 0.95},
        "health": {"endpoints": [], "evidence": [], "confidence": 0.90},
        "messaging": {"endpoints": [], "evidence": [], "confidence": 0.80},
    }

    # 1. Administration
    if admin_surfaces:
        for a in admin_surfaces:
            buckets["administration"]["endpoints"].append(a.get("endpoint", ""))
        buckets["administration"]["evidence"].append(f"{len(admin_surfaces)} administrative endpoints discovered")

    # 2. File Upload
    if upload_surfaces:
        for u in upload_surfaces:
            buckets["file_upload"]["endpoints"].append(u.get("endpoint", ""))
        buckets["file_upload"]["evidence"].append(f"{len(upload_surfaces)} file upload interfaces detected")

    # 3. Documentation
    if doc_surfaces:
        for d in doc_surfaces:
            buckets["documentation"]["endpoints"].append(d.get("documentation_url", ""))
        buckets["documentation"]["evidence"].append(f"{len(doc_surfaces)} API/technical documentation specs discovered")

    # 4. Health / Operational
    if operational_endpoints:
        for h in operational_endpoints:
            buckets["health"]["endpoints"].append(h.get("endpoint", ""))
        buckets["health"]["evidence"].append(f"{len(operational_endpoints)} health/status telemetry endpoints identified")

    # 5. APIs
    if api_endpoints:
        buckets["api"]["endpoints"] = [ep.get("endpoint") or ep.get("path") for ep in api_endpoints[:15]]
        buckets["api"]["evidence"].append(f"{len(api_endpoints)} REST/GraphQL API endpoints cataloged")

    # 6. Forms
    for f in forms:
        action = f.get("action") or ""
        cls = f.get("classification") or ""
        if cls == "login":
            buckets["authentication"]["endpoints"].append(action)
            buckets["authentication"]["evidence"].append(f"Login form on {action}")
        elif cls == "registration":
            buckets["account_management"]["endpoints"].append(action)
            buckets["account_management"]["evidence"].append(f"Registration form on {action}")
        elif cls == "search":
            buckets["search"]["endpoints"].append(action)
            buckets["search"]["evidence"].append(f"Search input form on {action}")
        elif cls in ("contact", "feedback"):
            buckets["messaging"]["endpoints"].append(action)
            buckets["messaging"]["evidence"].append(f"Contact/messaging form on {action}")

    # 7. Endpoint URL regex checks
    for ep in endpoints:
        path = ep.get("path") or ep.get("url") or ""
        path_lower = path.lower()

        if re.search(r"/(?:login|signin|logout|oauth|auth|token)", path_lower):
            buckets["authentication"]["endpoints"].append(path)
        if re.search(r"/(?:register|signup|account|user|profile|settings)", path_lower):
            buckets["account_management"]["endpoints"].append(path)
        if re.search(r"/(?:payment|checkout|stripe|paypal|billing|invoice|cart)", path_lower):
            buckets["payments"]["endpoints"].append(path)
            buckets["payments"]["evidence"].append(f"Payment or billing route: {path}")
        if re.search(r"/(?:profile|avatar|me)", path_lower):
            buckets["profile"]["endpoints"].append(path)
        if re.search(r"/(?:search|query|find)", path_lower):
            buckets["search"]["endpoints"].append(path)
        if re.search(r"/(?:messages|chat|contact|feedback|notifications)", path_lower):
            buckets["messaging"]["endpoints"].append(path)

    # Convert populated buckets to list of FunctionalityCategoryRecord
    records: List[FunctionalityCategoryRecord] = []
    for cat_name, data in buckets.items():
        unique_eps = sorted(list(set(filter(bool, data["endpoints"]))))
        if unique_eps or data["evidence"]:
            records.append(FunctionalityCategoryRecord(
                category=cat_name,
                confidence=data["confidence"],
                endpoints=unique_eps[:20],
                evidence=sorted(list(set(data["evidence"])))[:5]
            ))

    return records
