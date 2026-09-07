"""
Web Security Configuration Scoring Engine
Calculates a transparent 0-100 configuration hygiene score.
"""
from typing import Dict, Any, List

def calculate_security_score(
    security_headers: Dict[str, Any],
    https_info: Dict[str, Any],
    cookies: List[Dict[str, Any]],
    cors_info: Dict[str, Any],
    findings: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Computes the 'Web Security Configuration Score' based on observed security posture.
    """
    score = 100

    # Deductions based on finding severity
    for f in findings:
        sev = f.get("severity", "").lower()
        if sev == "high":
            score -= 25
        elif sev == "medium":
            score -= 12
        elif sev == "low":
            score -= 5
        elif sev == "info":
            score -= 1

    # Clamp between 0 and 100
    final_score = max(0, min(100, score))

    if final_score >= 90:
        grade = "A+"
        color = "#3fb950"
        label = "Excellent Security Configuration"
    elif final_score >= 80:
        grade = "A"
        color = "#2ea043"
        label = "Strong Security Configuration"
    elif final_score >= 65:
        grade = "B"
        color = "#d29922"
        label = "Moderate Configuration - Action Recommended"
    elif final_score >= 50:
        grade = "C"
        color = "#db6d28"
        label = "Weak Configuration - Attention Needed"
    elif final_score >= 35:
        grade = "D"
        color = "#f85149"
        label = "Poor Configuration - High Risk"
    else:
        grade = "F"
        color = "#da3633"
        label = "Critical Configuration Deficiencies"

    return {
        "score": final_score,
        "score_name": "Web Security Configuration Score",
        "grade": grade,
        "color": color,
        "label": label,
        "breakdown": {
            "total_findings": len(findings),
            "high": sum(1 for f in findings if f.get("severity") == "high"),
            "medium": sum(1 for f in findings if f.get("severity") == "medium"),
            "low": sum(1 for f in findings if f.get("severity") == "low"),
            "info": sum(1 for f in findings if f.get("severity") == "info"),
        }
    }
