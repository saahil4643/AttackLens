"""
Technology Fingerprint Rule Definitions and Schema.
"""
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Pattern, Callable
import re

@dataclass
class EvidenceMatch:
    type: str  # "header", "cookie", "meta", "script", "html", "path", "cdn"
    source: str
    description: str
    value: Optional[str] = None
    confidence: float = 0.80

@dataclass
class TechnologyRule:
    technology: str
    category: str  # "web_server", "backend", "frontend", "javascript", "css", "cms", "cdn", "hosting", "analytics", "authentication", "api", "database", "other"
    website: Optional[str] = None
    description: Optional[str] = None
    
    # Matching rules
    headers: Dict[str, Any] = field(default_factory=dict)  # header_name -> pattern/regex or (regex, version_extractor)
    cookies: List[str] = field(default_factory=list)  # list of cookie names (exact or regex)
    meta_tags: Dict[str, Any] = field(default_factory=dict)  # meta_name -> regex
    html_patterns: List[str] = field(default_factory=list)  # regex patterns in raw html
    script_patterns: List[str] = field(default_factory=list)  # patterns in <script src> or script tag URLs
    js_content_patterns: List[str] = field(default_factory=list)  # patterns in fetched JavaScript file content
    css_patterns: List[str] = field(default_factory=list)  # patterns in <link rel="stylesheet"> or css text
    url_patterns: List[str] = field(default_factory=list)  # endpoints / paths regex
    
    # Version extractors
    version_regexes: List[Pattern] = field(default_factory=list)

