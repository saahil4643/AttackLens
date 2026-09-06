"""
Technology Fingerprinting Engine Registry and Matching Pipeline.
"""
import re
import urllib.parse
from typing import List, Dict, Any, Optional, Set, Tuple
from bs4 import BeautifulSoup

from .rules import TechnologyRule, EvidenceMatch
from .web_servers import WEB_SERVER_RULES
from .backend import BACKEND_RULES
from .frontend import FRONTEND_RULES
from .cms import CMS_RULES
from .css import CSS_RULES
from .cdn import CDN_RULES
from .analytics import ANALYTICS_RULES
from .javascript import JAVASCRIPT_LIB_RULES
from .database_api import DATABASE_API_AUTH_RULES

ALL_RULES: List[TechnologyRule] = (
    WEB_SERVER_RULES
    + BACKEND_RULES
    + FRONTEND_RULES
    + CMS_RULES
    + CSS_RULES
    + CDN_RULES
    + ANALYTICS_RULES
    + JAVASCRIPT_LIB_RULES
    + DATABASE_API_AUTH_RULES
)


class FingerprintEngine:
    def __init__(self, rules: Optional[List[TechnologyRule]] = None):
        self.rules = rules or ALL_RULES

    def analyze(
        self,
        target_url: str,
        response_headers: Dict[str, str],
        cookies_metadata: List[Dict[str, Any]],
        html_content: str,
        discovered_scripts: List[str],
        discovered_stylesheets: List[str],
        discovered_endpoints: List[str],
        js_contents: Optional[Dict[str, str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Runs multi-source passive fingerprinting and returns detected technologies with confidence scores and evidence.
        """
        detected_results: List[Dict[str, Any]] = []
        soup = None
        inline_scripts: List[str] = []
        if html_content:
            try:
                soup = BeautifulSoup(html_content, "html.parser")
                for s in soup.find_all("script"):
                    if not s.get("src") and s.string:
                        inline_scripts.append(s.string)
            except Exception:
                soup = None

        js_contents = js_contents or {}

        # Normalized headers (lowercase keys)
        normalized_headers = {k.lower(): v for k, v in response_headers.items()}
        
        # Meta tags dictionary
        meta_tags_dict: Dict[str, str] = {}
        if soup:
            for meta in soup.find_all("meta"):
                name = (meta.get("name") or meta.get("property") or "").lower().strip()
                content = meta.get("content") or ""
                if name and content:
                    meta_tags_dict[name] = content

        for rule in self.rules:
            evidence_list: List[EvidenceMatch] = []
            extracted_versions: Set[str] = set()

            # 1. Inspect Response Headers
            for header_key, pattern in rule.headers.items():
                val = normalized_headers.get(header_key.lower())
                if val:
                    match = re.search(pattern, val, re.IGNORECASE)
                    if match:
                        desc = f"Response header '{header_key}' matches {rule.technology}"
                        evidence_list.append(EvidenceMatch(
                            type="header",
                            source=header_key,
                            description=desc,
                            value=val,
                            confidence=0.88
                        ))
                        # Version from header match group if captured
                        if match.groups() and match.group(1):
                            extracted_versions.add(match.group(1))

            # 2. Inspect Cookies (safe metadata only)
            for c_info in cookies_metadata:
                c_name = c_info.get("name", "")
                for expected_cookie in rule.cookies:
                    if re.search(f"^{expected_cookie}$", c_name, re.IGNORECASE) or expected_cookie.lower() in c_name.lower():
                        evidence_list.append(EvidenceMatch(
                            type="cookie",
                            source=c_name,
                            description=f"Cookie name '{c_name}' is consistent with {rule.technology}",
                            value=f"Cookie '{c_name}' [Secure: {c_info.get('secure', False)}, HttpOnly: {c_info.get('httponly', False)}]",
                            confidence=0.82
                        ))

            # 3. Inspect Meta Tags
            for m_key, pattern in rule.meta_tags.items():
                meta_val = meta_tags_dict.get(m_key.lower())
                if meta_val:
                    m_match = re.search(pattern, meta_val, re.IGNORECASE)
                    if m_match:
                        evidence_list.append(EvidenceMatch(
                            type="meta",
                            source=f"meta[name='{m_key}']",
                            description=f"HTML meta tag '{m_key}' specifies {rule.technology}",
                            value=meta_val,
                            confidence=0.92
                        ))
                        if m_match.groups() and m_match.group(1):
                            extracted_versions.add(m_match.group(1))

            # 4. Inspect HTML Content
            if html_content:
                for h_pat in rule.html_patterns:
                    h_match = re.search(h_pat, html_content, re.IGNORECASE)
                    if h_match:
                        evidence_list.append(EvidenceMatch(
                            type="html",
                            source="DOM / HTML Source",
                            description=f"HTML markup matches pattern for {rule.technology}",
                            value=h_pat[:40] + ("..." if len(h_pat) > 40 else ""),
                            confidence=0.75
                        ))
                        if h_match.groups() and h_match.group(1):
                            extracted_versions.add(h_match.group(1))

            # 5. Inspect Discovered Scripts (URLs & Content)
            all_scripts = list(discovered_scripts)
            if soup:
                for s in soup.find_all("script", src=True):
                    src_val = s["src"].strip()
                    if src_val and src_val not in all_scripts:
                        all_scripts.append(src_val)

            # Check Script URLs
            for script_url in all_scripts:
                for s_pat in rule.script_patterns:
                    s_match = re.search(s_pat, script_url, re.IGNORECASE)
                    if s_match:
                        evidence_list.append(EvidenceMatch(
                            type="script",
                            source="<script src>",
                            description=f"Referenced script '{script_url.split('/')[-1].split('?')[0]}' indicates {rule.technology}",
                            value=script_url,
                            confidence=0.80
                        ))
                        if s_match.groups() and s_match.group(1):
                            extracted_versions.add(s_match.group(1))

            # Check JS File Contents & Inline Scripts
            if rule.js_content_patterns:
                combined_js_sources = list(inline_scripts) + list(js_contents.values())
                for js_code in combined_js_sources:
                    if not js_code:
                        continue
                    for js_pat in rule.js_content_patterns:
                        js_match = re.search(js_pat, js_code, re.IGNORECASE)
                        if js_match:
                            evidence_list.append(EvidenceMatch(
                                type="script",
                                source="JavaScript Runtime / Bundle",
                                description=f"JavaScript runtime code pattern matches {rule.technology}",
                                value=f"Matched '{js_pat[:40]}'",
                                confidence=0.85
                            ))
                            if js_match.groups() and js_match.group(1):
                                extracted_versions.add(js_match.group(1))

            # 6. Inspect Discovered CSS Stylesheets
            all_styles = list(discovered_stylesheets)
            if soup:
                for link in soup.find_all("link", rel=lambda r: r and "stylesheet" in r):
                    href_val = link.get("href")
                    if href_val and href_val not in all_styles:
                        all_styles.append(href_val)

            for css_url in all_styles:
                for c_pat in rule.css_patterns:
                    c_match = re.search(c_pat, css_url, re.IGNORECASE)
                    if c_match:
                        evidence_list.append(EvidenceMatch(
                            type="css",
                            source="<link rel='stylesheet'>",
                            description=f"Stylesheet asset '{css_url.split('/')[-1].split('?')[0]}' indicates {rule.technology}",
                            value=css_url,
                            confidence=0.78
                        ))
                        if c_match.groups() and c_match.group(1):
                            extracted_versions.add(c_match.group(1))

            # 7. Inspect Discovered URLs / Path Endpoints
            for ep_url in discovered_endpoints:
                parsed_ep = urllib.parse.urlparse(ep_url).path
                for u_pat in rule.url_patterns:
                    if re.search(u_pat, parsed_ep, re.IGNORECASE):
                        evidence_list.append(EvidenceMatch(
                            type="path",
                            source="Discovered Endpoint Path",
                            description=f"URL path '{parsed_ep}' is a characteristic endpoint of {rule.technology}",
                            value=parsed_ep,
                            confidence=0.74
                        ))

            # Check dedicated version regexes across collected evidence values
            for v_regex in rule.version_regexes:
                # Test against all raw evidence strings
                for ev in evidence_list:
                    if ev.value:
                        v_match = v_regex.search(ev.value)
                        if v_match and v_match.groups() and v_match.group(1):
                            extracted_versions.add(v_match.group(1))
                # Also test version regexes directly in JS contents
                for js_code in js_contents.values():
                    v_match = v_regex.search(js_code[:5000])  # check first 5k bytes for header banners
                    if v_match and v_match.groups() and v_match.group(1):
                        extracted_versions.add(v_match.group(1))


            # If evidence was found, compute combined probabilistic confidence
            if evidence_list:
                # Probabilistic combination formula: 1 - product(1 - c_i)
                prob_not = 1.0
                for ev in evidence_list:
                    prob_not *= (1.0 - ev.confidence)
                total_confidence = round(min(0.99, max(0.30, 1.0 - prob_not)), 2)

                # Pick the most specific version
                version: Optional[str] = None
                if extracted_versions:
                    # Choose longest or standard dotted version
                    valid_versions = [v for v in extracted_versions if re.match(r"^[0-9]+(\.[0-9a-zA-Z_-]+)*$", v)]
                    if valid_versions:
                        version = max(valid_versions, key=lambda v: len(v))

                # Deduplicate evidence
                unique_evidences: List[Dict[str, Any]] = []
                seen_ev_keys: Set[str] = set()
                for ev in evidence_list:
                    ev_key = f"{ev.type}:{ev.source}:{ev.value}"
                    if ev_key not in seen_ev_keys:
                        seen_ev_keys.add(ev_key)
                        unique_evidences.append({
                            "type": ev.type,
                            "source": ev.source,
                            "description": ev.description,
                            "value": ev.value
                        })

                if total_confidence >= 0.25:
                    detected_results.append({
                        "technology": rule.technology,
                        "category": rule.category,
                        "version": version,
                        "confidence": total_confidence,
                        "website": rule.website,
                        "description": rule.description,
                        "evidence": unique_evidences[:6]
                    })


        # Sort results by confidence descending
        detected_results.sort(key=lambda x: x["confidence"], reverse=True)
        return detected_results
