"""
Parameter Extraction & Type Inference Service
"""
import re
import urllib.parse
from typing import List, Tuple, Any
from .models import ApiParameter

SENSITIVE_PARAM_NAMES = {
    "password", "pass", "pwd", "secret", "token", "auth", "access_token",
    "refresh_token", "apikey", "api_key", "key", "authorization", "bearer",
    "session", "sessionid", "sid", "jwt", "private_key", "card", "cvv"
}

UUID_REGEX = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')


def infer_primitive_type(value_str: str) -> str:
    """Infers primitive JSON/API type from a raw string value."""
    if not value_str:
        return "string"
    v = value_str.strip().lower()
    if v in ("true", "false"):
        return "boolean"
    if v.isdigit() or (v.startswith("-") and v[1:].isdigit()):
        return "integer"
    try:
        float(v)
        return "number"
    except ValueError:
        pass
    if "," in value_str:
        return "array"
    return "string"


def sanitize_example(param_name: str, value: Any) -> Any:
    """Redacts sensitive values from parameter examples."""
    if not value:
        return None
    name_clean = param_name.lower().replace("-", "_")
    if any(s in name_clean for s in SENSITIVE_PARAM_NAMES):
        return "[REDACTED]"
    return str(value)


def extract_parameters_from_url(url_or_path: str) -> List[ApiParameter]:
    """
    Extracts path and query parameters from a URL or URI template.
    """
    params: List[ApiParameter] = []
    parsed = urllib.parse.urlparse(url_or_path)
    path = parsed.path or "/"
    query = parsed.query

    # 1. Path Parameters Extraction
    # Case A: Template bracket notation /users/{id}
    template_matches = re.findall(r'\{([a-zA-Z0-9_\-]+)\}', path)
    for p_name in template_matches:
        params.append(ApiParameter(
            name=p_name,
            location="path",
            param_type="string",
            required=True,
            description="Path parameter"
        ))

    # Case B: Colon notation /users/:id
    colon_matches = re.findall(r':([a-zA-Z0-9_\-]+)', path)
    for p_name in colon_matches:
        if p_name not in [p.name for p in params]:
            params.append(ApiParameter(
                name=p_name,
                location="path",
                param_type="string",
                required=True,
                description="Path parameter"
            ))

    # Case C: Dynamic ID segment detection /api/users/123 or /api/orders/550e8400...
    segments = [s for s in path.split("/") if s]
    for idx, seg in enumerate(segments):
        if not seg.startswith("{") and not seg.startswith(":"):
            if seg.isdigit():
                prev_seg = segments[idx - 1] if idx > 0 else "item"
                p_name = f"{prev_seg.rstrip('s')}_id" if prev_seg.endswith("s") else f"{prev_seg}_id"
                if p_name not in [p.name for p in params]:
                    params.append(ApiParameter(
                        name=p_name,
                        location="path",
                        param_type="integer",
                        required=True,
                        description=f"Inferred path ID from segment '{seg}'",
                        example=seg
                    ))
            elif UUID_REGEX.match(seg):
                prev_seg = segments[idx - 1] if idx > 0 else "item"
                p_name = f"{prev_seg.rstrip('s')}_uuid" if prev_seg.endswith("s") else f"{prev_seg}_uuid"
                if p_name not in [p.name for p in params]:
                    params.append(ApiParameter(
                        name=p_name,
                        location="path",
                        param_type="string",
                        required=True,
                        description=f"Inferred UUID path parameter",
                        example="[UUID]"
                    ))

    # 2. Query Parameters Extraction
    if query:
        query_dict = urllib.parse.parse_qs(query, keep_blank_values=True)
        for q_name, q_vals in query_dict.items():
            first_val = q_vals[0] if q_vals else ""
            inferred_t = infer_primitive_type(first_val)
            safe_ex = sanitize_example(q_name, first_val)

            params.append(ApiParameter(
                name=q_name,
                location="query",
                param_type=inferred_t,
                required=False,
                description="Query parameter",
                example=safe_ex
            ))

    return params
