"""
API Deep Analysis Data Models
"""
from typing import Dict, Any, List, Optional


class ApiParameter:
    def __init__(
        self,
        name: str,
        location: str = "query",  # path, query, header, body, cookie
        param_type: str = "unknown",  # string, integer, number, boolean, array, object, unknown
        required: bool = False,
        description: str = "",
        example: Optional[Any] = None
    ):
        self.name = name
        self.location = location
        self.type = param_type
        self.required = required
        self.description = description
        self.example = example

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "location": self.location,
            "type": self.type,
            "required": self.required,
            "description": self.description,
            "example": self.example
        }


class ApiAuthIndicator:
    def __init__(
        self,
        required: bool = False,
        auth_type: str = "none",  # bearer, api_key, basic, oauth2, cookie, none, unknown
        evidence: Optional[List[str]] = None,
        scheme_name: Optional[str] = None
    ):
        self.required = required
        self.type = auth_type
        self.evidence = evidence or []
        self.scheme_name = scheme_name

    def to_dict(self) -> Dict[str, Any]:
        return {
            "required": self.required,
            "type": self.type,
            "evidence": self.evidence,
            "scheme_name": self.scheme_name
        }


class ApiResponseInfo:
    def __init__(
        self,
        status_code: Optional[int] = None,
        content_type: Optional[str] = None,
        structure: str = "unknown",  # object, array, primitive, unknown
        size_bytes: Optional[int] = None,
        schema_summary: Optional[str] = None
    ):
        self.status_code = status_code
        self.content_type = content_type
        self.structure = structure
        self.size_bytes = size_bytes
        self.schema_summary = schema_summary

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status_code": self.status_code,
            "content_type": self.content_type,
            "structure": self.structure,
            "size_bytes": self.size_bytes,
            "schema_summary": self.schema_summary
        }


class ApiRateLimitInfo:
    def __init__(
        self,
        detected: bool = False,
        limit: Optional[str] = None,
        remaining: Optional[str] = None,
        reset: Optional[str] = None,
        retry_after: Optional[str] = None
    ):
        self.detected = detected
        self.limit = limit
        self.remaining = remaining
        self.reset = reset
        self.retry_after = retry_after

    def to_dict(self) -> Dict[str, Any]:
        return {
            "detected": self.detected,
            "limit": self.limit,
            "remaining": self.remaining,
            "reset": self.reset,
            "retry_after": self.retry_after
        }


class ApiEndpoint:
    def __init__(
        self,
        endpoint: str,
        path: str,
        hostname: str,
        method: str = "GET",
        api_type: str = "REST",  # REST, GraphQL, API Documentation, Web Endpoint, Unknown
        version: Optional[str] = None,
        source: str = "crawler",  # openapi, javascript, crawler, sitemap, robots, forms, direct
        summary: Optional[str] = None,
        description: Optional[str] = None,
        parameters: Optional[List[ApiParameter]] = None,
        authentication: Optional[ApiAuthIndicator] = None,
        response: Optional[ApiResponseInfo] = None,
        rate_limit: Optional[ApiRateLimitInfo] = None,
        cors: Optional[Dict[str, Any]] = None,
        confidence: float = 0.90
    ):
        self.endpoint = endpoint
        self.path = path
        self.hostname = hostname
        self.method = method.upper()
        self.type = api_type
        self.version = version
        self.source = source
        self.summary = summary
        self.description = description
        self.parameters = parameters or []
        self.authentication = authentication or ApiAuthIndicator()
        self.response = response or ApiResponseInfo()
        self.rate_limit = rate_limit or ApiRateLimitInfo()
        self.cors = cors or {}
        self.confidence = round(confidence, 2)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "path": self.path,
            "hostname": self.hostname,
            "method": self.method,
            "type": self.type,
            "version": self.version,
            "source": self.source,
            "summary": self.summary,
            "description": self.description,
            "parameters": [p.to_dict() for p in self.parameters],
            "authentication": self.authentication.to_dict(),
            "response": self.response.to_dict(),
            "rate_limit": self.rate_limit.to_dict(),
            "cors": self.cors,
            "confidence": self.confidence
        }


class ApiDocumentation:
    def __init__(
        self,
        url: str,
        doc_format: str = "openapi",  # openapi, swagger, api_docs
        title: Optional[str] = None,
        version: Optional[str] = None,
        endpoint_count: int = 0,
        auth_schemes: Optional[List[str]] = None
    ):
        self.url = url
        self.format = doc_format
        self.title = title
        self.version = version
        self.endpoint_count = endpoint_count
        self.auth_schemes = auth_schemes or []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "format": self.format,
            "title": self.title,
            "version": self.version,
            "endpoint_count": self.endpoint_count,
            "auth_schemes": self.auth_schemes
        }


class ApiFinding:
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
        self.category = category  # api_documentation, authentication, rate_limiting, graphql, deprecated_version, information_disclosure
        self.severity = severity  # info, low, medium
        self.confidence = round(confidence, 2)
        self.description = description
        self.evidence = evidence
        self.recommendation = recommendation

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation
        }
