"""
Data models and schemas for Overall Web Application Attack-Surface Analysis.
"""
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional


@dataclass
class AssetRecord:
    host: str
    ip: Optional[str] = None
    port: Optional[int] = None
    protocol: str = "HTTP"
    service: str = "web"
    scope: str = "in_scope"  # in_scope | out_of_scope | external_dependency | unknown
    source: str = "discovery"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class WebServiceRecord:
    host: str
    port: int
    protocol: str
    status_code: Optional[int] = None
    server: Optional[str] = None
    final_url: Optional[str] = None
    page_title: Optional[str] = None
    technologies: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EndpointSurfaceRecord:
    path: str
    url: str
    method: str = "GET"
    content_type: Optional[str] = None
    source: str = "crawler"
    status_code: Optional[int] = None
    category: str = "page"  # page | api | authentication | administrative | static | upload | documentation | health | unknown
    confidence: float = 0.90
    authentication: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ApiSurfaceRecord:
    endpoint: str
    path: str
    method: str = "GET"
    type: str = "REST"  # REST | GraphQL | RPC | unknown
    version: Optional[str] = None
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    authentication: Optional[Dict[str, Any]] = None
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    documentation_source: Optional[str] = None
    rate_limit: Optional[Dict[str, Any]] = None
    confidence: float = 0.95

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AuthSurfaceRecord:
    endpoint: str
    type: str  # login | registration | password_reset | oauth | token | session | sso | 2fa
    method: str = "POST"
    source: str = "endpoint_discovery"
    confidence: float = 0.90
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SessionSurfaceRecord:
    cookie_name: str
    is_secure: bool = False
    is_httponly: bool = False
    same_site: Optional[str] = None
    domain: Optional[str] = None
    path: Optional[str] = None
    likely_session_indicator: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FormSurfaceRecord:
    action: str
    method: str = "GET"
    input_names: List[str] = field(default_factory=list)
    input_types: List[str] = field(default_factory=list)
    fields_count: int = 0
    classification: str = "unknown"  # login | registration | search | contact | upload | password | feedback | unknown
    confidence: float = 0.85

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FileUploadSurfaceRecord:
    endpoint: str
    method: str = "POST"
    type: str = "form_input"  # form_input | multipart_api | direct_upload
    source: str = "form"
    confidence: float = 0.95
    evidence: str = "File input element detected in form"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AdminSurfaceRecord:
    endpoint: str
    classification: str = "administrative"  # administrative | management | control_panel | dashboard
    confidence: float = 0.88
    evidence: str = "Administrative URL pattern match"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DocSurfaceRecord:
    documentation_url: str
    spec_format: str = "openapi"  # openapi | swagger | graphql | api_docs | html_docs
    api_version: Optional[str] = None
    endpoint_count: int = 0
    source: str = "discovery"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DebugErrorSurfaceRecord:
    endpoint: str
    type: str  # debug_page | stack_trace | verbose_error | server_disclosure | internal_path
    severity: str = "info"  # info | low | medium
    evidence_redacted: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class OperationalSurfaceRecord:
    endpoint: str
    type: str = "health"  # health | metrics | ready | liveness | ping | status
    method: str = "GET"
    status_code: Optional[int] = None
    confidence: float = 0.90

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class WebSocketSurfaceRecord:
    url: str
    protocol: str = "wss"  # ws | wss
    source: str = "javascript"
    confidence: float = 0.90

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ExternalDependencyRecord:
    host: str
    category: str = "cdn"  # cdn | analytics | payment | identity | storage | font | api | unknown
    source: str = "html"
    referenced_urls: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ParameterSurfaceRecord:
    name: str
    location: str = "query"  # query | path | form | header | body
    endpoints: List[str] = field(default_factory=list)
    parameter_type: str = "string"
    source: str = "crawler"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FunctionalityCategoryRecord:
    category: str  # authentication | authorization | account_management | search | file_upload | payments | checkout | profile | administration | content | messaging | api | documentation | health | unknown
    confidence: float = 0.85
    endpoints: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TestCandidateRecord:
    area: str  # authentication | authorization | api | input_validation | file_upload | session_management | business_logic | administration | websocket | configuration | information_disclosure
    endpoint: str
    method: str = "GET"
    reason: str = ""
    priority: str = "medium"  # high | medium | low

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AttackSurfaceSummary:
    assets: int = 0
    web_services: int = 0
    endpoints: int = 0
    api_endpoints: int = 0
    authentication_surfaces: int = 0
    forms: int = 0
    file_uploads: int = 0
    administrative_surfaces: int = 0
    documentation: int = 0
    websockets: int = 0
    operational_endpoints: int = 0
    external_dependencies: int = 0
    parameters: int = 0
    test_candidates: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
