import re
from .rules import TechnologyRule

WEB_SERVER_RULES = [
    TechnologyRule(
        technology="nginx",
        category="web_server",
        website="https://nginx.org",
        description="High-performance asynchronous HTTP server and reverse proxy.",
        headers={
            "server": r"nginx(?:/([0-9\.]+))?",
            "x-powered-by": r"nginx",
        },
        version_regexes=[
            re.compile(r"nginx/([0-9\.]+)", re.IGNORECASE)
        ]
    ),
    TechnologyRule(
        technology="Apache HTTP Server",
        category="web_server",
        website="https://httpd.apache.org",
        description="Open-source HTTP server by the Apache Software Foundation.",
        headers={
            "server": r"Apache(?:/([0-9\.]+))?",
        },
        version_regexes=[
            re.compile(r"Apache/([0-9\.]+)", re.IGNORECASE)
        ]
    ),
    TechnologyRule(
        technology="Microsoft IIS",
        category="web_server",
        website="https://www.iis.net",
        description="Extensible web server created by Microsoft for Windows Server.",
        headers={
            "server": r"Microsoft-IIS(?:/([0-9\.]+))?",
            "x-powered-by": r"ASP\.NET",
            "x-aspnet-version": r"([0-9\.]+)",
        },
        version_regexes=[
            re.compile(r"Microsoft-IIS/([0-9\.]+)", re.IGNORECASE),
            re.compile(r"X-AspNet-Version:\s*([0-9\.]+)", re.IGNORECASE)
        ]
    ),
    TechnologyRule(
        technology="Caddy",
        category="web_server",
        website="https://caddyserver.com",
        description="Fast, multi-platform open-source web server written in Go with automatic HTTPS.",
        headers={
            "server": r"Caddy(?:/v?([0-9\.]+))?",
        },
        version_regexes=[
            re.compile(r"Caddy/v?([0-9\.]+)", re.IGNORECASE)
        ]
    ),
    TechnologyRule(
        technology="LiteSpeed",
        category="web_server",
        website="https://www.litespeedtech.com",
        description="High-performance, lightweight Apache-compatible web server.",
        headers={
            "server": r"LiteSpeed",
            "x-litespeed-cache": r".*",
        }
    ),
    TechnologyRule(
        technology="OpenResty",
        category="web_server",
        website="https://openresty.org",
        description="Full-fledged web platform that integrates the standard Nginx core with LuaJIT.",
        headers={
            "server": r"openresty(?:/([0-9\.]+))?",
        },
        version_regexes=[
            re.compile(r"openresty/([0-9\.]+)", re.IGNORECASE)
        ]
    ),
    TechnologyRule(
        technology="Cloudflare Server",
        category="web_server",
        website="https://cloudflare.com",
        description="Cloudflare edge reverse proxy server layer.",
        headers={
            "server": r"cloudflare",
        }
    ),
    TechnologyRule(
        technology="Gunicorn",
        category="web_server",
        website="https://gunicorn.org",
        description="Python WSGI HTTP Server for UNIX.",
        headers={
            "server": r"gunicorn(?:/([0-9\.]+))?",
        },
        version_regexes=[
            re.compile(r"gunicorn/([0-9\.]+)", re.IGNORECASE)
        ]
    ),
    TechnologyRule(
        technology="uWSGI",
        category="web_server",
        website="https://uwsgi-docs.readthedocs.io",
        description="Application server container with WSGI and HTTP implementations.",
        headers={
            "server": r"uWSGI",
        }
    ),
    TechnologyRule(
        technology="Envoy",
        category="web_server",
        website="https://www.envoyproxy.io",
        description="High performance C++ distributed proxy designed for cloud-native applications.",
        headers={
            "server": r"envoy",
            "x-envoy-upstream-service-time": r".*",
        }
    ),
    TechnologyRule(
        technology="Kestrel",
        category="web_server",
        website="https://learn.microsoft.com/aspnet/core/fundamentals/servers/kestrel",
        description="Cross-platform web server for ASP.NET Core.",
        headers={
            "server": r"Kestrel",
        }
    ),
]
