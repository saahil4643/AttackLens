import re
from .rules import TechnologyRule

BACKEND_RULES = [
    TechnologyRule(
        technology="Django",
        category="backend",
        website="https://www.djangoproject.com",
        description="High-level Python web framework that encourages rapid development.",
        cookies=["csrftoken", "sessionid", "django_language"],
        headers={
            "x-django-version": r"([0-9\.]+)",
        },
        html_patterns=[
            r'name=["\']csrfmiddlewaretoken["\']',
            r'/static/admin/css/base\.css',
            r'/static/admin/js/core\.js',
        ],
        url_patterns=[
            r"^/admin/login/?",
            r"^/static/admin/",
        ],
        version_regexes=[
            re.compile(r"x-django-version:\s*([0-9\.]+)", re.IGNORECASE)
        ]
    ),
    TechnologyRule(
        technology="Flask",
        category="backend",
        website="https://flask.palletsprojects.com",
        description="Lightweight WSGI Python micro web framework.",
        cookies=["session"],
        headers={
            "x-powered-by": r"Flask",
            "server": r"Werkzeug(?:/([0-9\.]+))?",
        },
        version_regexes=[
            re.compile(r"Werkzeug/([0-9\.]+)", re.IGNORECASE)
        ]
    ),
    TechnologyRule(
        technology="FastAPI",
        category="backend",
        website="https://fastapi.tiangolo.com",
        description="Modern, fast web framework for building APIs with Python 3.8+ based on standard Python type hints.",
        headers={
            "server": r"uvicorn",
        },
        html_patterns=[
            r'SwaggerUIBundle\(',
            r'/docs/oauth2-redirect',
            r'redoc-spec-url',
        ],
        url_patterns=[
            r"^/docs/?$",
            r"^/redoc/?$",
            r"^/openapi\.json$",
        ]
    ),
    TechnologyRule(
        technology="Laravel",
        category="backend",
        website="https://laravel.com",
        description="PHP web application framework with expressive, elegant syntax.",
        cookies=["laravel_session", "XSRF-TOKEN", "laravel_token"],
        headers={
            "x-powered-by": r"Laravel",
        },
        html_patterns=[
            r'window\.Laravel\s*=',
            r'name=["\']csrf-token["\']\s+content=["\'][a-zA-Z0-9]{40}',
        ],
        url_patterns=[
            r"^/sanctum/csrf-cookie",
            r"^/telescope/?",
            r"^/horizon/?",
        ]
    ),
    TechnologyRule(
        technology="PHP",
        category="backend",
        website="https://www.php.net",
        description="General-purpose scripting language especially suited to web development.",
        cookies=["PHPSESSID"],
        headers={
            "x-powered-by": r"PHP(?:/([0-9\.]+))?",
            "server": r"PHP(?:/([0-9\.]+))?",
        },
        html_patterns=[
            r'\.php(?:\?[^"\'<>\s]*)?["\']',
        ],
        version_regexes=[
            re.compile(r"PHP/([0-9\.]+)", re.IGNORECASE)
        ]
    ),
    TechnologyRule(
        technology="Spring Boot",
        category="backend",
        website="https://spring.io/projects/spring-boot",
        description="Java-based framework used to create stand-alone, production-grade Spring-based Applications.",
        cookies=["JSESSIONID"],
        headers={
            "x-application-context": r".*",
        },
        html_patterns=[
            r'Whitelabel Error Page',
            r'This application has no explicit mapping for /error',
        ],
        url_patterns=[
            r"^/actuator(?:/health|/info|/env)?",
        ]
    ),
    TechnologyRule(
        technology="Express",
        category="backend",
        website="https://expressjs.com",
        description="Fast, unopinionated, minimalist web framework for Node.js.",
        cookies=["connect.sid"],
        headers={
            "x-powered-by": r"Express",
        }
    ),
    TechnologyRule(
        technology="Ruby on Rails",
        category="backend",
        website="https://rubyonrails.org",
        description="Server-side web application framework written in Ruby.",
        cookies=["_session_id", "_rails_session"],
        headers={
            "x-powered-by": r"Phusion Passenger",
            "x-runtime": r"^[0-9\.]+$",
            "x-rack-cache": r".*",
        },
        html_patterns=[
            r'data-turbo-track',
            r'csrf-param["\']\s+content=["\']authenticity_token',
        ]
    ),
    TechnologyRule(
        technology="ASP.NET",
        category="backend",
        website="https://dotnet.microsoft.com/apps/aspnet",
        description="Cross-platform, high-performance, open-source framework for building modern, cloud-enabled web applications.",
        cookies=["ASP.NET_SessionId", ".AspNetCore.Antiforgery", ".AspNetCore.Cookies", ".AspNetCore.Session"],
        headers={
            "x-powered-by": r"ASP\.NET",
            "x-aspnet-version": r"([0-9\.]+)",
            "x-aspnetmvc-version": r"([0-9\.]+)",
        },
        html_patterns=[
            r'id=["\']__VIEWSTATE["\']',
            r'id=["\']__EVENTVALIDATION["\']',
        ],
        version_regexes=[
            re.compile(r"X-AspNet-Version:\s*([0-9\.]+)", re.IGNORECASE),
            re.compile(r"X-AspNetMvc-Version:\s*([0-9\.]+)", re.IGNORECASE)
        ]
    ),
    TechnologyRule(
        technology="Node.js",
        category="backend",
        website="https://nodejs.org",
        description="Open-source, cross-platform JavaScript runtime environment.",
        headers={
            "x-powered-by": r"Node\.js|Express|Next\.js|Nuxt",
        }
    ),
]
