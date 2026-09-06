import re
from .rules import TechnologyRule

DATABASE_API_AUTH_RULES = [
    TechnologyRule(
        technology="GraphQL",
        category="api",
        website="https://graphql.org",
        description="Query language for APIs and runtime for fulfilling queries with existing data.",
        url_patterns=[
            r"^/graphql/?$",
            r"^/api/graphql/?$",
            r"^/v1/graphql/?$",
        ],
        html_patterns=[
            r'__schema',
            r'GraphQL Playground',
            r'GraphiQL',
        ]
    ),
    TechnologyRule(
        technology="Swagger / OpenAPI",
        category="api",
        website="https://swagger.io",
        description="API documentation and interactive interface generation tool.",
        url_patterns=[
            r"^/swagger(?:-ui)?/?",
            r"^/v2/api-docs",
            r"^/v3/api-docs",
            r"^/openapi\.json",
            r"^/api-docs",
        ],
        html_patterns=[
            r'swagger-ui',
            r'SwaggerUIBundle',
        ]
    ),
    TechnologyRule(
        technology="Auth0",
        category="authentication",
        website="https://auth0.com",
        description="Adaptable authentication and authorization platform.",
        cookies=["auth0", "auth0_compat", "a0:session"],
        script_patterns=[
            r'cdn\.auth0\.com/js/auth0-spa-js/',
            r'cdn\.auth0\.com/js/lock/',
        ]
    ),
    TechnologyRule(
        technology="Firebase",
        category="backend",
        website="https://firebase.google.com",
        description="App development platform backed by Google with Realtime Database, Firestore, and Auth.",
        script_patterns=[
            r'gstatic\.com/firebasejs/([0-9\.]+)/firebase',
            r'firebase-app\.js',
            r'firebase-auth\.js',
        ],
        html_patterns=[
            r'firebaseConfig',
            r'firebase\.initializeApp\(',
        ],
        version_regexes=[
            re.compile(r'firebasejs/([0-9\.]+)/', re.IGNORECASE)
        ]
    ),
    TechnologyRule(
        technology="Supabase",
        category="backend",
        website="https://supabase.com",
        description="Open source Firebase alternative built on top of PostgreSQL.",
        cookies=["sb-access-token", "sb-refresh-token"],
        script_patterns=[
            r'cdn\.jsdelivr\.net/npm/@supabase/supabase-js',
        ]
    ),
    TechnologyRule(
        technology="Keycloak",
        category="authentication",
        website="https://www.keycloak.org",
        description="Open Source Identity and Access Management for modern applications and services.",
        cookies=["KEYCLOAK_IDENTITY", "KEYCLOAK_SESSION"],
        url_patterns=[
            r"^/auth/realms/",
        ],
        script_patterns=[
            r'/auth/js/keycloak\.js',
        ]
    ),
]
