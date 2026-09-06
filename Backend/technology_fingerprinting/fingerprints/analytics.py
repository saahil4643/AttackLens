import re
from .rules import TechnologyRule

ANALYTICS_RULES = [
    TechnologyRule(
        technology="Google Analytics",
        category="analytics",
        website="https://analytics.google.com",
        description="Web analytics service offered by Google that tracks and reports website traffic.",
        cookies=["_ga", "_gid", "_gat", "__utma", "__utmb", "__utmc", "__utmz"],
        script_patterns=[
            r'google-analytics\.com/(?:ga|analytics)\.js',
            r'googletagmanager\.com/gtag/js',
        ],
        html_patterns=[
            r'gtag\(["\']config["\'],\s*["\'](G-[A-Z0-9]+|UA-[0-9-]+)["\']',
            r'ga\(["\']create["\'],\s*["\']UA-[0-9-]+["\']',
        ]
    ),
    TechnologyRule(
        technology="Google Tag Manager",
        category="analytics",
        website="https://tagmanager.google.com",
        description="Tag management system that allows you to quickly update measurement codes and related code fragments.",
        script_patterns=[
            r'googletagmanager\.com/gtm\.js\?id=(GTM-[A-Z0-9]+)',
        ],
        html_patterns=[
            r'<!-- Google Tag Manager -->',
            r'https://www.googletagmanager.com/gtm\.js\?id=',
        ]
    ),
    TechnologyRule(
        technology="Matomo",
        category="analytics",
        website="https://matomo.org",
        description="Open source web analytics application.",
        cookies=["_pk_id", "_pk_ses", "_pk_ref"],
        script_patterns=[
            r'matomo\.js',
            r'piwik\.js',
        ],
        html_patterns=[
            r'_paq\.push\(',
        ]
    ),
    TechnologyRule(
        technology="Hotjar",
        category="analytics",
        website="https://www.hotjar.com",
        description="Product experience insights platform with heatmaps and user feedback recordings.",
        cookies=["_hjSessionUser", "_hjSession", "_hjIncludedInSessionSample"],
        script_patterns=[
            r'static\.hotjar\.com/c/hotjar-([0-9]+)\.js',
        ]
    ),
    TechnologyRule(
        technology="Segment",
        category="analytics",
        website="https://segment.com",
        description="Customer Data Platform (CDP) for collecting and routing analytics data.",
        script_patterns=[
            r'cdn\.segment\.com/analytics\.js/v1/([a-zA-Z0-9]+)/analytics\.min\.js',
        ],
        html_patterns=[
            r'analytics\.load\(',
        ]
    ),
    TechnologyRule(
        technology="Plausible Analytics",
        category="analytics",
        website="https://plausible.io",
        description="Lightweight and open-source Google Analytics alternative without cookies.",
        script_patterns=[
            r'plausible\.io/js/script\.js',
            r'plausible\.io/js/plausible\.js',
        ]
    ),
]
