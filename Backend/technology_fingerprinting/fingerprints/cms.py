import re
from .rules import TechnologyRule

CMS_RULES = [
    TechnologyRule(
        technology="WordPress",
        category="cms",
        website="https://wordpress.org",
        description="Free and open-source Content Management System written in PHP.",
        meta_tags={
            "generator": r"WordPress(?: ([0-9\.]+))?",
        },
        html_patterns=[
            r'/wp-content/themes/',
            r'/wp-content/plugins/',
            r'/wp-includes/js/',
            r'name=["\']generator["\']\s+content=["\']WordPress(?:\s+([0-9\.]+))?["\']',
        ],
        url_patterns=[
            r"^/wp-admin/?",
            r"^/wp-login\.php",
            r"^/wp-json/?",
            r"^/wp-content/",
            r"^/wp-includes/",
        ],
        script_patterns=[
            r'/wp-includes/js/wp-embed\.min\.js',
            r'/wp-content/plugins/',
        ],
        version_regexes=[
            re.compile(r"WordPress\s+([0-9\.]+)", re.IGNORECASE),
            re.compile(r"ver=([0-9\.]+)", re.IGNORECASE)
        ]
    ),
    TechnologyRule(
        technology="Drupal",
        category="cms",
        website="https://www.drupal.org",
        description="Flexible, open-source CMS platform built on PHP and Symfony components.",
        headers={
            "x-drupal-cache": r".*",
            "x-drupal-dynamic-cache": r".*",
            "x-generator": r"Drupal\s*([0-9\.]+)?",
        },
        meta_tags={
            "generator": r"Drupal(?:\s+([0-9\.]+))?",
        },
        html_patterns=[
            r'/sites/default/files/',
            r'/core/assets/vendor/',
            r'Drupal\.settings',
        ],
        url_patterns=[
            r"^/sites/default/",
            r"^/core/misc/",
        ],
        version_regexes=[
            re.compile(r"Drupal\s+([0-9\.]+)", re.IGNORECASE)
        ]
    ),
    TechnologyRule(
        technology="Joomla",
        category="cms",
        website="https://www.joomla.org",
        description="Free and open-source content management system for publishing web content.",
        meta_tags={
            "generator": r"Joomla!(?:\s+([0-9\.]+))?",
        },
        html_patterns=[
            r'/media/jui/js/',
            r'/media/system/js/',
        ],
        url_patterns=[
            r"^/administrator/?",
            r"^/media/com_",
        ],
        version_regexes=[
            re.compile(r"Joomla!\s+([0-9\.]+)", re.IGNORECASE)
        ]
    ),
    TechnologyRule(
        technology="Shopify",
        category="cms",
        website="https://www.shopify.com",
        description="E-commerce platform for online stores and retail point-of-sale systems.",
        headers={
            "x-shopid": r".*",
            "x-shardid": r".*",
        },
        html_patterns=[
            r'cdn\.shopify\.com',
            r'window\.Shopify\s*=',
            r'Shopify\.theme',
        ],
        script_patterns=[
            r'cdn\.shopify\.com/s/files/',
        ]
    ),
    TechnologyRule(
        technology="Ghost",
        category="cms",
        website="https://ghost.org",
        description="Modern open-source publishing platform built on Node.js.",
        meta_tags={
            "generator": r"Ghost(?:\s+([0-9\.]+))?",
        },
        headers={
            "x-ghost-cache-status": r".*",
        },
        html_patterns=[
            r'ghost-search',
            r'class=["\']gh-head["\']',
        ],
        version_regexes=[
            re.compile(r"Ghost\s+([0-9\.]+)", re.IGNORECASE)
        ]
    ),
    TechnologyRule(
        technology="Webflow",
        category="cms",
        website="https://webflow.com",
        description="Visual web development platform, CMS, and hosting provider.",
        meta_tags={
            "generator": r"Webflow",
        },
        html_patterns=[
            r'data-wf-page',
            r'data-wf-site',
            r'uploads-ssl\.webflow\.com',
        ]
    ),
    TechnologyRule(
        technology="Wix",
        category="cms",
        website="https://www.wix.com",
        description="Cloud-based web development platform.",
        headers={
            "x-wix-request-id": r".*",
        },
        html_patterns=[
            r'static\.wixstatic\.com',
            r'_wixCssLoaded',
        ]
    ),
    TechnologyRule(
        technology="Squarespace",
        category="cms",
        website="https://www.squarespace.com",
        description="All-in-one content management system and website building platform.",
        headers={
            "x-served-by": r"Squarespace",
        },
        html_patterns=[
            r'static1\.squarespace\.com',
            r'<!-- This is Squarespace\. -->',
        ]
    ),
    TechnologyRule(
        technology="Strapi",
        category="cms",
        website="https://strapi.io",
        description="Open-source Headless CMS based on Node.js.",
        url_patterns=[
            r"^/admin/init",
            r"^/api/users-permissions",
        ],
        html_patterns=[
            r'Strapi Admin',
        ]
    ),
]
