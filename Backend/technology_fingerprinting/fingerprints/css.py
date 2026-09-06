import re
from .rules import TechnologyRule

CSS_RULES = [
    TechnologyRule(
        technology="Bootstrap",
        category="css",
        website="https://getbootstrap.com",
        description="Powerful, extensible, and feature-packed frontend toolkit.",
        css_patterns=[
            r'bootstrap(?:\.min)?\.css',
            r'/bootstrap/([0-9\.]+)/css/',
            r'cdn\.jsdelivr\.net/npm/bootstrap@([0-9\.]+)',
        ],
        html_patterns=[
            r'class=["\'][^"\']*\b(?:col-(?:xs|sm|md|lg|xl|xxl)-\d+|btn-(?:primary|secondary|success|danger|warning|info)|navbar-expand|d-flex)\b[^"\']*["\']',
        ],
        script_patterns=[
            r'bootstrap(?:\.bundle)?(?:\.min)?\.js',
            r'/bootstrap/([0-9\.]+)/js/',
        ],
        version_regexes=[
            re.compile(r'bootstrap[@/-]([0-9\.]+)', re.IGNORECASE)
        ]
    ),
    TechnologyRule(
        technology="Tailwind CSS",
        category="css",
        website="https://tailwindcss.com",
        description="Utility-first CSS framework packed with classes like flex, pt-4, text-center and rotate-90.",
        css_patterns=[
            r'tailwind(?:\.min)?\.css',
        ],
        html_patterns=[
            r'class=["\'][^"\']*\b(?:flex|grid|items-center|justify-between|bg-(?:slate|gray|zinc|neutral|stone|red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose)-\d{2,3}|text-(?:xs|sm|base|lg|xl|2xl|3xl)|p-\d+|px-\d+|py-\d+|m-\d+|mx-\d+|my-\d+|rounded-(?:sm|md|lg|xl|2xl|full))\b[^"\']*["\']',
        ],
        script_patterns=[
            r'cdn\.tailwindcss\.com',
        ]
    ),
    TechnologyRule(
        technology="Foundation",
        category="css",
        website="https://get.foundation",
        description="Responsive front-end framework by ZURB.",
        css_patterns=[
            r'foundation(?:\.min)?\.css',
        ],
        html_patterns=[
            r'class=["\'][^"\']*\b(?:small|medium|large)-\d+\s+columns\b',
        ]
    ),
    TechnologyRule(
        technology="Bulma",
        category="css",
        website="https://bulma.io",
        description="Free, open source CSS framework based on Flexbox.",
        css_patterns=[
            r'bulma(?:\.min)?\.css',
        ],
        html_patterns=[
            r'class=["\'][^"\']*\b(?:is-primary|is-info|is-success|is-warning|is-danger|has-text-centered|hero-body)\b',
        ]
    ),
    TechnologyRule(
        technology="Font Awesome",
        category="css",
        website="https://fontawesome.com",
        description="Icon library and toolkit.",
        css_patterns=[
            r'font-awesome(?:\.min)?\.css',
            r'all(?:\.min)?\.css',
            r'fontawesome',
        ],
        html_patterns=[
            r'class=["\'][^"\']*\b(?:fa|fas|far|fal|fad|fab)\s+fa-[a-z0-9-]+',
        ],
        script_patterns=[
            r'fontawesome',
            r'kit\.fontawesome\.com',
        ]
    ),
    TechnologyRule(
        technology="Material-UI / MUI",
        category="css",
        website="https://mui.com",
        description="React component library that implements Google's Material Design.",
        html_patterns=[
            r'class=["\'][^"\']*\b(?:MuiButton-|MuiTypography-|MuiBox-|MuiGrid-|MuiContainer-|MuiPaper-)[^"\']*["\']',
        ]
    ),
]
