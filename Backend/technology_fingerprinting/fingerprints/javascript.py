import re
from .rules import TechnologyRule

JAVASCRIPT_LIB_RULES = [
    TechnologyRule(
        technology="Axios",
        category="javascript",
        website="https://axios-http.com",
        description="Promise-based HTTP client for the browser and node.js.",
        script_patterns=[
            r'axios(?:\.min)?\.js',
            r'cdn\.jsdelivr\.net/npm/axios@([0-9\.]+)',
        ],
        version_regexes=[
            re.compile(r'axios@([0-9\.]+)', re.IGNORECASE)
        ]
    ),
    TechnologyRule(
        technology="Lodash",
        category="javascript",
        website="https://lodash.com",
        description="Modern JavaScript utility library delivering modularity, performance, and extras.",
        script_patterns=[
            r'lodash(?:\.min)?\.js',
            r'cdn\.jsdelivr\.net/npm/lodash@([0-9\.]+)',
        ],
        version_regexes=[
            re.compile(r'lodash@([0-9\.]+)', re.IGNORECASE)
        ]
    ),
    TechnologyRule(
        technology="Moment.js",
        category="javascript",
        website="https://momentjs.com",
        description="Parse, validate, manipulate, and display dates and times in JavaScript.",
        script_patterns=[
            r'moment(?:\.min)?\.js',
            r'/moment/([0-9\.]+)/moment\.min\.js',
        ],
        version_regexes=[
            re.compile(r'moment/([0-9\.]+)/', re.IGNORECASE)
        ]
    ),
    TechnologyRule(
        technology="Chart.js",
        category="javascript",
        website="https://www.chartjs.org",
        description="Simple yet flexible JavaScript charting for designers and developers.",
        script_patterns=[
            r'chart(?:\.min)?\.js',
            r'cdn\.jsdelivr\.net/npm/chart\.js@([0-9\.]+)',
        ],
        version_regexes=[
            re.compile(r'chart\.js@([0-9\.]+)', re.IGNORECASE)
        ]
    ),
    TechnologyRule(
        technology="Three.js",
        category="javascript",
        website="https://threejs.org",
        description="JavaScript 3D library for WebGL rendering.",
        script_patterns=[
            r'three(?:\.min)?\.js',
            r'/r([0-9]+)/three\.min\.js',
        ],
        version_regexes=[
            re.compile(r'/r([0-9]+)/three', re.IGNORECASE)
        ]
    ),
    TechnologyRule(
        technology="Webpack",
        category="javascript",
        website="https://webpack.js.org",
        description="Static module bundler for modern JavaScript applications.",
        html_patterns=[
            r'webpackJsonp',
            r'window\[["\']webpackChunk',
            r'__webpack_require__',
        ],
        script_patterns=[
            r'webpack\.',
        ]
    ),
    TechnologyRule(
        technology="Vite",
        category="javascript",
        website="https://vite.dev",
        description="Next generation frontend tooling and build system.",
        html_patterns=[
            r'<script type=["\']module["\'] src=["\']/@vite/client["\']>',
            r'<script type=["\']module["\'] src=["\']/src/main\.(?:jsx?|tsx?)["\']>',
        ],
        script_patterns=[
            r'/@vite/client',
        ]
    ),
]
