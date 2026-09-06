import re
from .rules import TechnologyRule

FRONTEND_RULES = [
    TechnologyRule(
        technology="React",
        category="frontend",
        website="https://react.dev",
        description="Declarative, component-based JavaScript library for building user interfaces.",
        html_patterns=[
            r'data-reactroot',
            r'data-reactid',
            r'_reactListening',
            r'__reactFiber',
            r'react-root',
            r'<div id=["\']root["\']',
            r'<div id=["\']__next["\']',
            r'window\.__INITIAL_STATE__',
            r'window\.__PRELOADED_STATE__',
        ],
        script_patterns=[
            r'react(?:\.production|\.development)?(?:\.min)?\.js',
            r'react-dom(?:\.production|\.development)?(?:\.min)?\.js',
            r'static/js/bundle\.js',
            r'static/js/main\.[a-f0-9]+\.js',
            r'assets/index-[a-zA-Z0-9_-]+\.js',
        ],
        js_content_patterns=[
            r'React\.createElement',
            r'__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED',
            r'react\.production\.min\.js',
            r'useLayoutEffect',
            r'createRoot\(',
            r'react/jsx-runtime',
            r'_reactInternals',
            r'/*!\s*React\s+v?([0-9\.]+)',
        ],
        version_regexes=[
            re.compile(r'React\s+v?([0-9\.]+)', re.IGNORECASE),
            re.compile(r'react@([0-9\.]+)', re.IGNORECASE)
        ]
    ),
    TechnologyRule(
        technology="Next.js",
        category="frontend",
        website="https://nextjs.org",
        description="The React Framework for full-stack web applications with SSR, SSG, and Server Components.",
        headers={
            "x-powered-by": r"Next\.js(?:/([0-9\.]+))?",
        },
        html_patterns=[
            r'<div id=["\']__next["\']',
            r'id=["\']__NEXT_DATA__["\']',
            r'/_next/static/',
            r'next-head-count',
            r'self\.__next_f',
        ],
        script_patterns=[
            r'/_next/static/chunks/',
            r'/_next/static/webpack/',
            r'/_next/static/[a-zA-Z0-9_-]+/_buildManifest\.js',
        ],
        js_content_patterns=[
            r'__NEXT_DATA__',
            r'__next_f\.push',
            r'_N_E\s*=',
            r'self\.__next_s',
        ],
        url_patterns=[
            r"^/_next/static/",
            r"^/_next/data/",
        ],
        version_regexes=[
            re.compile(r"Next\.js/([0-9\.]+)", re.IGNORECASE)
        ]
    ),
    TechnologyRule(
        technology="Remix",
        category="frontend",
        website="https://remix.run",
        description="Full stack web framework focused on web standards and modern React architecture.",
        html_patterns=[
            r'window\.__remixContext',
            r'<script[^>]*>window\.__remixManifest',
        ],
        js_content_patterns=[
            r'window\.__remixContext',
            r'@remix-run/react',
        ]
    ),
    TechnologyRule(
        technology="Vue.js",
        category="frontend",
        website="https://vuejs.org",
        description="Progressive framework for building user interfaces based on standard HTML, CSS, and JavaScript.",
        html_patterns=[
            r'data-v-[a-f0-9]{8}',
            r'id=["\']app["\']\s+data-server-rendered',
            r'__vue__',
            r'<div id=["\']app["\']',
        ],
        script_patterns=[
            r'vue(?:\.runtime)?(?:\.esm-bundler)?(?:\.min)?\.js',
            r'/vue@[0-9\.]+',
        ],
        js_content_patterns=[
            r'__VUE_HMR_RUNTIME__',
            r'__VUE__',
            r'Vue\.component',
            r'createVNode|defineComponent|createApp\(',
            r'/*!\s*Vue\.js\s+v?([0-9\.]+)',
        ],
        version_regexes=[
            re.compile(r'Vue\.js\s+v?([0-9\.]+)', re.IGNORECASE),
            re.compile(r'vue@([0-9\.]+)', re.IGNORECASE)
        ]
    ),
    TechnologyRule(
        technology="Nuxt",
        category="frontend",
        website="https://nuxt.com",
        description="The Intuitive Vue Framework for full-stack web development.",
        html_patterns=[
            r'<div id=["\']__nuxt["\']',
            r'id=["\']__NUXT_DATA__["\']',
            r'/_nuxt/',
        ],
        script_patterns=[
            r'/_nuxt/',
        ],
        js_content_patterns=[
            r'window\.__NUXT__',
            r'useNuxtApp',
        ],
        url_patterns=[
            r"^/_nuxt/",
        ]
    ),
    TechnologyRule(
        technology="Angular",
        category="frontend",
        website="https://angular.dev",
        description="Component-based web application framework developed by Google.",
        html_patterns=[
            r'ng-version=["\']([0-9\.]+)["\']',
            r'ng-app=',
            r'<app-root',
            r'_nghost-',
            r'_ngcontent-',
        ],
        script_patterns=[
            r'angular(?:\.min)?\.js',
            r'main\.[a-f0-9]+\.js',
            r'polyfills\.[a-f0-9]+\.js',
            r'runtime\.[a-f0-9]+\.js',
        ],
        js_content_patterns=[
            r'@angular/core',
            r'ngDevMode',
            r'ɵɵdefineComponent',
            r'ɵɵelementStart',
        ],
        version_regexes=[
            re.compile(r'ng-version=["\']([0-9\.]+)["\']', re.IGNORECASE),
            re.compile(r'Angular\s+v?([0-9\.]+)', re.IGNORECASE)
        ]
    ),
    TechnologyRule(
        technology="Svelte",
        category="frontend",
        website="https://svelte.dev",
        description="Component framework that compiles down to tiny, framework-less vanilla JavaScript.",
        html_patterns=[
            r'class=["\']svelte-[a-z0-9]+["\']',
            r'__sveltekit',
        ],
        script_patterns=[
            r'_app/immutable/',
        ],
        js_content_patterns=[
            r'SvelteComponent',
            r'detach_dev|insert_dev|mount_component',
            r'__svelte__',
        ]
    ),
    TechnologyRule(
        technology="Astro",
        category="frontend",
        website="https://astro.build",
        description="Web framework designed for content-driven websites with zero JS by default.",
        html_patterns=[
            r'astro-island',
            r'data-astro-cid-',
        ],
        meta_tags={
            "generator": r"Astro(?:\s+v?([0-9\.]+))?",
        },
        version_regexes=[
            re.compile(r"Astro\s+v?([0-9\.]+)", re.IGNORECASE)
        ]
    ),
    TechnologyRule(
        technology="jQuery",
        category="javascript",
        website="https://jquery.com",
        description="Fast, small, and feature-rich JavaScript utility library.",
        html_patterns=[
            r'jquery(?:-([0-9\.]+))?(?:\.min)?\.js',
        ],
        script_patterns=[
            r'jquery(?:-([0-9\.]+))?(?:\.slim)?(?:\.min)?\.js',
            r'/jquery/([0-9\.]+)/jquery',
            r'code\.jquery\.com/jquery-([0-9\.]+)',
        ],
        js_content_patterns=[
            r'/\*! jQuery v([0-9\.]+)',
            r'jQuery\.fn\.jquery',
            r'window\.jQuery',
        ],
        version_regexes=[
            re.compile(r'jQuery\s+v([0-9\.]+)', re.IGNORECASE),
            re.compile(r'jquery[/-]([0-9\.]+)(?:\.slim)?(?:\.min)?\.js', re.IGNORECASE),
            re.compile(r'/jquery/([0-9\.]+)/', re.IGNORECASE)
        ]
    ),
    TechnologyRule(
        technology="Alpine.js",
        category="frontend",
        website="https://alpinejs.dev",
        description="Rugged, minimal tool for composing behavior directly in your HTML markup.",
        html_patterns=[
            r'x-data=',
            r'x-show=',
            r'x-bind:',
            r'x-on:',
        ],
        script_patterns=[
            r'alpine(?:\.min)?\.js',
            r'cdn\.jsdelivr\.net/npm/alpinejs@([0-9\.]+)',
        ],
        js_content_patterns=[
            r'Alpine\.data',
            r'window\.Alpine',
        ],
        version_regexes=[
            re.compile(r'alpinejs@([0-9\.]+)', re.IGNORECASE)
        ]
    ),
]
