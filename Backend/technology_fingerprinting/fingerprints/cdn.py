import re
from .rules import TechnologyRule

CDN_RULES = [
    TechnologyRule(
        technology="Cloudflare",
        category="cdn",
        website="https://www.cloudflare.com",
        description="Global content delivery network, cloud cybersecurity, and DDoS mitigation services.",
        headers={
            "cf-ray": r".*",
            "cf-cache-status": r".*",
            "cf-request-id": r".*",
            "server": r"cloudflare",
            "expect-ct": r".*cloudflare.*",
        },
        cookies=["__cf_bm", "__cfduid", "cf_clearance"],
        script_patterns=[
            r'challenges\.cloudflare\.com/turnstile',
            r'static\.cloudflareinsights\.com/beacon\.min\.js',
        ]
    ),
    TechnologyRule(
        technology="Amazon CloudFront",
        category="cdn",
        website="https://aws.amazon.com/cloudfront",
        description="Content delivery network (CDN) service built for high performance and security by AWS.",
        headers={
            "x-amz-cf-id": r".*",
            "x-amz-cf-pop": r".*",
            "via": r".*cloudfront\.net.*",
            "x-cache": r".*(?:Hit|Miss) from cloudfront.*",
        }
    ),
    TechnologyRule(
        technology="Vercel",
        category="hosting",
        website="https://vercel.com",
        description="Cloud platform for frontend developers, providing static hosting and Serverless Functions.",
        headers={
            "x-vercel-id": r".*",
            "x-vercel-cache": r".*",
            "server": r"Vercel",
        }
    ),
    TechnologyRule(
        technology="Netlify",
        category="hosting",
        website="https://www.netlify.com",
        description="Remote-first cloud development platform for web applications and dynamic sites.",
        headers={
            "x-nf-request-id": r".*",
            "server": r"Netlify",
        }
    ),
    TechnologyRule(
        technology="Akamai",
        category="cdn",
        website="https://www.akamai.com",
        description="Global content delivery network (CDN), cybersecurity, and cloud service provider.",
        headers={
            "x-akamai-transformed": r".*",
            "x-akamai-request-id": r".*",
            "x-akamai-session-info": r".*",
            "server": r"AkamaiNetStorage|AkamaiGHost",
        }
    ),
    TechnologyRule(
        technology="Fastly",
        category="cdn",
        website="https://www.fastly.com",
        description="Cloud computing services provider operating an edge cloud platform.",
        headers={
            "x-fastly-request-id": r".*",
            "x-served-by": r".*cache-[a-z0-9]+-[A-Z]+.*",
            "via": r".*varnish.*",
        }
    ),
    TechnologyRule(
        technology="AWS S3",
        category="hosting",
        website="https://aws.amazon.com/s3",
        description="Object storage service offering industry-leading scalability and data availability.",
        headers={
            "x-amz-bucket-region": r".*",
            "x-amz-request-id": r".*",
            "server": r"AmazonS3",
        }
    ),
    TechnologyRule(
        technology="GitHub Pages",
        category="hosting",
        website="https://pages.github.com",
        description="Static site hosting service designed to host your pages directly from a GitHub repo.",
        headers={
            "x-github-request-id": r".*",
            "server": r"GitHub\.com",
        }
    ),
]
