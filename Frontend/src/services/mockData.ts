import { Project, Asset, Scan, Finding, Report, HttpInteraction, AuditLog } from './types';

export const mockProjects: Project[] = [
  {
    id: 'p1',
    name: 'Corporate Infrastructure',
    description: 'Internal & external network perimeter testing and asset discovery.',
    createdAt: '2026-06-10T10:00:00Z',
    status: 'active',
    targetCount: 5,
    findingCount: { critical: 2, high: 4, medium: 12, low: 18, info: 45 },
    scanCount: 14,
    targets: ['corp.attacklens.internal', '192.168.10.0/24', 'vpn.attacklens.com']
  },
  {
    id: 'p2',
    name: 'External Web Assets',
    description: 'Continuous monitoring and web application vulnerability assessment.',
    createdAt: '2026-07-01T08:30:00Z',
    status: 'active',
    targetCount: 4,
    findingCount: { critical: 1, high: 5, medium: 8, low: 10, info: 22 },
    scanCount: 8,
    targets: ['attacklens.com', 'api.attacklens.com', 'portal.attacklens.com']
  },
  {
    id: 'p3',
    name: 'Mobile API Assessment',
    description: 'Security evaluation of REST and GraphQL endpoints used by iOS/Android client.',
    createdAt: '2026-07-15T14:00:00Z',
    status: 'completed',
    targetCount: 2,
    findingCount: { critical: 0, high: 2, medium: 3, low: 7, info: 15 },
    scanCount: 4,
    targets: ['api.attacklens.com/v2', 'graphql.attacklens.com']
  },
  {
    id: 'p4',
    name: 'Core Platform Source Code',
    description: 'Static application security testing (SAST) and software composition analysis (SCA) on Git repos.',
    createdAt: '2026-08-01T09:00:00Z',
    status: 'active',
    targetCount: 3,
    findingCount: { critical: 3, high: 1, medium: 5, low: 14, info: 38 },
    scanCount: 12,
    targets: ['github.com/attacklens/core-api', 'github.com/attacklens/auth-service']
  }
];

export const mockAssets: Asset[] = [
  {
    id: 'a1',
    projectId: 'p1',
    type: 'domain',
    name: 'corp.attacklens.internal',
    ipAddress: '192.168.10.15',
    ports: [22, 80, 443, 8080],
    services: ['SSH', 'HTTP', 'HTTPS', 'HTTP-Proxy'],
    technologies: ['Apache httpd 2.4.41', 'OpenSSH 8.2p1', 'Ubuntu Linux'],
    vulnCount: 4,
    status: 'warning',
    lastScanned: '2026-08-14T22:00:00Z'
  },
  {
    id: 'a2',
    projectId: 'p1',
    type: 'ip',
    name: '192.168.10.50',
    ipAddress: '192.168.10.50',
    ports: [5432, 6379],
    services: ['PostgreSQL', 'Redis'],
    technologies: ['PostgreSQL 13.4', 'Redis key-value store 6.0.9'],
    vulnCount: 1,
    status: 'safe',
    lastScanned: '2026-08-13T18:30:00Z'
  },
  {
    id: 'a3',
    projectId: 'p1',
    type: 'subdomain',
    name: 'vpn.attacklens.com',
    ipAddress: '203.0.113.88',
    ports: [443, 1194],
    services: ['HTTPS', 'OpenVPN'],
    technologies: ['OpenSSL', 'Fortinet VPN'],
    vulnCount: 3,
    status: 'compromised',
    lastScanned: '2026-08-15T09:15:00Z'
  },
  {
    id: 'a4',
    projectId: 'p2',
    type: 'domain',
    name: 'attacklens.com',
    ipAddress: '104.21.45.19',
    ports: [80, 443],
    services: ['HTTP', 'HTTPS'],
    technologies: ['Cloudflare WAF', 'React', 'Next.js', 'TailwindCSS'],
    vulnCount: 0,
    status: 'safe',
    lastScanned: '2026-08-15T11:00:00Z'
  },
  {
    id: 'a5',
    projectId: 'p2',
    type: 'subdomain',
    name: 'api.attacklens.com',
    ipAddress: '104.21.45.20',
    ports: [443, 3000],
    services: ['HTTPS', 'Node.js/Express'],
    technologies: ['Express', 'Node.js v18.16.0', 'Sequelize ORM', 'PostgreSQL'],
    vulnCount: 8,
    status: 'compromised',
    lastScanned: '2026-08-15T12:30:00Z'
  },
  {
    id: 'a6',
    projectId: 'p2',
    type: 'subdomain',
    name: 'portal.attacklens.com',
    ipAddress: '104.21.45.21',
    ports: [443],
    services: ['HTTPS'],
    technologies: ['Angular', 'Nginx 1.18.0'],
    vulnCount: 2,
    status: 'warning',
    lastScanned: '2026-08-14T07:45:00Z'
  },
  {
    id: 'a7',
    projectId: 'p4',
    type: 'host',
    name: 'github.com/attacklens/core-api',
    ports: [],
    services: [],
    technologies: ['TypeScript', 'Node.js', 'JWT', 'NPM packages'],
    vulnCount: 12,
    status: 'compromised',
    lastScanned: '2026-08-15T21:40:00Z'
  }
];

export const mockScans: Scan[] = [
  {
    id: 's1',
    projectId: 'p1',
    name: 'Internal Asset Discovery',
    status: 'completed',
    type: 'recon',
    target: '192.168.10.0/24',
    startTime: '2026-08-14T06:00:00Z',
    duration: '14m 22s',
    progress: 100,
    findingsCount: { critical: 0, high: 1, medium: 4, low: 12, info: 32 }
  },
  {
    id: 's2',
    projectId: 'p1',
    name: 'VPN Gateway Penetration Test',
    status: 'completed',
    type: 'network',
    target: 'vpn.attacklens.com',
    startTime: '2026-08-15T08:00:00Z',
    duration: '45m 10s',
    progress: 100,
    findingsCount: { critical: 2, high: 3, medium: 2, low: 4, info: 8 }
  },
  {
    id: 's3',
    projectId: 'p2',
    name: 'API Vulnerability Audit',
    status: 'running',
    type: 'api',
    target: 'api.attacklens.com',
    startTime: '2026-08-15T22:30:00Z',
    progress: 68,
    findingsCount: { critical: 1, high: 4, medium: 3, low: 5, info: 10 },
    currentPhase: 'Fuzzing endpoint parameters',
    logs: [
      '[22:30:00] Initializing API assessment engine.',
      '[22:30:15] Loading OpenAPI schema from https://api.attacklens.com/swagger.json.',
      '[22:30:34] Parsing schema: 24 paths, 56 operations detected.',
      '[22:31:02] Completed passive endpoint analysis.',
      '[22:32:15] Starting authenticated fuzzing tests on /v1/user.',
      '[22:33:04] Found: SQL Injection on /v1/user?id= (Severity: Critical).',
      '[22:34:12] Beginning authentication bypass testing on /v1/admin.'
    ]
  },
  {
    id: 's4',
    projectId: 'p4',
    name: 'SAST Main Branch Security Check',
    status: 'completed',
    type: 'code',
    target: 'github.com/attacklens/core-api',
    startTime: '2026-08-15T21:30:00Z',
    duration: '8m 15s',
    progress: 100,
    findingsCount: { critical: 3, high: 1, medium: 5, low: 14, info: 38 }
  },
  {
    id: 's5',
    projectId: 'p2',
    name: 'Web Front-End Passive Crawler',
    status: 'queued',
    type: 'web',
    target: 'attacklens.com',
    startTime: 'Pending',
    progress: 0,
    findingsCount: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  }
];

export const mockFindings: Finding[] = [
  {
    id: 'f1',
    projectId: 'p2',
    assetId: 'a5',
    title: 'SQL Injection in User Query Handler',
    severity: 'critical',
    cvss: 9.8,
    cwe: 'CWE-89',
    status: 'open',
    affectedAsset: 'https://api.attacklens.com/v1/users',
    description: 'The API endpoint allows an unauthenticated user to inject arbitrary SQL commands via the `search` parameter. This occurs due to direct string concatenation of input data into the SQL query without proper parameterized inputs.',
    impact: 'An attacker can read, modify, and delete the entire database. Depending on database permissions, the attacker may also execute system commands on the host OS.',
    remediation: 'Implement parameterized SQL queries / prepared statements using ORM (e.g. Sequelize) or manual binding. Ensure all user input is sanitized and validated.',
    evidence: 'Payload: `\' UNION SELECT username, password_hash, email FROM users--` successfully bypassed authentication and returned sensitive customer records.',
    request: `POST /v1/users/search HTTP/1.1\nHost: api.attacklens.com\nContent-Type: application/json\nContent-Length: 72\n\n{\n  "query": "admin' UNION SELECT username, password_hash, email FROM users--"\n}`,
    response: `HTTP/1.1 200 OK\nContent-Type: application/json\nContent-Length: 284\n\n[\n  {\n    "username": "admin",\n    "password_hash": "$2b$12$N9qo8uLOiGC3THlRux4Vfuxf4W20W/L0OaY6sN.tK.B21W...",\n    "email": "security@attacklens.com"\n  }\n]`,
    references: [
      'https://owasp.org/www-community/attacks/SQL_Injection',
      'https://cwe.mitre.org/data/definitions/89.html'
    ],
    detectedTime: '2026-08-15T22:33:04Z'
  },
  {
    id: 'f2',
    projectId: 'p2',
    assetId: 'a5',
    title: 'Cross-Site Scripting (XSS) on API Error Response',
    severity: 'high',
    cvss: 7.5,
    cwe: 'CWE-79',
    status: 'confirmed',
    affectedAsset: 'https://api.attacklens.com/v1/error',
    description: 'The API mirrors back the value of the `msg` query parameter without proper HTML encoding or JSON serialization encoding, leading to HTML injection and cross-site scripting when rendered in a client browser.',
    impact: 'Execution of malicious JavaScript code in the context of the user’s session, enabling session hijacking, cookie theft, and defacement.',
    remediation: 'Ensure that all API responses strictly return `application/json` content-type, and filter/encode any mirrored strings before echoing them to the client.',
    evidence: 'URL: `https://api.attacklens.com/v1/error?msg=<script>alert(document.cookie)</script>`\nReturned HTML-formatted script tags executed in user session.',
    request: `GET /v1/error?msg=%3Cscript%3Ealert(document.cookie)%3C/script%3E HTTP/1.1\nHost: api.attacklens.com\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)`,
    response: `HTTP/1.1 200 OK\nContent-Type: text/html\nContent-Length: 104\n\n<html><body>Error description: <script>alert(document.cookie)</script></body></html>`,
    references: [
      'https://owasp.org/www-community/attacks/xss/',
      'https://cwe.mitre.org/data/definitions/79.html'
    ],
    detectedTime: '2026-08-15T20:10:00Z'
  },
  {
    id: 'f3',
    projectId: 'p1',
    assetId: 'a3',
    title: 'Fortinet VPN SSL Gateway Buffer Overflow (FortiGate RCE)',
    severity: 'critical',
    cvss: 9.8,
    cwe: 'CWE-121',
    status: 'open',
    affectedAsset: 'vpn.attacklens.com (FortiOS Gateway)',
    description: 'A stack-based buffer overflow vulnerability in FortiOS SSL VPN daemon may allow a remote unauthenticated attacker to execute arbitrary code or commands via specifically crafted HTTP requests.',
    impact: 'Complete system compromise of the VPN gateway, allowing network pivot and full access to internal subnets.',
    remediation: 'Upgrade FortiOS to version 7.2.5 or above. Immediately disable SSL VPN if patching is delayed, and implement multi-factor authentication on all login endpoints.',
    evidence: 'Version fingerprint: FortiOS v7.2.1 detected, which is vulnerable to CVE-2023-27997.',
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2023-27997',
      'https://www.fortiguard.com/psirt/FG-IR-23-097'
    ],
    detectedTime: '2026-08-15T09:20:00Z'
  },
  {
    id: 'f4',
    projectId: 'p4',
    assetId: 'a7',
    title: 'Hardcoded AWS Credentials in Config File',
    severity: 'critical',
    cvss: 9.1,
    cwe: 'CWE-798',
    status: 'open',
    affectedAsset: 'github.com/attacklens/core-api:src/config/aws.ts',
    description: 'Static scanning detected AWS Access Key ID and Secret Access Key stored in plain text inside the configuration files of the core-api repository.',
    impact: 'Attackers who gain access to the repository can compromise AWS resources, including databases, S3 buckets, and EC2 instances, leading to massive data exposure.',
    remediation: 'Revoke the AWS access keys immediately in the AWS IAM Console. Migrate configuration to AWS Secrets Manager or use environment variables loaded through system configurations.',
    references: [
      'https://cwe.mitre.org/data/definitions/798.html'
    ],
    detectedTime: '2026-08-15T21:38:00Z',
    codeContext: {
      file: 'src/config/aws.ts',
      lineNumber: 12,
      code: '  secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",',
      preLines: [
        'import AWS from "aws-sdk";',
        '',
        'export const awsConfig = {',
        '  region: "us-east-1",',
        '  accessKeyId: "AKIAIOSFODNN7EXAMPLE",',
      ],
      postLines: [
        '  sessionToken: process.env.AWS_SESSION_TOKEN || ""',
        '};',
        '',
        'AWS.config.update(awsConfig);'
      ]
    }
  },
  {
    id: 'f5',
    projectId: 'p4',
    assetId: 'a7',
    title: 'Insecure JWT Signature Verification (None Algorithm Allowed)',
    severity: 'high',
    cvss: 8.1,
    cwe: 'CWE-347',
    status: 'confirmed',
    affectedAsset: 'github.com/attacklens/core-api:src/middleware/auth.ts',
    description: 'The JWT verification middleware accepts tokens signed with the "none" algorithm. An attacker can craft a JWT with a modified payload (e.g. setting isAdmin: true) and sign it using "none", bypassing user authentication.',
    impact: 'Authentication bypass and privilege escalation to Administrator.',
    remediation: 'Explicitly specify the allowed algorithms (e.g. HS256, RS256) when calling jwt.verify() and ensure tokens with "none" are rejected.',
    references: [
      'https://cwe.mitre.org/data/definitions/347.html'
    ],
    detectedTime: '2026-08-15T21:35:00Z',
    codeContext: {
      file: 'src/middleware/auth.ts',
      lineNumber: 18,
      code: '    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ["HS256", "none"] }) as any;',
      preLines: [
        'import jwt from "jsonwebtoken";',
        'const JWT_SECRET = process.env.JWT_SECRET || "default_dev_secret";',
        '',
        'export const authMiddleware = (req: any, res: any, next: any) => {',
        '    const authHeader = req.headers["authorization"];',
        '    const token = authHeader && authHeader.split(" ")[1];',
        '    if (!token) return res.sendStatus(401);',
      ],
      postLines: [
        '    req.user = decoded;',
        '    next();',
        '};'
      ]
    }
  },
  {
    id: 'f6',
    projectId: 'p1',
    assetId: 'a1',
    title: 'Outdated OpenSSH Vulnerable to Terrapin Attack',
    severity: 'medium',
    cvss: 5.9,
    cwe: 'CWE-310',
    status: 'accepted_risk',
    affectedAsset: 'corp.attacklens.internal:22',
    description: 'The SSH server is running OpenSSH version 8.2p1, which is vulnerable to the Terrapin Attack (CVE-2023-48795). This allows an attacker in a Man-in-the-Middle position to downgrade SSH channel security options.',
    impact: 'Man-in-the-Middle traffic interception or encryption algorithm downgrades.',
    remediation: 'Update OpenSSH server package to 9.6p1 or newer, or disable ChaCha20-Poly1305 and encrypt-then-mac MAC algorithms in sshd_config.',
    references: [
      'https://terrapin-attack.com/',
      'https://nvd.nist.gov/vuln/detail/CVE-2023-48795'
    ],
    detectedTime: '2026-08-14T22:04:00Z'
  }
];

export const mockReports: Report[] = [
  {
    id: 'r1',
    projectId: 'p1',
    name: 'Executive Penetration Summary - Corporate Q2',
    type: 'executive',
    format: 'pdf',
    generatedAt: '2026-07-20T12:00:00Z',
    status: 'ready',
    size: '1.2 MB'
  },
  {
    id: 'r2',
    projectId: 'p1',
    name: 'Detailed Network Perimeter Audit',
    type: 'network',
    format: 'html',
    generatedAt: '2026-08-14T10:00:00Z',
    status: 'ready',
    size: '840 KB'
  },
  {
    id: 'r3',
    projectId: 'p2',
    name: 'Web Application and API Scanning Report',
    type: 'web',
    format: 'pdf',
    generatedAt: '2026-08-15T15:30:00Z',
    status: 'ready',
    size: '2.4 MB'
  },
  {
    id: 'r4',
    projectId: 'p4',
    name: 'SAST Source Code Security Review',
    type: 'code',
    format: 'csv',
    generatedAt: '2026-08-15T22:00:00Z',
    status: 'generating'
  }
];

export const mockHttpHistory: HttpInteraction[] = [
  {
    id: 'h1',
    timestamp: '2026-08-15T22:45:01Z',
    method: 'GET',
    url: 'https://api.attacklens.com/v1/users?search=admin',
    status: 200,
    duration: 124,
    size: 450,
    requestHeaders: [
      { key: 'Host', value: 'api.attacklens.com' },
      { key: 'Authorization', value: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...' },
      { key: 'User-Agent', value: 'Mozilla/5.0' }
    ],
    responseHeaders: [
      { key: 'Content-Type', value: 'application/json' },
      { key: 'Server', value: 'nginx/1.18.0' },
      { key: 'X-Rate-Limit', value: '99/100' }
    ],
    responseBody: '[\n  {\n    "id": 1,\n    "username": "admin",\n    "email": "admin@attacklens.com",\n    "role": "SuperAdmin"\n  }\n]'
  },
  {
    id: 'h2',
    timestamp: '2026-08-15T22:45:15Z',
    method: 'POST',
    url: 'https://api.attacklens.com/v1/auth/login',
    status: 401,
    duration: 310,
    size: 85,
    requestHeaders: [
      { key: 'Host', value: 'api.attacklens.com' },
      { key: 'Content-Type', value: 'application/json' }
    ],
    requestBody: '{\n  "username": "tester",\n  "password": "wrong_password"\n}',
    responseHeaders: [
      { key: 'Content-Type', value: 'application/json' },
      { key: 'X-Frame-Options', value: 'DENY' }
    ],
    responseBody: '{\n  "error": "Unauthorized",\n  "message": "Invalid credentials provided."\n}'
  },
  {
    id: 'h3',
    timestamp: '2026-08-15T22:46:02Z',
    method: 'PUT',
    url: 'https://api.attacklens.com/v1/profile/update',
    status: 403,
    duration: 95,
    size: 60,
    requestHeaders: [
      { key: 'Host', value: 'api.attacklens.com' },
      { key: 'Content-Type', value: 'application/json' },
      { key: 'Authorization', value: 'Bearer expired_token' }
    ],
    requestBody: '{\n  "displayName": "New Name"\n}',
    responseHeaders: [
      { key: 'Content-Type', value: 'application/json' }
    ],
    responseBody: '{\n  "code": 403,\n  "status": "Forbidden",\n  "message": "Token has expired."\n}'
  },
  {
    id: 'h4',
    timestamp: '2026-08-15T22:47:05Z',
    method: 'GET',
    url: 'https://api.attacklens.com/v1/admin/dashboard',
    status: 404,
    duration: 82,
    size: 142,
    requestHeaders: [
      { key: 'Host', value: 'api.attacklens.com' }
    ],
    responseHeaders: [
      { key: 'Content-Type', value: 'text/html' }
    ],
    responseBody: '<html>\n  <head><title>404 Not Found</title></head>\n  <body>\n    <center><h1>404 Not Found</h1></center>\n  </body>\n</html>'
  }
];

export const mockAuditLogs: AuditLog[] = [
  {
    id: 'l1',
    timestamp: '2026-08-15T22:00:00Z',
    user: 'security-engineer@attacklens.com',
    action: 'Scan Started',
    details: 'Initiated API Vulnerability Audit scan on target api.attacklens.com.',
    ipAddress: '198.51.100.12'
  },
  {
    id: 'l2',
    timestamp: '2026-08-15T21:30:00Z',
    user: 'system-agent',
    action: 'SAST Finished',
    details: 'SAST Security check completed for github.com/attacklens/core-api. 4 findings discovered.',
    ipAddress: '127.0.0.1'
  },
  {
    id: 'l3',
    timestamp: '2026-08-15T18:45:00Z',
    user: 'admin@attacklens.com',
    action: 'Project Created',
    details: 'Created project "Core Platform Source Code" and assigned targets.',
    ipAddress: '198.51.100.10'
  },
  {
    id: 'l4',
    timestamp: '2026-08-15T15:20:00Z',
    user: 'security-engineer@attacklens.com',
    action: 'Finding Status Updated',
    details: 'Marked vulnerability "Outdated OpenSSH Vulnerable to Terrapin Attack" as Accepted Risk.',
    ipAddress: '198.51.100.12'
  }
];
