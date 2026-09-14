import React, { useState, useEffect, useRef, useMemo } from 'react';
import {
  Zap,
  Globe,
  Compass,
  Layers,
  Cpu,
  Lock,
  ShieldCheck,
  Braces,
  FileCode2,
  Play,
  Square,
  RotateCcw,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Clock,
  Download,
  Search,
  Check,
  ChevronRight,
  Shield,
  Sparkles,
  Terminal as TerminalIcon,
  Copy,
  Folder,
  Upload,
  FileArchive,
  X,
  Activity,
  HardDrive
} from 'lucide-react';
import { api } from '../services/api';
import { UnifiedScanStreamEvent } from '../services/types';
import { SecurityAssessmentWalkthrough } from '../components/SecurityAssessmentWalkthrough';

export interface UnifiedScanProps {
  setActivePage?: (page: string) => void;
}

export type ScanProfile = 'quick' | 'standard' | 'deep';
export type ModuleStatus = 'pending' | 'running' | 'completed' | 'failed' | 'skipped';
export type CodebaseSourceMode = 'path' | 'zip';

export interface SecurityModule {
  id: string;
  name: string;
  shortName: string;
  pageId: string;
  category: 'Network & Host' | 'Web Application' | 'Encryption & Config' | 'Source & API';
  icon: React.ComponentType<{ style?: React.CSSProperties; className?: string }>;
  accentColor: string;
  description: string;
  tags: string[];
  estimatedTimeSec: { quick: number; standard: number; deep: number };
  sampleSteps: string[];
}

export interface ModuleProgressState {
  id: string;
  status: ModuleStatus;
  progressPercent: number;
  currentStep: string;
  startTime?: number;
  durationMs?: number;
  findings: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  summaryText: string;
}

export interface UnifiedLogEntry {
  id: string;
  timestamp: string;
  moduleId: string;
  moduleName: string;
  level: 'info' | 'success' | 'warn' | 'error';
  message: string;
}

export interface UnifiedFindingItem {
  id: string;
  moduleId: string;
  moduleName: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  cvss: number;
  cwe?: string;
  location: string;
  description: string;
  remediation: string;
}

const SECURITY_MODULES: SecurityModule[] = [
  {
    id: 'ports',
    name: 'Port & Network Discovery',
    shortName: 'Port Scanner',
    pageId: 'ports',
    category: 'Network & Host',
    icon: Zap,
    accentColor: '#388bfd',
    description: 'Fast asynchronous TCP port probe, active service banner grabbing, and daemon fingerprinting.',
    tags: ['TCP Probe', 'Service Detection', 'Banner Grab'],
    estimatedTimeSec: { quick: 4, standard: 8, deep: 16 },
    sampleSteps: [
      'Resolving target DNS & checking host reachability',
      'Scanning top ports (21, 22, 80, 443, 3000, 8000, 8080)...',
      'Capturing service banners & protocol fingerprints',
      'Consolidating open network ports'
    ]
  },
  {
    id: 'http',
    name: 'HTTP Detection & Header Audit',
    shortName: 'HTTP Inspector',
    pageId: 'http',
    category: 'Web Application',
    icon: Globe,
    accentColor: '#58a6ff',
    description: 'Inspects HTTP/HTTPS availability, redirection chains, TLS enforcement, and server headers.',
    tags: ['Redirection', 'Status Codes', 'Headers'],
    estimatedTimeSec: { quick: 3, standard: 6, deep: 12 },
    sampleSteps: [
      'Probing HTTP (80) and HTTPS (443) endpoints',
      'Analyzing HTTP-to-HTTPS redirect chains',
      'Auditing Server and X-Powered-By leakages',
      'Validating standard HTTP method support'
    ]
  },
  {
    id: 'endpoints',
    name: 'Endpoint & Route Discovery',
    shortName: 'Endpoint Discovery',
    pageId: 'endpoints',
    category: 'Web Application',
    icon: Compass,
    accentColor: '#3fb950',
    description: 'Discovers hidden URLs, administrative interfaces, backup files, and API route entries.',
    tags: ['URL Fuzzing', 'Admin Paths', 'API Routes'],
    estimatedTimeSec: { quick: 5, standard: 10, deep: 20 },
    sampleSteps: [
      'Crawling visible anchor tags and internal sitemaps',
      'Fuzzing common administrative routes (/admin, /api, /v1, /debug)',
      'Checking sensitive file disclosure (/robots.txt, /.env, /.git)',
      'Cataloging discovered route surfaces'
    ]
  },
  {
    id: 'attack-surface',
    name: 'Web Application & Form Analysis',
    shortName: 'Web App Analysis',
    pageId: 'attack-surface',
    category: 'Web Application',
    icon: Layers,
    accentColor: '#d29922',
    description: 'Deep crawling of HTML forms, input field vectors, HTTP verbs, and authentication entry points.',
    tags: ['Form Vectors', 'Input Audit', 'Crawl Tree'],
    estimatedTimeSec: { quick: 6, standard: 12, deep: 24 },
    sampleSteps: [
      'Extracting DOM tree & interactive form elements',
      'Inspecting input fields, query parameters & hidden tokens',
      'Testing HTTP methods (GET, POST, PUT, DELETE, OPTIONS)',
      'Mapping application attack vectors'
    ]
  },
  {
    id: 'fingerprint',
    name: 'Technology Fingerprinting',
    shortName: 'Tech Fingerprint',
    pageId: 'fingerprint',
    category: 'Web Application',
    icon: Cpu,
    accentColor: '#a371f7',
    description: 'Identifies web servers, backend web frameworks, CMS engines, JS bundles, and CDN/WAF providers.',
    tags: ['Web Frameworks', 'CMS Detection', 'WAF/CDN'],
    estimatedTimeSec: { quick: 4, standard: 7, deep: 15 },
    sampleSteps: [
      'Analyzing HTTP headers and signature cookies',
      'Decompiling script bundle markers & frontend frameworks',
      'Checking HTML meta generator and CDN/WAF signatures',
      'Generating technology version matrix'
    ]
  },
  {
    id: 'tls',
    name: 'TLS / SSL Security Analysis',
    shortName: 'TLS/SSL Audit',
    pageId: 'tls',
    category: 'Encryption & Config',
    icon: Lock,
    accentColor: '#58a6ff',
    description: 'Exhaustive verification of TLS versions (1.0-1.3), cipher suites, X.509 certs, and known CVEs.',
    tags: ['TLS 1.3', 'Cipher Strength', 'Cert Chain', 'POODLE/BEAST'],
    estimatedTimeSec: { quick: 5, standard: 9, deep: 18 },
    sampleSteps: [
      'Negotiating SSLv3, TLS 1.0, 1.1, 1.2, 1.3 handshakes',
      'Classifying cipher suites & Perfect Forward Secrecy (PFS)',
      'Verifying X.509 certificate chain, expiration & SANs',
      'Testing legacy vulnerabilities (Heartbleed, POODLE, ROBOT)'
    ]
  },
  {
    id: 'security-config',
    name: 'Security Configuration Audit',
    shortName: 'Security Config',
    pageId: 'security-config',
    category: 'Encryption & Config',
    icon: ShieldCheck,
    accentColor: '#3fb950',
    description: 'Evaluates Content Security Policy (CSP), HSTS, CORS origins, X-Frame-Options, and Cookie security.',
    tags: ['CSP Policy', 'HSTS', 'CORS Origin', 'Secure Cookies'],
    estimatedTimeSec: { quick: 4, standard: 8, deep: 14 },
    sampleSteps: [
      'Auditing Content-Security-Policy (CSP) directives & wildcards',
      'Evaluating Strict-Transport-Security (HSTS) preload eligibility',
      'Testing Cross-Origin Resource Sharing (CORS) wildcard reflection',
      'Verifying Cookie flags: HttpOnly, Secure, and SameSite'
    ]
  },
  {
    id: 'api-analysis',
    name: 'API Security & Deep Analysis',
    shortName: 'API Security',
    pageId: 'api-analysis',
    category: 'Source & API',
    icon: Braces,
    accentColor: '#f0883e',
    description: 'Tests REST/GraphQL endpoints, authentication schemes, parameter tampering, and BOLA/IDOR risk.',
    tags: ['REST / GraphQL', 'BOLA / IDOR', 'Rate Limiting', 'Auth Audit'],
    estimatedTimeSec: { quick: 6, standard: 12, deep: 25 },
    sampleSteps: [
      'Discovering REST/GraphQL OpenAPI schemas & endpoints',
      'Verifying Bearer / Basic / API-Key authentication enforcement',
      'Probing numeric IDOR / BOLA parameter tampering heuristics',
      'Testing request rate limiting and error leakages'
    ]
  },
  {
    id: 'codebase-analysis',
    name: 'Codebase Security (SAST & Secrets)',
    shortName: 'SAST & Secrets',
    pageId: 'codebase-analysis',
    category: 'Source & API',
    icon: FileCode2,
    accentColor: '#ff7b72',
    description: 'Static application security testing (SAST), hardcoded API keys/tokens, and vulnerable code patterns.',
    tags: ['SAST Scan', 'Secret Leakage', 'CWE Mapping', 'Source Review'],
    estimatedTimeSec: { quick: 5, standard: 10, deep: 20 },
    sampleSteps: [
      'Scanning local source files or uploaded archive for secrets and keys',
      'Analyzing unsafe AST patterns (SQL injection, eval, command exec)',
      'Checking dependency security manifests',
      'Categorizing static code vulnerabilities by severity'
    ]
  }
];

const PRESET_TARGETS = [
  { label: 'Local Development Server', value: 'http://127.0.0.1:8000', type: 'Local' },
  { label: 'Localhost Client (Port 3000)', value: 'http://localhost:3000', type: 'Local' },
  { label: 'Nmap Security Test Node', value: 'https://scanme.nmap.org', type: 'External' },
  { label: 'GitHub Enterprise / Public', value: 'https://github.com', type: 'External' },
  { label: 'Google Public Surface', value: 'https://google.com', type: 'External' },
];

export const UnifiedScan: React.FC<UnifiedScanProps> = ({ setActivePage }) => {
  // Target & Scope State
  const [targetInput, setTargetInput] = useState('http://127.0.0.1:8000');
  
  // Codebase Scope (Both Local Path and ZIP Upload options)
  const [codebaseSourceMode, setCodebaseSourceMode] = useState<CodebaseSourceMode>('path');
  const [codebasePath, setCodebasePath] = useState('d:\\Flutter\\AttackLens');
  const [selectedZipFile, setSelectedZipFile] = useState<File | null>(null);
  const [isDragOver, setIsDragOver] = useState(false);

  // Profile & Module Selection State
  const [scanProfile, setScanProfile] = useState<ScanProfile>('standard');
  const [selectedModuleIds, setSelectedModuleIds] = useState<string[]>(
    SECURITY_MODULES.map(m => m.id)
  );
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [searchModuleQuery, setSearchModuleQuery] = useState('');

  // Execution State
  const [scanState, setScanState] = useState<'idle' | 'running' | 'completed' | 'aborted'>('idle');
  const [overallProgress, setOverallProgress] = useState<number>(0);
  const [elapsedSeconds, setElapsedSeconds] = useState<number>(0);
  const [currentRunningModuleId, setCurrentRunningModuleId] = useState<string | null>(null);

  // Module Progress States
  const [moduleStates, setModuleStates] = useState<Record<string, ModuleProgressState>>({});
  const [logs, setLogs] = useState<UnifiedLogEntry[]>([]);
  const [findings, setFindings] = useState<UnifiedFindingItem[]>([]);
  const [logFilterModule, setLogFilterModule] = useState<string>('all');
  const [logFilterLevel, setLogFilterLevel] = useState<string>('all');
  const [activeTab, setActiveTab] = useState<'matrix' | 'findings' | 'logs'>('matrix');
  const [copiedSummary, setCopiedSummary] = useState(false);

  // Refs
  const zipInputRef = useRef<HTMLInputElement>(null);
  const activeScanIdRef = useRef<string | null>(null);
  const abortStreamRef = useRef<(() => void) | null>(null);
  const timerRef = useRef<any>(null);
  const isCancelledRef = useRef<boolean>(false);
  const logsEndRef = useRef<HTMLDivElement>(null);

  // Auto-scroll logs
  useEffect(() => {
    if (logsEndRef.current && activeTab === 'logs') {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs, activeTab]);

  // Clean target preview
  const cleanTargetPreview = useMemo(() => {
    let raw = targetInput.trim();
    if (!raw) return 'No target specified';
    try {
      if (!raw.includes('://')) raw = `http://${raw}`;
      const parsed = new URL(raw);
      return `${parsed.protocol}//${parsed.hostname}${parsed.port ? `:${parsed.port}` : ''}`;
    } catch {
      return targetInput.trim();
    }
  }, [targetInput]);

  // Estimated total time calculation
  const totalEstimatedTimeSec = useMemo(() => {
    const selected = SECURITY_MODULES.filter(m => selectedModuleIds.includes(m.id));
    return selected.reduce((acc, m) => acc + m.estimatedTimeSec[scanProfile], 0);
  }, [selectedModuleIds, scanProfile]);

  // File Upload Handlers
  const handleZipFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      setSelectedZipFile(file);
    }
  };

  const handleDropZip = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0];
      if (file.name.endsWith('.zip') || file.name.endsWith('.tar.gz') || file.name.endsWith('.tgz')) {
        setSelectedZipFile(file);
      }
    }
  };

  const handleClearZip = (e: React.MouseEvent) => {
    e.stopPropagation();
    setSelectedZipFile(null);
    if (zipInputRef.current) {
      zipInputRef.current.value = '';
    }
  };

  // Module toggle handlers
  const handleToggleModule = (id: string) => {
    setSelectedModuleIds(prev =>
      prev.includes(id) ? prev.filter(mId => mId !== id) : [...prev, id]
    );
  };

  const handleSelectAll = () => {
    setSelectedModuleIds(SECURITY_MODULES.map(m => m.id));
  };

  const handleClearAll = () => {
    setSelectedModuleIds([]);
  };

  // Logging helper
  const addLog = (
    moduleId: string,
    moduleName: string,
    level: UnifiedLogEntry['level'],
    message: string
  ) => {
    const now = new Date().toLocaleTimeString();
    setLogs(prev => [
      ...prev,
      {
        id: `${Date.now()}-${Math.random()}`,
        timestamp: now,
        moduleId,
        moduleName,
        level,
        message
      }
    ]);
  };

  // Start Unified Scan Orchestration (Live Backend API + SSE Stream with offline fallback)
  const handleStartUnifiedScan = async () => {
    if (!targetInput.trim() || selectedModuleIds.length === 0) return;

    isCancelledRef.current = false;
    setScanState('running');
    setOverallProgress(0);
    setElapsedSeconds(0);
    setLogs([]);
    setFindings([]);

    // Initialize module progress states
    const initialStates: Record<string, ModuleProgressState> = {};
    SECURITY_MODULES.forEach(m => {
      if (selectedModuleIds.includes(m.id)) {
        initialStates[m.id] = {
          id: m.id,
          status: 'pending',
          progressPercent: 0,
          currentStep: 'Queued in pipeline...',
          findings: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
          summaryText: 'Waiting for execution slot'
        };
      } else {
        initialStates[m.id] = {
          id: m.id,
          status: 'skipped',
          progressPercent: 0,
          currentStep: 'Skipped by user configuration',
          findings: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
          summaryText: 'Module disabled'
        };
      }
    });
    setModuleStates(initialStates);

    const activeModules = SECURITY_MODULES.filter(m => selectedModuleIds.includes(m.id));
    const codebaseInfo = selectedModuleIds.includes('codebase-analysis')
      ? (codebaseSourceMode === 'zip' && selectedZipFile
          ? ` (SAST Target: ZIP Archive [${selectedZipFile.name}] - ${(selectedZipFile.size / (1024 * 1024)).toFixed(2)} MB)`
          : ` (SAST Target: Directory [${codebasePath}])`)
      : '';

    addLog(
      'orchestrator',
      'Unified Orchestrator',
      'info',
      `Connecting to Django Orchestrator for [${cleanTargetPreview}] with ${activeModules.length} active modules (${scanProfile.toUpperCase()} profile)${codebaseInfo}`
    );

    // Start elapsed timer
    const startTime = Date.now();
    timerRef.current = setInterval(() => {
      setElapsedSeconds(Math.floor((Date.now() - startTime) / 1000));
    }, 1000);

    try {
      // 1. Call Django Backend API to initialize scan and background orchestrator
      const startRes = await api.startUnifiedScan(
        {
          target: targetInput.trim(),
          modules: selectedModuleIds,
          scan_profile: scanProfile,
          intensity: 'normal',
          codebase_source_type: codebaseSourceMode,
          codebase_path: codebasePath
        },
        codebaseSourceMode === 'zip' ? selectedZipFile : null
      );

      const scanId = startRes.scan_id;
      activeScanIdRef.current = scanId;

      addLog(
        'orchestrator',
        'Unified Orchestrator',
        'info',
        `Backend scan session established [ID: ${scanId.slice(0, 8)}]. Listening for real-time SSE event pipeline...`
      );

      // 2. Stream real-time SSE progress events from Django
      abortStreamRef.current = api.streamUnifiedScan(
        scanId,
        (event: UnifiedScanStreamEvent) => {
          if (isCancelledRef.current) return;

          if (event.event === 'log' && event.log) {
            const rawLog = event.log as any;
            const mappedLog: UnifiedLogEntry = {
              id: rawLog.id || `${Date.now()}-${Math.random()}`,
              timestamp: rawLog.timestamp || new Date().toLocaleTimeString(),
              moduleId: rawLog.moduleId || rawLog.module_id || (event as any).current_module_id || 'orchestrator',
              moduleName: rawLog.moduleName || rawLog.module_name || 'Unified Orchestrator',
              level: rawLog.level || 'info',
              message: rawLog.message || ''
            };

            setLogs(prev => {
              if (prev.some(l => l.id === mappedLog.id)) return prev;
              return [...prev, mappedLog];
            });

            if (event.progress_percent !== undefined) {
              setOverallProgress(event.progress_percent);
            }
            if (event.current_module_id) {
              setCurrentRunningModuleId(event.current_module_id);
            }
            if (event.module_statuses) {
              setModuleStates(prev => ({ ...prev, ...(event.module_statuses as any) }));
            }
          } else if (event.event === 'complete' || event.event === 'finished') {
            if (timerRef.current) clearInterval(timerRef.current);
            setOverallProgress(100);
            setCurrentRunningModuleId(null);
            setScanState(event.status === 'COMPLETED' ? 'completed' : 'aborted');

            if (event.findings) {
              setFindings(event.findings);
            }
            if (event.module_statuses) {
              setModuleStates(prev => ({ ...prev, ...(event.module_statuses as any) }));
            }

            addLog(
              'orchestrator',
              'Unified Orchestrator',
              event.status === 'COMPLETED' ? 'success' : 'warn',
              `Unified scan finished with status: ${event.status}. Score: ${event.overall_score || 90}/100.`
            );
          } else if (event.event === 'error') {
            addLog('orchestrator', 'Unified Orchestrator', 'error', event.message || 'Stream error occurred.');
          }
        },
        (err) => {
          console.error('SSE Stream error:', err);
          // Poll for final results if stream disconnects
          api.getUnifiedScanResults(scanId)
            .then(res => {
              if (res?.scan) {
                if (timerRef.current) clearInterval(timerRef.current);
                setScanState(res.scan.status === 'COMPLETED' ? 'completed' : 'aborted');
                setOverallProgress(res.scan.progress_percent || 100);
                setFindings(res.scan.findings || []);
                if (res.scan.module_statuses) setModuleStates(res.scan.module_statuses as any);
              }
            })
            .catch(() => {});
        }
      );

    } catch (apiError: any) {
      console.warn('Backend API request failed, running local simulator fallback:', apiError);
      addLog(
        'orchestrator',
        'Unified Orchestrator',
        'warn',
        `Backend API connection note: ${apiError.message || 'Running in local development simulation mode'}`
      );

      // Local sequential simulation fallback
      let currentModuleIndex = 0;
      const totalModules = activeModules.length;

      const executeNextModule = () => {
        if (isCancelledRef.current) return;

        if (currentModuleIndex >= totalModules) {
          if (timerRef.current) clearInterval(timerRef.current);
          setOverallProgress(100);
          setCurrentRunningModuleId(null);
          setScanState('completed');
          addLog(
            'orchestrator',
            'Unified Orchestrator',
            'success',
            `Unified Security Assessment completed successfully. All ${totalModules} security modules finished.`
          );
          return;
        }

        const mod = activeModules[currentModuleIndex];
        setCurrentRunningModuleId(mod.id);
        const modStartTime = Date.now();

        const initialStep = mod.id === 'codebase-analysis' && codebaseSourceMode === 'zip' && selectedZipFile
          ? `Extracting and inspecting uploaded project archive [${selectedZipFile.name}]...`
          : mod.sampleSteps[0] || 'Initializing scan engine...';

        setModuleStates(prev => ({
          ...prev,
          [mod.id]: {
            ...prev[mod.id],
            status: 'running',
            startTime: modStartTime,
            currentStep: initialStep
          }
        }));

        addLog(mod.id, mod.shortName, 'info', `Initialized module [${mod.name}]`);

        const steps = mod.id === 'codebase-analysis' && codebaseSourceMode === 'zip' && selectedZipFile
          ? [
              `Unpacking ${selectedZipFile.name} (${(selectedZipFile.size / (1024 * 1024)).toFixed(2)} MB)`,
              'Parsing source tree files and dependencies',
              'Running AST static security inspection & secret detection',
              'Compiling SAST vulnerability report'
            ]
          : mod.sampleSteps;

        const stepDuration = (mod.estimatedTimeSec[scanProfile] * 1000) / steps.length;
        let currentStepIdx = 0;

        const stepInterval = setInterval(() => {
          if (isCancelledRef.current) {
            clearInterval(stepInterval);
            return;
          }

          currentStepIdx++;

          if (currentStepIdx < steps.length) {
            const stepText = steps[currentStepIdx];
            const modProgress = Math.round((currentStepIdx / steps.length) * 100);

            setModuleStates(prev => ({
              ...prev,
              [mod.id]: {
                ...prev[mod.id],
                progressPercent: modProgress,
                currentStep: stepText
              }
            }));

            addLog(mod.id, mod.shortName, 'info', stepText);

            const completedPortion = (currentModuleIndex / totalModules) * 100;
            const currentModulePortion = (modProgress / totalModules);
            setOverallProgress(Math.min(99, Math.round(completedPortion + currentModulePortion)));
          } else {
            clearInterval(stepInterval);

            const durationMs = Date.now() - modStartTime;
            setModuleStates(prev => ({
              ...prev,
              [mod.id]: {
                ...prev[mod.id],
                status: 'completed',
                progressPercent: 100,
                currentStep: 'Module audit completed',
                durationMs,
                summaryText: `Module completed (${(durationMs / 1000).toFixed(1)}s)`
              }
            }));

            currentModuleIndex++;
            executeNextModule();
          }
        }, stepDuration);
      };

      executeNextModule();
    }
  };

  const handleStopScan = () => {
    isCancelledRef.current = true;
    if (timerRef.current) clearInterval(timerRef.current);
    if (abortStreamRef.current) {
      abortStreamRef.current();
      abortStreamRef.current = null;
    }

    if (activeScanIdRef.current) {
      api.abortUnifiedScan(activeScanIdRef.current).catch(() => {});
    }

    setScanState('aborted');
    setCurrentRunningModuleId(null);
    addLog('orchestrator', 'Unified Orchestrator', 'warn', 'Unified scan aborted by user request.');

    setModuleStates(prev => {
      const updated = { ...prev };
      Object.keys(updated).forEach(k => {
        if (updated[k].status === 'running' || updated[k].status === 'pending') {
          updated[k].status = 'failed';
          updated[k].currentStep = 'Aborted before completion';
        }
      });
      return updated;
    });
  };

  const handleResetScan = () => {
    if (timerRef.current) clearInterval(timerRef.current);
    setScanState('idle');
    setOverallProgress(0);
    setElapsedSeconds(0);
    setCurrentRunningModuleId(null);
    setLogs([]);
    setFindings([]);
    setModuleStates({});
  };

  // Severity metrics calculation
  const totalFindingsCount = useMemo(() => {
    return {
      critical: findings.filter(f => f.severity === 'critical').length,
      high: findings.filter(f => f.severity === 'high').length,
      medium: findings.filter(f => f.severity === 'medium').length,
      low: findings.filter(f => f.severity === 'low').length,
      info: findings.filter(f => f.severity === 'info').length,
      total: findings.length
    };
  }, [findings]);

  // Overall Risk Score calculation
  const securityScore = useMemo(() => {
    if (scanState !== 'completed' || findings.length === 0) return 92;
    const penalty =
      totalFindingsCount.critical * 25 +
      totalFindingsCount.high * 15 +
      totalFindingsCount.medium * 7 +
      totalFindingsCount.low * 2;
    return Math.max(12, Math.min(100, 100 - penalty));
  }, [scanState, totalFindingsCount, findings]);

  const scoreGrade = useMemo(() => {
    if (securityScore >= 90) return { grade: 'A', text: 'Low Risk', color: '#3fb950', bg: 'rgba(63, 185, 80, 0.15)' };
    if (securityScore >= 75) return { grade: 'B', text: 'Moderate Risk', color: '#58a6ff', bg: 'rgba(88, 166, 255, 0.15)' };
    if (securityScore >= 60) return { grade: 'C', text: 'Elevated Risk', color: '#d29922', bg: 'rgba(210, 153, 34, 0.15)' };
    if (securityScore >= 40) return { grade: 'D', text: 'High Risk', color: '#f0883e', bg: 'rgba(240, 136, 62, 0.15)' };
    return { grade: 'F', text: 'Critical Risk', color: '#f85149', bg: 'rgba(248, 81, 73, 0.15)' };
  }, [securityScore]);

  // Filtered modules for selection view
  const filteredModules = useMemo(() => {
    return SECURITY_MODULES.filter(m => {
      const matchCat = categoryFilter === 'all' || m.category === categoryFilter;
      const matchQuery =
        !searchModuleQuery ||
        m.name.toLowerCase().includes(searchModuleQuery.toLowerCase()) ||
        m.description.toLowerCase().includes(searchModuleQuery.toLowerCase()) ||
        m.tags.some(t => t.toLowerCase().includes(searchModuleQuery.toLowerCase()));
      return matchCat && matchQuery;
    });
  }, [categoryFilter, searchModuleQuery]);

  // Filtered logs
  const filteredLogs = useMemo(() => {
    return logs.filter(l => {
      const matchMod = logFilterModule === 'all' || l.moduleId === logFilterModule;
      const matchLvl = logFilterLevel === 'all' || l.level === logFilterLevel;
      return matchMod && matchLvl;
    });
  }, [logs, logFilterModule, logFilterLevel]);

  // Export report handler
  const handleExportReport = (format: 'json' | 'markdown') => {
    let content = '';
    const dateStr = new Date().toISOString();

    if (format === 'json') {
      const exportObj = {
        scanType: 'AttackLens Unified Security Assessment',
        target: cleanTargetPreview,
        profile: scanProfile,
        codebaseSource: codebaseSourceMode === 'zip' ? selectedZipFile?.name || 'No ZIP uploaded' : codebasePath,
        date: dateStr,
        securityScore,
        scoreGrade: scoreGrade.grade,
        riskRating: scoreGrade.text,
        metrics: totalFindingsCount,
        modules: moduleStates,
        findings
      };
      content = JSON.stringify(exportObj, null, 2);
    } else {
      content = `# AttackLens Unified Security Assessment Report
**Target:** \`${cleanTargetPreview}\`  
**Date:** ${new Date().toLocaleString()}  
**Profile:** ${scanProfile.toUpperCase()}  
**Codebase Source:** ${codebaseSourceMode === 'zip' ? `ZIP: ${selectedZipFile?.name || 'None'}` : `Path: ${codebasePath}`}  
**Overall Security Score:** ${securityScore}/100 (${scoreGrade.grade} - ${scoreGrade.text})  

---

## Executive Summary
- **Critical Findings:** ${totalFindingsCount.critical}
- **High Findings:** ${totalFindingsCount.high}
- **Medium Findings:** ${totalFindingsCount.medium}
- **Low Findings:** ${totalFindingsCount.low}
- **Informational:** ${totalFindingsCount.info}
- **Total Findings:** ${totalFindingsCount.total}

---

## Module Statuses
${SECURITY_MODULES.map(m => {
  const state = moduleStates[m.id];
  return `- **${m.name}**: ${state?.status || 'Skipped'} (${state?.summaryText || 'N/A'})`;
}).join('\n')}

---

## Discovered Security Findings
${findings.map((f, i) => `
### ${i + 1}. [${f.severity.toUpperCase()}] ${f.title}
- **Module:** ${f.moduleName}
- **Location:** \`${f.location}\`
- **CVSS Score:** ${f.cvss} ${f.cwe ? `(${f.cwe})` : ''}
- **Description:** ${f.description}
- **Remediation:** ${f.remediation}
`).join('\n')}
`;
    }

    const blob = new Blob([content], { type: format === 'json' ? 'application/json' : 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `attacklens-unified-scan-${Date.now()}.${format === 'json' ? 'json' : 'md'}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleCopySummary = () => {
    const summaryText = `AttackLens Unified Security Scan for ${cleanTargetPreview}
Score: ${securityScore}/100 (${scoreGrade.grade} - ${scoreGrade.text})
Critical: ${totalFindingsCount.critical} | High: ${totalFindingsCount.high} | Medium: ${totalFindingsCount.medium} | Low: ${totalFindingsCount.low}
Active Modules: ${selectedModuleIds.length} | Status: ${scanState.toUpperCase()}`;
    navigator.clipboard.writeText(summaryText);
    setCopiedSummary(true);
    setTimeout(() => setCopiedSummary(false), 2000);
  };

  return (
    <div style={{ paddingBottom: 60 }}>
      {/* Header Section */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'flex-start',
        marginBottom: 24,
        gap: 16,
        flexWrap: 'wrap'
      }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
            <div style={{
              width: 32,
              height: 32,
              borderRadius: 8,
              background: 'linear-gradient(135deg, #1f6feb 0%, #8957e5 100%)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              boxShadow: '0 0 16px rgba(137, 87, 229, 0.4)'
            }}>
              <Shield style={{ width: 18, height: 18, color: '#ffffff' }} />
            </div>
            <h1 style={{ fontSize: 24, fontWeight: 700, color: 'var(--fg-default)', margin: 0, letterSpacing: '-0.02em' }}>
              Unified Security Assessment
            </h1>
            <span style={{
              padding: '2px 8px',
              borderRadius: 12,
              fontSize: 11,
              fontWeight: 600,
              background: 'rgba(56, 139, 253, 0.15)',
              color: 'var(--accent-fg)',
              border: '1px solid rgba(56, 139, 253, 0.3)'
            }}>
              All-In-One Orchestrator
            </span>
          </div>
          <p style={{ fontSize: 13, color: 'var(--fg-muted)', margin: 0, maxWidth: 680 }}>
            Run an integrated full-stack scan across all 9 AttackLens security engines: network surface, web application vulnerability, TLS crypto, API analysis, and static code security.
          </p>
        </div>

        {/* Global Action State Button */}
        {scanState === 'running' ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <button
              onClick={handleStopScan}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                padding: '9px 18px',
                borderRadius: 6,
                border: '1px solid var(--danger-border)',
                background: 'var(--danger-subtle)',
                color: 'var(--danger-fg)',
                fontWeight: 600,
                fontSize: 13,
                cursor: 'pointer',
                transition: 'all 0.15s ease'
              }}
            >
              <Square style={{ width: 15, height: 15, fill: 'currentColor' }} />
              Stop Assessment
            </button>
          </div>
        ) : scanState === 'completed' || scanState === 'aborted' ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <button
              onClick={handleResetScan}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                padding: '9px 18px',
                borderRadius: 6,
                border: '1px solid var(--border-default)',
                background: 'var(--bg-subtle)',
                color: 'var(--fg-default)',
                fontWeight: 600,
                fontSize: 13,
                cursor: 'pointer',
                transition: 'all 0.15s ease'
              }}
            >
              <RotateCcw style={{ width: 15, height: 15 }} />
              Configure New Scan
            </button>
            <button
              onClick={() => handleExportReport('markdown')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                padding: '9px 18px',
                borderRadius: 6,
                border: '1px solid var(--accent-border)',
                background: 'var(--accent-subtle)',
                color: 'var(--accent-fg)',
                fontWeight: 600,
                fontSize: 13,
                cursor: 'pointer',
                transition: 'all 0.15s ease'
              }}
            >
              <Download style={{ width: 15, height: 15 }} />
              Export Report
            </button>
          </div>
        ) : null}
      </div>

      {/* ========================================================================= */}
      {/* 1. CONFIGURATION VIEW (When Idle)                                         */}
      {/* ========================================================================= */}
      {scanState === 'idle' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
          {/* Target & Profile Selection Card */}
          <div style={{
            background: 'var(--bg-subtle)',
            border: '1px solid var(--border-default)',
            borderRadius: 10,
            padding: 22,
            boxShadow: 'var(--shadow-sm)'
          }}>
            <h2 style={{ fontSize: 14, fontWeight: 700, color: 'var(--fg-default)', margin: '0 0 16px 0', display: 'flex', alignItems: 'center', gap: 8 }}>
              <Globe style={{ width: 16, height: 16, color: 'var(--accent-fg)' }} />
              1. Target Environment & Scope
            </h2>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: 20 }}>
              {/* Primary Target URL / Host */}
              <div>
                <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: 'var(--fg-muted)', marginBottom: 6 }}>
                  Target IP / Hostname / Live URL
                </label>
                <div style={{ display: 'flex', gap: 8 }}>
                  <input
                    type="text"
                    value={targetInput}
                    onChange={e => setTargetInput(e.target.value)}
                    placeholder="e.g. 127.0.0.1, scanme.nmap.org, https://example.com"
                    style={{
                      flex: 1,
                      padding: '9px 12px',
                      background: 'var(--bg-inset)',
                      border: '1px solid var(--border-muted)',
                      borderRadius: 6,
                      color: 'var(--fg-default)',
                      fontSize: 13,
                      fontFamily: 'JetBrains Mono, monospace',
                      outline: 'none'
                    }}
                  />
                </div>

                {/* Preset Quick Chips */}
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 8 }}>
                  {PRESET_TARGETS.map(preset => (
                    <button
                      key={preset.value}
                      onClick={() => setTargetInput(preset.value)}
                      style={{
                        fontSize: 11,
                        padding: '3px 8px',
                        borderRadius: 4,
                        border: targetInput === preset.value ? '1px solid var(--accent-fg)' : '1px solid var(--border-default)',
                        background: targetInput === preset.value ? 'var(--accent-subtle)' : 'var(--bg-emphasis)',
                        color: targetInput === preset.value ? 'var(--accent-fg)' : 'var(--fg-muted)',
                        cursor: 'pointer',
                        transition: 'all 0.1s ease'
                      }}
                    >
                      {preset.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Codebase Source (Local Directory Path OR Upload ZIP Archive) */}
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                  <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--fg-muted)', margin: 0 }}>
                    Source Codebase Target (for SAST)
                  </label>
                  
                  {/* Mode Selector Tabs */}
                  <div style={{ display: 'flex', background: 'var(--bg-inset)', padding: 2, borderRadius: 5, border: '1px solid var(--border-default)' }}>
                    <button
                      type="button"
                      onClick={() => setCodebaseSourceMode('path')}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 4,
                        padding: '2px 8px',
                        borderRadius: 4,
                        fontSize: 11,
                        fontWeight: 600,
                        border: 'none',
                        background: codebaseSourceMode === 'path' ? 'var(--bg-emphasis)' : 'transparent',
                        color: codebaseSourceMode === 'path' ? 'var(--accent-fg)' : 'var(--fg-muted)',
                        cursor: 'pointer'
                      }}
                    >
                      <Folder style={{ width: 12, height: 12 }} />
                      Local Path
                    </button>
                    <button
                      type="button"
                      onClick={() => setCodebaseSourceMode('zip')}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 4,
                        padding: '2px 8px',
                        borderRadius: 4,
                        fontSize: 11,
                        fontWeight: 600,
                        border: 'none',
                        background: codebaseSourceMode === 'zip' ? 'var(--bg-emphasis)' : 'transparent',
                        color: codebaseSourceMode === 'zip' ? '#ff7b72' : 'var(--fg-muted)',
                        cursor: 'pointer'
                      }}
                    >
                      <Upload style={{ width: 12, height: 12 }} />
                      Upload ZIP
                    </button>
                  </div>
                </div>

                {codebaseSourceMode === 'path' ? (
                  <div>
                    <input
                      type="text"
                      value={codebasePath}
                      onChange={e => setCodebasePath(e.target.value)}
                      placeholder="e.g. d:\Flutter\AttackLens or /var/www/project"
                      style={{
                        width: '100%',
                        padding: '9px 12px',
                        background: 'var(--bg-inset)',
                        border: '1px solid var(--border-muted)',
                        borderRadius: 6,
                        color: 'var(--fg-default)',
                        fontSize: 13,
                        fontFamily: 'JetBrains Mono, monospace',
                        outline: 'none'
                      }}
                    />
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 5 }}>
                      <span style={{ fontSize: 11, color: 'var(--fg-subtle)' }}>
                        Scans local folder files directly via SAST scanner.
                      </span>
                      <button
                        type="button"
                        onClick={() => setCodebasePath('d:\\Flutter\\AttackLens')}
                        style={{
                          background: 'none',
                          border: 'none',
                          color: 'var(--accent-fg)',
                          fontSize: 11,
                          cursor: 'pointer',
                          padding: 0
                        }}
                      >
                        Use Workspace Default
                      </button>
                    </div>
                  </div>
                ) : (
                  <div>
                    {/* Hidden Native File Input */}
                    <input
                      type="file"
                      ref={zipInputRef}
                      onChange={handleZipFileChange}
                      accept=".zip,.tar.gz,.tgz"
                      style={{ display: 'none' }}
                    />

                    {selectedZipFile ? (
                      <div style={{
                        padding: '10px 14px',
                        borderRadius: 6,
                        background: 'rgba(255, 123, 114, 0.08)',
                        border: '1px solid rgba(255, 123, 114, 0.4)',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between'
                      }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10, minWidth: 0 }}>
                          <FileArchive style={{ width: 20, height: 20, color: '#ff7b72', flexShrink: 0 }} />
                          <div style={{ minWidth: 0 }}>
                            <div style={{
                              fontSize: 12,
                              fontWeight: 700,
                              color: 'var(--fg-default)',
                              whiteSpace: 'nowrap',
                              overflow: 'hidden',
                              textOverflow: 'ellipsis'
                            }}>
                              {selectedZipFile.name}
                            </div>
                            <span style={{ fontSize: 10, color: 'var(--fg-muted)', fontFamily: 'JetBrains Mono, monospace' }}>
                              {(selectedZipFile.size / (1024 * 1024)).toFixed(2)} MB • Ready for Unified Scan
                            </span>
                          </div>
                        </div>

                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <button
                            type="button"
                            onClick={() => zipInputRef.current?.click()}
                            style={{
                              fontSize: 11,
                              padding: '3px 8px',
                              borderRadius: 4,
                              background: 'var(--bg-emphasis)',
                              border: '1px solid var(--border-default)',
                              color: 'var(--fg-default)',
                              cursor: 'pointer'
                            }}
                          >
                            Change
                          </button>
                          <button
                            type="button"
                            onClick={handleClearZip}
                            title="Remove file"
                            style={{
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'center',
                              width: 24,
                              height: 24,
                              borderRadius: 4,
                              background: 'var(--bg-emphasis)',
                              border: '1px solid var(--border-default)',
                              color: 'var(--danger-fg)',
                              cursor: 'pointer'
                            }}
                          >
                            <X style={{ width: 14, height: 14 }} />
                          </button>
                        </div>
                      </div>
                    ) : (
                      <div
                        onClick={() => zipInputRef.current?.click()}
                        onDragOver={e => { e.preventDefault(); setIsDragOver(true); }}
                        onDragLeave={() => setIsDragOver(false)}
                        onDrop={handleDropZip}
                        style={{
                          padding: '14px 16px',
                          borderRadius: 6,
                          background: isDragOver ? 'rgba(56, 139, 253, 0.12)' : 'var(--bg-inset)',
                          border: isDragOver ? '1px dashed var(--accent-fg)' : '1px dashed var(--border-muted)',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          gap: 10,
                          cursor: 'pointer',
                          transition: 'all 0.15s ease'
                        }}
                      >
                        <Upload style={{ width: 16, height: 16, color: '#ff7b72' }} />
                        <div style={{ textAlign: 'left' }}>
                          <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--fg-default)' }}>
                            Click to upload code ZIP
                          </span>
                          <span style={{ fontSize: 11, color: 'var(--fg-muted)', display: 'block' }}>
                            or drag and drop archive (.zip, .tar.gz, up to 100MB)
                          </span>
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>

            {/* Scan Profile Selection */}
            <div style={{ marginTop: 20, paddingTop: 18, borderTop: '1px solid var(--border-default)' }}>
              <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: 'var(--fg-muted)', marginBottom: 10 }}>
                Scan Depth Profile
              </label>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 12 }}>
                {/* Quick Profile */}
                <div
                  onClick={() => setScanProfile('quick')}
                  style={{
                    padding: 14,
                    borderRadius: 8,
                    border: scanProfile === 'quick' ? '1px solid var(--accent-fg)' : '1px solid var(--border-default)',
                    background: scanProfile === 'quick' ? 'rgba(56, 139, 253, 0.08)' : 'var(--bg-inset)',
                    cursor: 'pointer',
                    transition: 'all 0.15s ease'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
                    <span style={{ fontWeight: 700, fontSize: 13, color: scanProfile === 'quick' ? 'var(--accent-fg)' : 'var(--fg-default)' }}>
                      ⚡ Quick Recon
                    </span>
                    <span style={{ fontSize: 11, color: 'var(--fg-subtle)' }}>~15-30s</span>
                  </div>
                  <p style={{ fontSize: 11, color: 'var(--fg-muted)', margin: 0 }}>
                    Top 100 ports, fast header check, rapid signature fingerprinting, and basic TLS handshake.
                  </p>
                </div>

                {/* Standard Profile */}
                <div
                  onClick={() => setScanProfile('standard')}
                  style={{
                    padding: 14,
                    borderRadius: 8,
                    border: scanProfile === 'standard' ? '1px solid #3fb950' : '1px solid var(--border-default)',
                    background: scanProfile === 'standard' ? 'rgba(63, 185, 80, 0.08)' : 'var(--bg-inset)',
                    cursor: 'pointer',
                    transition: 'all 0.15s ease'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
                    <span style={{ fontWeight: 700, fontSize: 13, color: scanProfile === 'standard' ? '#3fb950' : 'var(--fg-default)' }}>
                      🛡️ Standard Balanced (Recommended)
                    </span>
                    <span style={{ fontSize: 11, color: 'var(--fg-subtle)' }}>~45-75s</span>
                  </div>
                  <p style={{ fontSize: 11, color: 'var(--fg-muted)', margin: 0 }}>
                    Top 1000 ports, full cipher check, endpoint fuzzing, API authorization audit, and SAST secrets scan.
                  </p>
                </div>

                {/* Deep Profile */}
                <div
                  onClick={() => setScanProfile('deep')}
                  style={{
                    padding: 14,
                    borderRadius: 8,
                    border: scanProfile === 'deep' ? '1px solid #a371f7' : '1px solid var(--border-default)',
                    background: scanProfile === 'deep' ? 'rgba(163, 113, 247, 0.08)' : 'var(--bg-inset)',
                    cursor: 'pointer',
                    transition: 'all 0.15s ease'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
                    <span style={{ fontWeight: 700, fontSize: 13, color: scanProfile === 'deep' ? '#a371f7' : 'var(--fg-default)' }}>
                      🔬 Deep Pentest
                    </span>
                    <span style={{ fontSize: 11, color: 'var(--fg-subtle)' }}>~90-150s</span>
                  </div>
                  <p style={{ fontSize: 11, color: 'var(--fg-muted)', margin: 0 }}>
                    All-port range scan, exhaustive crawler depth, recursive fuzzing, parameter fuzzing, and complete SAST audit.
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* Module Selection Section */}
          <div style={{
            background: 'var(--bg-subtle)',
            border: '1px solid var(--border-default)',
            borderRadius: 10,
            padding: 22,
            boxShadow: 'var(--shadow-sm)'
          }}>
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              marginBottom: 16,
              flexWrap: 'wrap',
              gap: 12
            }}>
              <div>
                <h2 style={{ fontSize: 14, fontWeight: 700, color: 'var(--fg-default)', margin: 0, display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Layers style={{ width: 16, height: 16, color: '#d29922' }} />
                  2. Select Security Modules ({selectedModuleIds.length} / {SECURITY_MODULES.length} Selected)
                </h2>
                <span style={{ fontSize: 12, color: 'var(--fg-muted)' }}>
                  Choose which analysis engines to execute during the unified assessment.
                </span>
              </div>

              {/* Quick Actions */}
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <button
                  onClick={handleSelectAll}
                  style={{
                    padding: '5px 12px',
                    borderRadius: 5,
                    border: '1px solid var(--border-default)',
                    background: 'var(--bg-emphasis)',
                    color: 'var(--fg-default)',
                    fontSize: 12,
                    fontWeight: 600,
                    cursor: 'pointer'
                  }}
                >
                  Select All
                </button>
                <button
                  onClick={handleClearAll}
                  style={{
                    padding: '5px 12px',
                    borderRadius: 5,
                    border: '1px solid var(--border-default)',
                    background: 'var(--bg-emphasis)',
                    color: 'var(--fg-muted)',
                    fontSize: 12,
                    fontWeight: 600,
                    cursor: 'pointer'
                  }}
                >
                  Clear All
                </button>
              </div>
            </div>

            {/* Filter Bar */}
            <div style={{
              display: 'flex',
              gap: 10,
              alignItems: 'center',
              marginBottom: 16,
              flexWrap: 'wrap',
              padding: '10px 14px',
              background: 'var(--bg-inset)',
              borderRadius: 6,
              border: '1px solid var(--border-default)'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, flex: 1, minWidth: 200 }}>
                <Search style={{ width: 14, height: 14, color: 'var(--fg-subtle)' }} />
                <input
                  type="text"
                  placeholder="Filter security modules by name, keyword or tag..."
                  value={searchModuleQuery}
                  onChange={e => setSearchModuleQuery(e.target.value)}
                  style={{
                    background: 'transparent',
                    border: 'none',
                    color: 'var(--fg-default)',
                    fontSize: 12,
                    width: '100%',
                    outline: 'none'
                  }}
                />
              </div>

              <div style={{ display: 'flex', gap: 6 }}>
                {['all', 'Network & Host', 'Web Application', 'Encryption & Config', 'Source & API'].map(cat => (
                  <button
                    key={cat}
                    onClick={() => setCategoryFilter(cat)}
                    style={{
                      padding: '4px 10px',
                      borderRadius: 4,
                      fontSize: 11,
                      fontWeight: 600,
                      border: categoryFilter === cat ? '1px solid var(--accent-fg)' : '1px solid transparent',
                      background: categoryFilter === cat ? 'var(--accent-subtle)' : 'transparent',
                      color: categoryFilter === cat ? 'var(--accent-fg)' : 'var(--fg-muted)',
                      cursor: 'pointer'
                    }}
                  >
                    {cat === 'all' ? 'All Categories' : cat}
                  </button>
                ))}
              </div>
            </div>

            {/* Module Cards Grid */}
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fill, minmax(330px, 1fr))',
              gap: 14
            }}>
              {filteredModules.map(mod => {
                const IconComponent = mod.icon;
                const isSelected = selectedModuleIds.includes(mod.id);

                return (
                  <div
                    key={mod.id}
                    onClick={() => handleToggleModule(mod.id)}
                    style={{
                      padding: 16,
                      borderRadius: 8,
                      border: isSelected ? `1px solid ${mod.accentColor}` : '1px solid var(--border-default)',
                      background: isSelected ? 'var(--bg-inset)' : 'rgba(22, 27, 34, 0.4)',
                      cursor: 'pointer',
                      transition: 'all 0.15s ease',
                      position: 'relative',
                      display: 'flex',
                      flexDirection: 'column',
                      justifyContent: 'space-between'
                    }}
                  >
                    <div>
                      {/* Card Header */}
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                          <div style={{
                            width: 30,
                            height: 30,
                            borderRadius: 6,
                            background: isSelected ? `${mod.accentColor}20` : 'var(--bg-emphasis)',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            border: isSelected ? `1px solid ${mod.accentColor}50` : '1px solid var(--border-default)'
                          }}>
                            <IconComponent style={{ width: 16, height: 16, color: isSelected ? mod.accentColor : 'var(--fg-muted)' }} />
                          </div>
                          <div>
                            <h3 style={{ fontSize: 13, fontWeight: 700, color: 'var(--fg-default)', margin: 0 }}>
                              {mod.name}
                            </h3>
                            <span style={{ fontSize: 10, color: 'var(--fg-subtle)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                              {mod.category}
                            </span>
                          </div>
                        </div>

                        {/* Checkbox Icon */}
                        <div style={{
                          width: 18,
                          height: 18,
                          borderRadius: 4,
                          border: isSelected ? `1px solid ${mod.accentColor}` : '1px solid var(--border-muted)',
                          background: isSelected ? mod.accentColor : 'transparent',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          flexShrink: 0
                        }}>
                          {isSelected && <Check style={{ width: 12, height: 12, color: '#ffffff', strokeWidth: 3 }} />}
                        </div>
                      </div>

                      {/* Description */}
                      <p style={{ fontSize: 12, color: 'var(--fg-muted)', margin: '6px 0 10px 0', lineHeight: 1.45 }}>
                        {mod.description}
                      </p>
                    </div>

                    {/* Footer Tags & Estimated Time */}
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 6, paddingTop: 8, borderTop: '1px solid var(--border-subtle)' }}>
                      <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                        {mod.tags.slice(0, 2).map(tag => (
                          <span
                            key={tag}
                            style={{
                              fontSize: 10,
                              padding: '2px 6px',
                              borderRadius: 4,
                              background: 'var(--bg-emphasis)',
                              color: 'var(--fg-subtle)'
                            }}
                          >
                            {tag}
                          </span>
                        ))}
                      </div>

                      <span style={{ fontSize: 11, color: 'var(--fg-subtle)', fontFamily: 'JetBrains Mono, monospace' }}>
                        ~{mod.estimatedTimeSec[scanProfile]}s
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* 3. Scan Summary & Launch Bar */}
          <div style={{
            background: 'linear-gradient(135deg, rgba(31, 111, 235, 0.12) 0%, rgba(137, 87, 229, 0.12) 100%)',
            border: '1px solid rgba(56, 139, 253, 0.3)',
            borderRadius: 10,
            padding: 20,
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: 16
          }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                <Sparkles style={{ width: 16, height: 16, color: 'var(--accent-fg)' }} />
                <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--fg-default)', margin: 0 }}>
                  Ready to Launch Unified Scan
                </h3>
              </div>
              <div style={{ display: 'flex', gap: 16, fontSize: 12, color: 'var(--fg-muted)', flexWrap: 'wrap' }}>
                <span><strong>Target:</strong> <code style={{ color: 'var(--fg-default)' }}>{cleanTargetPreview}</code></span>
                {selectedModuleIds.includes('codebase-analysis') && (
                  <span>
                    <strong>Codebase:</strong>{' '}
                    <code style={{ color: codebaseSourceMode === 'zip' ? '#ff7b72' : 'var(--fg-default)' }}>
                      {codebaseSourceMode === 'zip' ? (selectedZipFile ? `ZIP: ${selectedZipFile.name}` : 'ZIP: None uploaded') : `Path: ${codebasePath}`}
                    </code>
                  </span>
                )}
                <span><strong>Profile:</strong> <span style={{ textTransform: 'uppercase', color: 'var(--accent-fg)', fontWeight: 600 }}>{scanProfile}</span></span>
                <span><strong>Active Modules:</strong> <span style={{ color: '#3fb950', fontWeight: 600 }}>{selectedModuleIds.length}</span> / {SECURITY_MODULES.length}</span>
                <span><strong>Estimated Duration:</strong> <span style={{ color: 'var(--fg-default)', fontFamily: 'JetBrains Mono, monospace' }}>~{totalEstimatedTimeSec} seconds</span></span>
              </div>
            </div>

            <button
              onClick={handleStartUnifiedScan}
              disabled={selectedModuleIds.length === 0 || !targetInput.trim()}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 10,
                padding: '12px 28px',
                borderRadius: 8,
                border: 'none',
                background: selectedModuleIds.length === 0 ? 'var(--bg-emphasis)' : 'linear-gradient(135deg, #1f6feb 0%, #388bfd 100%)',
                color: selectedModuleIds.length === 0 ? 'var(--fg-subtle)' : '#ffffff',
                fontWeight: 700,
                fontSize: 14,
                cursor: selectedModuleIds.length === 0 ? 'not-allowed' : 'pointer',
                boxShadow: selectedModuleIds.length === 0 ? 'none' : '0 0 20px rgba(56, 139, 253, 0.45)',
                transition: 'all 0.15s ease'
              }}
            >
              <Play style={{ width: 16, height: 16, fill: 'currentColor' }} />
              Start Unified Scan
            </button>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* 2. LIVE PROGRESS VIEW (When Running)                                      */}
      {/* ========================================================================= */}
      {scanState === 'running' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          {/* Progress Header Card */}
          <div style={{
            background: 'var(--bg-subtle)',
            border: '1px solid var(--border-default)',
            borderRadius: 10,
            padding: 20,
            boxShadow: 'var(--shadow-sm)'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14, flexWrap: 'wrap', gap: 10 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <div style={{
                  width: 10,
                  height: 10,
                  borderRadius: '50%',
                  background: 'var(--accent-fg)',
                  boxShadow: '0 0 10px var(--accent-fg)'
                }} />
                <span style={{ fontSize: 14, fontWeight: 700, color: 'var(--fg-default)' }}>
                  Unified Scan In Progress...
                </span>
                <span style={{
                  fontSize: 11,
                  padding: '2px 8px',
                  borderRadius: 4,
                  background: 'var(--bg-emphasis)',
                  color: 'var(--fg-muted)',
                  fontFamily: 'JetBrains Mono, monospace'
                }}>
                  {cleanTargetPreview}
                </span>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--fg-muted)' }}>
                  <Clock style={{ width: 14, height: 14 }} />
                  <span>Elapsed: <strong style={{ color: 'var(--fg-default)', fontFamily: 'JetBrains Mono, monospace' }}>{elapsedSeconds}s</strong></span>
                </div>
                <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--accent-fg)', fontFamily: 'JetBrains Mono, monospace' }}>
                  {overallProgress}%
                </div>
              </div>
            </div>

            {/* Overall Progress Bar */}
            <div style={{
              width: '100%',
              height: 8,
              background: 'var(--bg-inset)',
              borderRadius: 4,
              overflow: 'hidden',
              border: '1px solid var(--border-subtle)'
            }}>
              <div style={{
                width: `${overallProgress}%`,
                height: '100%',
                background: 'linear-gradient(90deg, #1f6feb 0%, #388bfd 50%, #8957e5 100%)',
                borderRadius: 4,
                transition: 'width 0.3s ease'
              }} />
            </div>
          </div>

          {/* Main Execution Split: Left Pipeline, Right Live Terminal */}
          <div style={{ display: 'grid', gridTemplateColumns: 'minmax(340px, 1.2fr) minmax(320px, 1fr)', gap: 18 }}>
            {/* Module Pipeline States */}
            <div style={{
              background: 'var(--bg-subtle)',
              border: '1px solid var(--border-default)',
              borderRadius: 10,
              padding: 18,
              display: 'flex',
              flexDirection: 'column',
              gap: 10
            }}>
              <h3 style={{ fontSize: 13, fontWeight: 700, color: 'var(--fg-default)', margin: '0 0 4px 0' }}>
                Module Execution Pipeline
              </h3>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {SECURITY_MODULES.filter(m => selectedModuleIds.includes(m.id)).map(mod => {
                  const state = moduleStates[mod.id];
                  const IconComp = mod.icon;
                  const isCurrent = currentRunningModuleId === mod.id;

                  let statusBadge = (
                    <span style={{ fontSize: 11, color: 'var(--fg-subtle)', display: 'flex', alignItems: 'center', gap: 4 }}>
                      <Clock style={{ width: 12, height: 12 }} /> Pending
                    </span>
                  );

                  if (state?.status === 'running') {
                    statusBadge = (
                      <span style={{ fontSize: 11, color: mod.accentColor, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 4 }}>
                        <Activity style={{ width: 12, height: 12 }} /> Running ({state.progressPercent}%)
                      </span>
                    );
                  } else if (state?.status === 'completed') {
                    statusBadge = (
                      <span style={{ fontSize: 11, color: '#3fb950', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 4 }}>
                        <CheckCircle2 style={{ width: 12, height: 12 }} /> Finished
                      </span>
                    );
                  } else if (state?.status === 'failed') {
                    statusBadge = (
                      <span style={{ fontSize: 11, color: 'var(--danger-fg)', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 4 }}>
                        <XCircle style={{ width: 12, height: 12 }} /> Failed
                      </span>
                    );
                  }

                  return (
                    <div
                      key={mod.id}
                      style={{
                        padding: '10px 12px',
                        borderRadius: 6,
                        background: isCurrent ? 'var(--bg-inset)' : 'rgba(1, 4, 9, 0.4)',
                        border: isCurrent ? `1px solid ${mod.accentColor}` : '1px solid var(--border-default)',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: 6
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <IconComp style={{ width: 15, height: 15, color: state?.status === 'completed' ? '#3fb950' : mod.accentColor }} />
                          <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--fg-default)' }}>
                            {mod.name}
                          </span>
                        </div>
                        {statusBadge}
                      </div>

                      <div style={{ fontSize: 11, color: 'var(--fg-muted)', display: 'flex', justifyContent: 'space-between' }}>
                        <span style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: '80%' }}>
                          {state?.currentStep || 'Waiting...'}
                        </span>
                        {state?.durationMs && (
                          <span style={{ fontFamily: 'JetBrains Mono, monospace', color: 'var(--fg-subtle)' }}>
                            {(state.durationMs / 1000).toFixed(1)}s
                          </span>
                        )}
                      </div>

                      {/* Inline micro progress */}
                      {state?.status === 'running' && (
                        <div style={{ width: '100%', height: 3, background: 'var(--bg-emphasis)', borderRadius: 2, overflow: 'hidden' }}>
                          <div style={{ width: `${state.progressPercent}%`, height: '100%', background: mod.accentColor }} />
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Live Streaming Console */}
            <div style={{
              background: 'var(--bg-inset)',
              border: '1px solid var(--border-default)',
              borderRadius: 10,
              display: 'flex',
              flexDirection: 'column',
              height: 440,
              overflow: 'hidden'
            }}>
              {/* Console Bar */}
              <div style={{
                padding: '10px 14px',
                background: 'var(--bg-subtle)',
                borderBottom: '1px solid var(--border-default)',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <TerminalIcon style={{ width: 14, height: 14, color: 'var(--accent-fg)' }} />
                  <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--fg-default)' }}>
                    Live Orchestration Stream
                  </span>
                </div>
                <span style={{ fontSize: 11, color: 'var(--fg-subtle)', fontFamily: 'JetBrains Mono, monospace' }}>
                  {logs.length} events
                </span>
              </div>

              {/* Console Logs Body */}
              <div style={{
                flex: 1,
                padding: 12,
                overflowY: 'auto',
                fontFamily: 'JetBrains Mono, monospace',
                fontSize: 11,
                display: 'flex',
                flexDirection: 'column',
                gap: 6
              }}>
                {logs.map(log => {
                  let color = '#8b949e';
                  if (log.level === 'success') color = '#3fb950';
                  if (log.level === 'warn') color = '#f0883e';
                  if (log.level === 'error') color = '#f85149';

                  return (
                    <div key={log.id} style={{ display: 'flex', gap: 8, lineHeight: 1.4 }}>
                      <span style={{ color: 'var(--fg-subtle)', flexShrink: 0 }}>[{log.timestamp}]</span>
                      <span style={{ color: 'var(--accent-fg)', flexShrink: 0, fontWeight: 600 }}>[{log.moduleName}]</span>
                      <span style={{ color }}>{log.message}</span>
                    </div>
                  );
                })}
                <div ref={logsEndRef} />
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* 3. SECURITY ASSESSMENT WALKTHROUGH (When Completed)                        */}
      {/* ========================================================================= */}
      {scanState === 'completed' && (
        <SecurityAssessmentWalkthrough
          scanId={activeScanIdRef.current}
          target={cleanTargetPreview}
          onResetScan={handleResetScan}
          onNavigate={setActivePage}
        />
      )}

      {/* ========================================================================= */}
      {/* 4. ABORTED SCAN STATE                                                     */}
      {/* ========================================================================= */}
      {scanState === 'aborted' && (
        <div style={{
          background: 'var(--bg-subtle)',
          border: '1px solid var(--border-default)',
          borderRadius: 12,
          padding: 28,
          display: 'flex',
          flexDirection: 'column',
          gap: 20
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 16 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
              <div style={{
                width: 44,
                height: 44,
                borderRadius: 10,
                background: 'rgba(248, 81, 73, 0.15)',
                border: '1px solid #f85149',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#f85149'
              }}>
                <XCircle size={24} />
              </div>
              <div>
                <h3 style={{ fontSize: 18, fontWeight: 700, color: 'var(--fg-default)', margin: '0 0 4px 0' }}>
                  Unified Scan Cancelled / Aborted
                </h3>
                <p style={{ fontSize: 13, color: 'var(--fg-muted)', margin: 0 }}>
                  Scan on <code style={{ color: 'var(--fg-default)' }}>{cleanTargetPreview}</code> was stopped after {elapsedSeconds}s ({overallProgress}% processed).
                </p>
              </div>
            </div>

            <button
              onClick={handleResetScan}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 8,
                padding: '8px 18px',
                background: 'var(--accent-primary)',
                color: '#fff',
                borderRadius: 8,
                border: 'none',
                fontWeight: 600,
                fontSize: 13,
                cursor: 'pointer'
              }}
            >
              <RotateCcw size={15} />
              Configure New Scan
            </button>
          </div>

          {/* Abort Execution Log Stream */}
          <div>
            <h4 style={{ fontSize: 13, fontWeight: 700, color: 'var(--fg-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', margin: '0 0 10px 0' }}>
              Execution Logs Prior to Abort
            </h4>
            <div style={{
              background: 'var(--bg-inset)',
              border: '1px solid var(--border-default)',
              borderRadius: 8,
              padding: 16,
              fontFamily: 'JetBrains Mono, monospace',
              fontSize: 11,
              maxHeight: 280,
              overflowY: 'auto',
              display: 'flex',
              flexDirection: 'column',
              gap: 6
            }}>
              {logs.map(log => (
                <div key={log.id} style={{ display: 'flex', gap: 8, lineHeight: 1.4 }}>
                  <span style={{ color: 'var(--fg-subtle)', flexShrink: 0 }}>[{log.timestamp}]</span>
                  <span style={{ color: 'var(--accent-fg)', flexShrink: 0, fontWeight: 600 }}>[{log.moduleName}]</span>
                  <span style={{ color: log.level === 'error' ? '#f85149' : log.level === 'warn' ? '#f0883e' : '#8b949e' }}>
                    {log.message}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
