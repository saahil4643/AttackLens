"""
Project Inventory and Language Detection Service for AttackLens SAST

Scans workspace files to build a structured inventory:
- File path, size, language, category (source, config, dependency, test, static, binary, doc, unknown)
- Language distribution calculation
- Safe handling of test files and vendor exclusions
"""

import os
from typing import Dict, List, Any, Set, Tuple

# Extension to Language mapping
EXTENSION_LANGUAGE_MAP = {
    # Python
    ".py": "Python",
    ".pyw": "Python",
    ".wsgi": "Python",
    ".asgi": "Python",
    # JavaScript / TypeScript
    ".js": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    # Java & JVM
    ".java": "Java",
    ".kt": "Kotlin",
    ".kts": "Kotlin",
    ".scala": "Scala",
    ".groovy": "Groovy",
    # C / C++ / C#
    ".c": "C",
    ".h": "C",
    ".cpp": "C++",
    ".cc": "C++",
    ".cxx": "C++",
    ".hpp": "C++",
    ".cs": "C#",
    # PHP
    ".php": "PHP",
    ".phtml": "PHP",
    ".php5": "PHP",
    ".php7": "PHP",
    ".php8": "PHP",
    # Ruby
    ".rb": "Ruby",
    ".rake": "Ruby",
    # Go
    ".go": "Go",
    # Rust
    ".rs": "Rust",
    # Swift / Obj-C
    ".swift": "Swift",
    ".m": "Objective-C",
    # Web / Markup / Style
    ".html": "HTML",
    ".htm": "HTML",
    ".css": "CSS",
    ".scss": "SCSS",
    ".sass": "Sass",
    ".less": "Less",
    # SQL
    ".sql": "SQL",
    # Shell
    ".sh": "Shell",
    ".bash": "Shell",
    ".zsh": "Shell",
    ".bat": "Batch",
    ".cmd": "Batch",
    ".ps1": "PowerShell",
    # Configuration / Structured
    ".json": "JSON",
    ".yaml": "YAML",
    ".yml": "YAML",
    ".toml": "TOML",
    ".xml": "XML",
    ".ini": "INI",
    ".env": "Env",
    ".properties": "Properties",
    ".conf": "Config",
    # Documentation
    ".md": "Markdown",
    ".rst": "ReStructuredText",
    ".txt": "Text",
}

# Binary extensions to skip reading as source
BINARY_EXTENSIONS = {
    ".exe", ".dll", ".so", ".dylib", ".bin", ".class", ".jar", ".war",
    ".ear", ".pyc", ".pyo", ".pyd", ".o", ".obj", ".a", ".lib",
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".pdf",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar", ".iso",
    ".ttf", ".otf", ".woff", ".woff2", ".eot", ".mp4", ".mp3", ".wav"
}

# Manifest filenames for dependency inventory
DEPENDENCY_MANIFEST_FILENAMES = {
    "requirements.txt", "pyproject.toml", "pipfile", "pipfile.lock", "setup.py",
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "pom.xml", "build.gradle", "build.gradle.kts",
    "gemfile", "gemfile.lock",
    "composer.json", "composer.lock",
    "go.mod", "go.sum",
    "cargo.toml", "cargo.lock"
}

# Default directories excluded from deep AST/vulnerability scans
DEFAULT_EXCLUDED_DIRS = {
    "node_modules", "vendor", "dist", "build", ".git", ".svn", ".hg",
    "coverage", ".cache", "__pycache__", ".venv", "venv", "env",
    ".idea", ".vscode", "target", "bin", "obj", ".next", ".nuxt",
    ".pytest_cache", ".mypy_cache", ".tox"
}


def is_test_file(rel_path: str) -> bool:
    """Detects whether a file path belongs to a test suite."""
    p_lower = rel_path.lower().replace("\\", "/")
    parts = p_lower.split("/")
    
    # Check directory names
    test_dirs = {"test", "tests", "__tests__", "spec", "specs", "testing", "fixtures"}
    if any(part in test_dirs for part in parts[:-1]):
        return True

    filename = parts[-1]
    if (
        filename.startswith("test_")
        or filename.endswith("_test.py")
        or filename.endswith(".test.js")
        or filename.endswith(".test.ts")
        or filename.endswith(".test.jsx")
        or filename.endswith(".test.tsx")
        or filename.endswith(".spec.js")
        or filename.endswith(".spec.ts")
        or filename.endswith(".spec.jsx")
        or filename.endswith(".spec.tsx")
        or filename.endswith("_test.go")
        or filename.endswith("test.java")
        or filename.endswith("tests.java")
        or filename.endswith("spec.rb")
    ):
        return True

    return False


def categorize_file(rel_path: str, ext: str, size: int) -> str:
    """Categorizes a file into source, test, config, dependency, static, doc, binary, or unknown."""
    lower_path = rel_path.lower().replace("\\", "/")
    filename = os.path.basename(lower_path)

    if ext in BINARY_EXTENSIONS:
        return "binary"

    if filename in DEPENDENCY_MANIFEST_FILENAMES or filename.endswith(".csproj") or filename.endswith(".fsproj"):
        return "dependency"

    if is_test_file(rel_path):
        return "test"

    if ext in {".json", ".yaml", ".yml", ".toml", ".xml", ".ini", ".conf", ".properties", ".env"} or filename.startswith(".env"):
        return "configuration"

    if filename in {"dockerfile", "docker-compose.yml", "docker-compose.yaml", "makefile", "procfile", "vagrantfile"}:
        return "configuration"

    if ext in {".html", ".htm", ".css", ".scss", ".sass", ".less", ".svg"}:
        return "static"

    if ext in {".md", ".rst", ".txt"} or filename.startswith("readme") or filename.startswith("license") or filename.startswith("changelog"):
        return "documentation"

    if ext in EXTENSION_LANGUAGE_MAP:
        return "source"

    return "unknown"


def detect_language(rel_path: str, ext: str, sample_content: str = "") -> str:
    """Determines the programming or scripting language of a file."""
    filename = os.path.basename(rel_path).lower()

    if filename == "dockerfile" or filename.startswith("dockerfile."):
        return "Dockerfile"
    if filename == "makefile":
        return "Makefile"
    if filename == "gemfile":
        return "Ruby"
    if filename in {"jenkinsfile", "vagrantfile"}:
        return "Groovy"

    lang = EXTENSION_LANGUAGE_MAP.get(ext)
    if lang:
        return lang

    # Content-based heuristics for extensionless scripts (e.g. #!/usr/bin/env python)
    if sample_content:
        first_line = sample_content.split("\n", 1)[0].lower()
        if first_line.startswith("#!"):
            if "python" in first_line:
                return "Python"
            if "node" in first_line or "javascript" in first_line:
                return "JavaScript"
            if "bash" in first_line or "sh" in first_line:
                return "Shell"
            if "perl" in first_line:
                return "Perl"
            if "ruby" in first_line:
                return "Ruby"
            if "php" in first_line:
                return "PHP"

    return "Unknown"


def scan_project_inventory(
    workspace_path: str,
    excluded_dirs: Set[str] = None
) -> Dict[str, Any]:
    """
    Builds a complete file inventory and statistical breakdown of the extracted codebase.
    """
    if excluded_dirs is None:
        excluded_dirs = DEFAULT_EXCLUDED_DIRS

    inventory: List[Dict[str, Any]] = []
    language_counts: Dict[str, int] = {}
    language_bytes: Dict[str, int] = {}
    category_counts: Dict[str, int] = {}
    total_files = 0
    total_source_files = 0
    total_bytes = 0
    skipped_large_files = 0

    canonical_workspace = os.path.realpath(workspace_path)

    for root, dirs, files in os.walk(canonical_workspace):
        rel_root = os.path.relpath(root, canonical_workspace).replace("\\", "/")
        root_parts = rel_root.split("/") if rel_root != "." else []

        # Check if current directory is inside an excluded directory
        is_excluded = any(part.lower() in excluded_dirs for part in root_parts)

        # Prune child directories for performance, but keep shallow manifest exploration
        dirs[:] = [d for d in dirs if d.lower() not in excluded_dirs]

        for file in files:
            total_files += 1
            full_path = os.path.join(root, file)
            rel_file_path = os.path.relpath(full_path, canonical_workspace).replace("\\", "/")
            
            try:
                file_size = os.path.getsize(full_path)
            except OSError:
                file_size = 0

            total_bytes += file_size
            _, ext = os.path.splitext(file.lower())

            # Read head sample if extensionless for language sniffing
            sample = ""
            if not ext and file_size > 0 and file_size < 1024 * 64:
                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        sample = f.read(256)
                except Exception:
                    sample = ""

            lang = detect_language(rel_file_path, ext, sample)
            cat = categorize_file(rel_file_path, ext, file_size)

            if cat == "source" or (cat == "test" and lang not in {"Unknown", "Text", "Markdown"}):
                total_source_files += 1

            # Accumulate stats
            if lang != "Unknown":
                language_counts[lang] = language_counts.get(lang, 0) + 1
                language_bytes[lang] = language_bytes.get(lang, 0) + file_size

            category_counts[cat] = category_counts.get(cat, 0) + 1

            inventory.append({
                "path": rel_file_path,
                "name": file,
                "extension": ext,
                "language": lang,
                "category": cat,
                "size": file_size,
                "is_excluded": is_excluded
            })

    # Calculate language percentages by bytes (or file count if small)
    total_lang_bytes = sum(language_bytes.values()) or 1
    languages_summary = [
        {
            "language": lang,
            "file_count": count,
            "bytes": language_bytes.get(lang, 0),
            "percentage": round((language_bytes.get(lang, 0) / total_lang_bytes) * 100, 1)
        }
        for lang, count in sorted(language_counts.items(), key=lambda x: x[1], reverse=True)
    ]

    return {
        "files_count": total_files,
        "source_files_count": total_source_files,
        "total_bytes": total_bytes,
        "languages": languages_summary,
        "categories": category_counts,
        "inventory": inventory
    }
