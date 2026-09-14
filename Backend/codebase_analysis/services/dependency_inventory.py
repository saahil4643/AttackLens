"""
Dependency Inventory Service for AttackLens SAST

Parses dependency manifests statically without executing package managers:
- requirements.txt, pyproject.toml, Pipfile (Python / PyPI)
- package.json, package-lock.json (Node / npm)
- pom.xml, build.gradle (Java / Maven / Gradle)
- Gemfile (Ruby / RubyGems)
- composer.json (PHP / Packagist)
- go.mod (Go modules)
- Cargo.toml (Rust / Crates.io)
"""

import os
import re
import json
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Set


def parse_requirements_txt(content: str, source_path: str) -> List[Dict[str, Any]]:
    """Parses standard Python requirements.txt."""
    dependencies = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-r") or line.startswith("-i") or line.startswith("--"):
            continue
        
        # Split on comments
        line = line.split("#")[0].strip()
        if not line:
            continue

        # Match package name and version specification
        match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*(?:([><=~!^]+)\s*([a-zA-Z0-9_\-\.\*]+))?", line)
        if match:
            pkg_name = match.group(1)
            op = match.group(2) or ""
            ver = match.group(3) or ""
            version_str = f"{op}{ver}".strip() if op or ver else "any"
            dependencies.append({
                "name": pkg_name,
                "version": version_str,
                "source": source_path,
                "ecosystem": "PyPI",
                "scope": "runtime"
            })
    return dependencies


def parse_package_json(content: str, source_path: str) -> List[Dict[str, Any]]:
    """Parses Node.js package.json."""
    dependencies = []
    try:
        data = json.loads(content)
        deps = data.get("dependencies", {})
        dev_deps = data.get("devDependencies", {})
        peer_deps = data.get("peerDependencies", {})

        if isinstance(deps, dict):
            for name, ver in deps.items():
                dependencies.append({
                    "name": str(name),
                    "version": str(ver),
                    "source": source_path,
                    "ecosystem": "npm",
                    "scope": "runtime"
                })

        if isinstance(dev_deps, dict):
            for name, ver in dev_deps.items():
                dependencies.append({
                    "name": str(name),
                    "version": str(ver),
                    "source": source_path,
                    "ecosystem": "npm",
                    "scope": "development"
                })

        if isinstance(peer_deps, dict):
            for name, ver in peer_deps.items():
                dependencies.append({
                    "name": str(name),
                    "version": str(ver),
                    "source": source_path,
                    "ecosystem": "npm",
                    "scope": "peer"
                })
    except Exception:
        pass
    return dependencies


def parse_pom_xml(content: str, source_path: str) -> List[Dict[str, Any]]:
    """Parses Maven pom.xml."""
    dependencies = []
    try:
        # Strip XML namespaces for simpler tag matching
        clean_xml = re.sub(r'\sxmlns="[^"]+"', '', content, count=1)
        root = ET.fromstring(clean_xml)
        for dep in root.findall(".//dependency"):
            group_id = dep.findtext("groupId", "").strip()
            artifact_id = dep.findtext("artifactId", "").strip()
            version = dep.findtext("version", "unknown").strip()
            scope = dep.findtext("scope", "compile").strip()

            if artifact_id:
                name = f"{group_id}:{artifact_id}" if group_id else artifact_id
                dependencies.append({
                    "name": name,
                    "version": version,
                    "source": source_path,
                    "ecosystem": "Maven",
                    "scope": scope
                })
    except Exception:
        pass
    return dependencies


def parse_composer_json(content: str, source_path: str) -> List[Dict[str, Any]]:
    """Parses PHP composer.json."""
    dependencies = []
    try:
        data = json.loads(content)
        for scope, key in [("runtime", "require"), ("development", "require-dev")]:
            deps = data.get(key, {})
            if isinstance(deps, dict):
                for name, ver in deps.items():
                    if name.lower() == "php":
                        continue
                    dependencies.append({
                        "name": str(name),
                        "version": str(ver),
                        "source": source_path,
                        "ecosystem": "Packagist",
                        "scope": scope
                    })
    except Exception:
        pass
    return dependencies


def parse_gemfile(content: str, source_path: str) -> List[Dict[str, Any]]:
    """Parses Ruby Gemfile."""
    dependencies = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r'''^\s*gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?''', line)
        if match:
            gem_name = match.group(1)
            gem_ver = match.group(2) or "any"
            dependencies.append({
                "name": gem_name,
                "version": gem_ver,
                "source": source_path,
                "ecosystem": "RubyGems",
                "scope": "runtime"
            })
    return dependencies


def parse_go_mod(content: str, source_path: str) -> List[Dict[str, Any]]:
    """Parses Go go.mod."""
    dependencies = []
    in_require_block = False
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("//"):
            continue

        if line.startswith("require ("):
            in_require_block = True
            continue
        if in_require_block:
            if line == ")":
                in_require_block = False
                continue
            parts = line.split()
            if len(parts) >= 2:
                dependencies.append({
                    "name": parts[0],
                    "version": parts[1],
                    "source": source_path,
                    "ecosystem": "Go",
                    "scope": "runtime"
                })
        elif line.startswith("require "):
            parts = line[len("require "):].strip().split()
            if len(parts) >= 2:
                dependencies.append({
                    "name": parts[0],
                    "version": parts[1],
                    "source": source_path,
                    "ecosystem": "Go",
                    "scope": "runtime"
                })
    return dependencies


def parse_cargo_toml(content: str, source_path: str) -> List[Dict[str, Any]]:
    """Parses Rust Cargo.toml."""
    dependencies = []
    current_section = ""
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current_section = line[1:-1].strip()
            continue

        if current_section in {"dependencies", "dev-dependencies", "build-dependencies"}:
            scope = "development" if "dev" in current_section else "runtime"
            if "=" in line:
                key, val = line.split("=", 1)
                name = key.strip().strip('"').strip("'")
                val_str = val.strip()
                version = "any"
                if val_str.startswith('"') or val_str.startswith("'"):
                    version = val_str.strip('"').strip("'")
                elif "version" in val_str:
                    v_match = re.search(r'version\s*=\s*["\']([^"\']+)["\']', val_str)
                    if v_match:
                        version = v_match.group(1)
                
                dependencies.append({
                    "name": name,
                    "version": version,
                    "source": source_path,
                    "ecosystem": "Crates.io",
                    "scope": scope
                })
    return dependencies


def scan_dependencies(workspace_path: str, inventory_items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Scans and aggregates all third-party dependencies declared across manifest files.
    """
    canonical_workspace = os.path.realpath(workspace_path)
    all_deps: List[Dict[str, Any]] = []
    seen: Set[str] = set()

    for item in inventory_items:
        if item.get("category") != "dependency" and not any(
            item.get("name", "").lower() == m.lower()
            for m in ["requirements.txt", "package.json", "pom.xml", "composer.json", "gemfile", "go.mod", "cargo.toml"]
        ):
            continue

        rel_path = item["path"]
        full_path = os.path.join(canonical_workspace, rel_path)
        base_name = os.path.basename(rel_path).lower()

        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            continue

        deps = []
        if base_name in {"requirements.txt", "requirements-dev.txt", "requirements-prod.txt"}:
            deps = parse_requirements_txt(content, rel_path)
        elif base_name == "package.json":
            deps = parse_package_json(content, rel_path)
        elif base_name == "pom.xml":
            deps = parse_pom_xml(content, rel_path)
        elif base_name == "composer.json":
            deps = parse_composer_json(content, rel_path)
        elif base_name in {"gemfile", "gemfile.lock"}:
            deps = parse_gemfile(content, rel_path)
        elif base_name == "go.mod":
            deps = parse_go_mod(content, rel_path)
        elif base_name == "cargo.toml":
            deps = parse_cargo_toml(content, rel_path)

        for d in deps:
            key = f"{d['ecosystem']}:{d['name']}:{d['version']}"
            if key not in seen:
                seen.add(key)
                all_deps.append(d)

    return all_deps
