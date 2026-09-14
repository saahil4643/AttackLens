"""
Framework Detection Service for AttackLens SAST

Identifies backend and frontend frameworks using static file inspection,
dependency manifests, configuration structures, and source-code signatures.
Zero dynamic execution.
"""

import os
import json
import re
from typing import List, Dict, Any, Set


FRAMEWORK_DEFINITIONS = [
    # ── Python ──
    {
        "name": "Django",
        "language": "Python",
        "type": "Backend / Full-Stack",
        "manifest_keys": ["django"],
        "file_patterns": ["manage.py", "settings.py", "wsgi.py", "asgi.py"],
        "code_regex": [r"from django", r"import django", r"DJANGO_SETTINGS_MODULE"]
    },
    {
        "name": "Flask",
        "language": "Python",
        "type": "Backend Microframework",
        "manifest_keys": ["flask"],
        "file_patterns": ["app.py", "wsgi.py"],
        "code_regex": [r"from flask import", r"Flask\(__name__\)", r"import flask"]
    },
    {
        "name": "FastAPI",
        "language": "Python",
        "type": "Backend Async API",
        "manifest_keys": ["fastapi"],
        "file_patterns": ["main.py", "app.py"],
        "code_regex": [r"from fastapi import", r"FastAPI\(\)", r"import fastapi"]
    },
    {
        "name": "Tornado",
        "language": "Python",
        "type": "Backend Async",
        "manifest_keys": ["tornado"],
        "file_patterns": [],
        "code_regex": [r"import tornado", r"tornado\.web\.Application"]
    },

    # ── JavaScript / TypeScript ──
    {
        "name": "React",
        "language": "JavaScript / TypeScript",
        "type": "Frontend Library",
        "manifest_keys": ["react", "react-dom"],
        "file_patterns": [],
        "code_regex": [r"import React", r"from ['\"]react['\"]", r"useState\(", r"useEffect\("]
    },
    {
        "name": "Next.js",
        "language": "JavaScript / TypeScript",
        "type": "Full-Stack React Framework",
        "manifest_keys": ["next"],
        "file_patterns": ["next.config.js", "next.config.mjs", "next.config.ts"],
        "code_regex": [r"from ['\"]next/", r"next/router", r"next/link", r"next/server"]
    },
    {
        "name": "Express",
        "language": "JavaScript / TypeScript",
        "type": "Backend Web Framework",
        "manifest_keys": ["express"],
        "file_patterns": [],
        "code_regex": [r"require\(['\"]express['\"]", r"import express from ['\"]express['\"]", r"express\(\)"]
    },
    {
        "name": "NestJS",
        "language": "TypeScript",
        "type": "Backend Architecture Framework",
        "manifest_keys": ["@nestjs/core", "@nestjs/common"],
        "file_patterns": ["nest-cli.json"],
        "code_regex": [r"@nestjs/core", r"@Controller\(", r"@Injectable\("]
    },
    {
        "name": "Vue",
        "language": "JavaScript / TypeScript",
        "type": "Frontend Framework",
        "manifest_keys": ["vue", "nuxt"],
        "file_patterns": ["vue.config.js", "nuxt.config.js", "nuxt.config.ts"],
        "code_regex": [r"createApp\(", r"from ['\"]vue['\"]"]
    },
    {
        "name": "Angular",
        "language": "TypeScript",
        "type": "Frontend Framework",
        "manifest_keys": ["@angular/core"],
        "file_patterns": ["angular.json"],
        "code_regex": [r"@angular/core", r"@Component\("]
    },
    {
        "name": "Fastify",
        "language": "JavaScript / TypeScript",
        "type": "Backend Web Framework",
        "manifest_keys": ["fastify"],
        "file_patterns": [],
        "code_regex": [r"require\(['\"]fastify['\"]", r"import fastify from ['\"]fastify['\"]"]
    },

    # ── Java ──
    {
        "name": "Spring Boot",
        "language": "Java",
        "type": "Backend Enterprise Framework",
        "manifest_keys": ["spring-boot", "spring-boot-starter-web", "org.springframework.boot"],
        "file_patterns": ["application.properties", "application.yml", "application.yaml"],
        "code_regex": [r"@SpringBootApplication", r"@RestController", r"@Autowired", r"org\.springframework"]
    },
    {
        "name": "Struts",
        "language": "Java",
        "type": "Backend MVC",
        "manifest_keys": ["struts2-core", "struts-core"],
        "file_patterns": ["struts.xml"],
        "code_regex": [r"org\.apache\.struts2", r"extends ActionSupport"]
    },

    # ── PHP ──
    {
        "name": "Laravel",
        "language": "PHP",
        "type": "Backend Full-Stack",
        "manifest_keys": ["laravel/framework"],
        "file_patterns": ["artisan"],
        "code_regex": [r"Illuminate\\", r"Route::get\(", r"Route::post\("]
    },
    {
        "name": "Symfony",
        "language": "PHP",
        "type": "Backend Framework",
        "manifest_keys": ["symfony/framework-bundle", "symfony/symfony"],
        "file_patterns": ["bin/console", "symfony.lock"],
        "code_regex": [r"Symfony\\Component", r"Symfony\\Bundle"]
    },
    {
        "name": "WordPress",
        "language": "PHP",
        "type": "CMS / Platform",
        "manifest_keys": ["johnpbloch/wordpress"],
        "file_patterns": ["wp-config.php", "wp-load.php"],
        "code_regex": [r"add_action\(", r"add_filter\(", r"wp_enqueue_script"]
    },

    # ── Ruby ──
    {
        "name": "Ruby on Rails",
        "language": "Ruby",
        "type": "Backend Full-Stack",
        "manifest_keys": ["rails"],
        "file_patterns": ["config/routes.rb", "bin/rails"],
        "code_regex": [r"Rails\.application", r"ActiveRecord::Base"]
    },
    {
        "name": "Sinatra",
        "language": "Ruby",
        "type": "Backend Microframework",
        "manifest_keys": ["sinatra"],
        "file_patterns": [],
        "code_regex": [r"require ['\"]sinatra['\"]", r"Sinatra::Base"]
    },

    # ── .NET ──
    {
        "name": "ASP.NET Core",
        "language": "C#",
        "type": "Backend Web Framework",
        "manifest_keys": ["Microsoft.AspNetCore"],
        "file_patterns": ["appsettings.json", "Program.cs"],
        "code_regex": [r"Microsoft\.AspNetCore", r"WebApplication\.CreateBuilder", r"services\.AddControllers"]
    },

    # ── Go ──
    {
        "name": "Gin",
        "language": "Go",
        "type": "Backend Web Framework",
        "manifest_keys": ["github.com/gin-gonic/gin"],
        "file_patterns": [],
        "code_regex": [r"github\.com/gin-gonic/gin", r"gin\.Default\(\)"]
    },
    {
        "name": "Echo",
        "language": "Go",
        "type": "Backend Web Framework",
        "manifest_keys": ["github.com/labstack/echo"],
        "file_patterns": [],
        "code_regex": [r"github\.com/labstack/echo", r"echo\.New\(\)"]
    },
    {
        "name": "Fiber",
        "language": "Go",
        "type": "Backend Web Framework",
        "manifest_keys": ["github.com/gofiber/fiber"],
        "file_patterns": [],
        "code_regex": [r"github\.com/gofiber/fiber", r"fiber\.New\(\)"]
    },

    # ── Rust ──
    {
        "name": "Actix-web",
        "language": "Rust",
        "type": "Backend Web Framework",
        "manifest_keys": ["actix-web"],
        "file_patterns": [],
        "code_regex": [r"actix_web", r"HttpServer::new"]
    },
    {
        "name": "Axum",
        "language": "Rust",
        "type": "Backend Web Framework",
        "manifest_keys": ["axum"],
        "file_patterns": [],
        "code_regex": [r"axum::Router", r"use axum"]
    }
]


def detect_frameworks(
    workspace_path: str,
    inventory_items: List[Dict[str, Any]],
    manifest_dependencies: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Detects active frameworks in the project by matching dependencies, file structures,
    and source signatures.
    """
    canonical_workspace = os.path.realpath(workspace_path)
    detected: List[Dict[str, Any]] = []
    detected_names: Set[str] = set()

    # Extract all dep names lowercase
    dep_names = {d.get("name", "").lower() for d in manifest_dependencies if d.get("name")}

    # Extract all relative file paths lowercase
    rel_paths = {item.get("path", "").lower() for item in inventory_items}
    base_filenames = {os.path.basename(item.get("path", "")).lower() for item in inventory_items}

    # Helper to check file existence
    def file_exists(pat: str) -> bool:
        pat_lower = pat.lower()
        if pat_lower in rel_paths or pat_lower in base_filenames:
            return True
        for p in rel_paths:
            if p.endswith("/" + pat_lower) or p == pat_lower:
                return True
        return False

    # Check each framework definition
    for fw in FRAMEWORK_DEFINITIONS:
        name = fw["name"]
        matched = False
        evidence_list = []
        confidence = 0.70

        # 1. Check dependencies
        for key in fw.get("manifest_keys", []):
            k_lower = key.lower()
            if any(k_lower == d or k_lower in d for d in dep_names):
                matched = True
                confidence = 0.95
                evidence_list.append(f"Dependency declared in manifest: '{key}'")
                break

        # 2. Check characteristic file patterns
        for fp in fw.get("file_patterns", []):
            if file_exists(fp):
                matched = True
                confidence = max(confidence, 0.85)
                evidence_list.append(f"Structure artifact found: '{fp}'")

        # 3. If not already high confidence, inspect a sample of relevant source files
        if not matched or confidence < 0.90:
            relevant_items = [
                it for it in inventory_items
                if it.get("category") in {"source", "configuration"}
                and it.get("size", 0) < 500 * 1024  # under 500KB
            ][:40]

            for it in relevant_items:
                full_path = os.path.join(canonical_workspace, it["path"])
                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        for regex_pat in fw.get("code_regex", []):
                            if re.search(regex_pat, content):
                                matched = True
                                confidence = max(confidence, 0.90)
                                evidence_list.append(f"Source signature matched in '{it['path']}'")
                                break
                except Exception:
                    continue

                if confidence >= 0.90:
                    break

        if matched and name not in detected_names:
            detected_names.add(name)
            detected.append({
                "name": name,
                "language": fw["language"],
                "type": fw["type"],
                "confidence": round(confidence, 2),
                "evidence": evidence_list[:3]
            })

    return detected
