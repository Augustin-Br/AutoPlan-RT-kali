"""Local web-application knowledge base for safe hypothesis grounding.

The entries below do not prove exploitability. They map observed application
fingerprints to conservative, manual validation paths that can be audited in
the JSON output and paper experiments.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class ApplicationKnowledgeEntry:
    kb_id: str
    label: str
    match_tokens: tuple[str, ...]
    path_tokens: tuple[str, ...]
    version_patterns: tuple[str, ...]
    risk_type: str
    impact_template: str
    validation_focus: str


@dataclass(frozen=True)
class ApplicationKnowledgeMatch:
    entry: ApplicationKnowledgeEntry
    paths: tuple[str, ...]
    versions: tuple[str, ...]


APP_KNOWLEDGE_BASE: tuple[ApplicationKnowledgeEntry, ...] = (
    ApplicationKnowledgeEntry(
        kb_id="phpmyadmin_exposed_admin",
        label="phpMyAdmin",
        match_tokens=("phpmyadmin",),
        path_tokens=("phpmyadmin",),
        version_patterns=(r"\bphpmyadmin[ /]*(?P<version>\d+(?:\.\d+){1,4})\b",),
        risk_type="database administration exposure",
        impact_template="Possible exposed database administration surface on {label}{target}; manual validation required",
        validation_focus="Validate access controls, exposed setup pages, default paths, and version-specific public advisories.",
    ),
    ApplicationKnowledgeEntry(
        kb_id="tomcat_manager_exposure",
        label="Apache Tomcat Manager",
        match_tokens=("apache tomcat", "tomcat manager", "/manager/html"),
        path_tokens=("manager", "tomcat"),
        version_patterns=(r"\btomcat[ /]*(?P<version>\d+(?:\.\d+){1,4})\b",),
        risk_type="application manager exposure",
        impact_template="Possible Tomcat manager/admin exposure on {label}{target}; manual validation required",
        validation_focus="Validate manager exposure and access policy without login attempts or deployment attempts.",
    ),
    ApplicationKnowledgeEntry(
        kb_id="jenkins_admin_exposure",
        label="Jenkins",
        match_tokens=("jenkins", "x-jenkins"),
        path_tokens=("jenkins",),
        version_patterns=(r"\bjenkins[ /]*(?P<version>\d+(?:\.\d+){1,4})\b", r"\bx-jenkins[:= ]+(?P<version>\d+(?:\.\d+){1,4})\b"),
        risk_type="CI administration exposure",
        impact_template="Possible Jenkins administration exposure on {label}{target}; manual validation required",
        validation_focus="Validate anonymous access, exposed build metadata, plugin/version clues, and access policy.",
    ),
    ApplicationKnowledgeEntry(
        kb_id="jboss_admin_console",
        label="JBoss administration console",
        match_tokens=("jboss", "jmx-console", "web-console"),
        path_tokens=("jmx-console", "web-console", "jboss"),
        version_patterns=(r"\bjboss[ /]*(?P<version>\d+(?:\.\d+){1,4})\b",),
        risk_type="application server console exposure",
        impact_template="Possible JBoss console exposure on {label}{target}; manual validation required",
        validation_focus="Validate console exposure and version clues without deploying payloads.",
    ),
    ApplicationKnowledgeEntry(
        kb_id="webmin_admin_exposure",
        label="Webmin",
        match_tokens=("webmin",),
        path_tokens=("webmin",),
        version_patterns=(r"\bwebmin[ /]*(?P<version>\d+(?:\.\d+){1,4})\b",),
        risk_type="web administration exposure",
        impact_template="Possible Webmin administration exposure on {label}{target}; manual validation required",
        validation_focus="Validate exposure, TLS/certificate clues, version, and access policy.",
    ),
    ApplicationKnowledgeEntry(
        kb_id="wordpress_cms_surface",
        label="WordPress",
        match_tokens=("wordpress", "wp-content", "wp-includes", "wp-login.php"),
        path_tokens=("wp-admin", "wp-content", "wp-login"),
        version_patterns=(r"\bwordpress[ /]*(?P<version>\d+(?:\.\d+){1,4})\b",),
        risk_type="CMS/plugin attack surface",
        impact_template="Possible WordPress CMS/plugin attack surface on {label}{target}; manual validation required",
        validation_focus="Enumerate core/plugin/theme versions and access policy; do not assume a plugin CVE without evidence.",
    ),
    ApplicationKnowledgeEntry(
        kb_id="drupal_cms_surface",
        label="Drupal",
        match_tokens=("drupal", "sites/default", "drupal.settings"),
        path_tokens=("drupal", "sites/default"),
        version_patterns=(r"\bdrupal[ /]*(?P<version>\d+(?:\.\d+){1,4})\b",),
        risk_type="CMS attack surface",
        impact_template="Possible Drupal CMS attack surface on {label}{target}; manual validation required",
        validation_focus="Validate Drupal version/module clues and map only observed versions to public advisories.",
    ),
    ApplicationKnowledgeEntry(
        kb_id="joomla_cms_surface",
        label="Joomla",
        match_tokens=("joomla", "com_content", "/administrator"),
        path_tokens=("administrator", "joomla"),
        version_patterns=(r"\bjoomla[! /]*(?P<version>\d+(?:\.\d+){1,4})\b",),
        risk_type="CMS administration/plugin attack surface",
        impact_template="Possible Joomla CMS/admin attack surface on {label}{target}; manual validation required",
        validation_focus="Validate administrator exposure and extension/core version clues before mapping advisories.",
    ),
    ApplicationKnowledgeEntry(
        kb_id="laravel_debug_or_env",
        label="Laravel/PHP application",
        match_tokens=("laravel", "app_key", ".env", "whoops"),
        path_tokens=(".env", "debug", "laravel"),
        version_patterns=(r"\blaravel[ /]*(?P<version>\d+(?:\.\d+){1,4})\b",),
        risk_type="debug/configuration disclosure",
        impact_template="Possible Laravel/PHP debug or configuration disclosure on {label}{target}; manual validation required",
        validation_focus="Validate exposed debug pages, .env/config leakage, and framework version clues.",
    ),
    ApplicationKnowledgeEntry(
        kb_id="nextjs_application_surface",
        label="Next.js application",
        match_tokens=("next.js", "nextjs", "x-nextjs", "next-router", "/_next/"),
        path_tokens=("_next", "api"),
        version_patterns=(r"\bnext\.js[ /]*(?P<version>\d+(?:\.\d+){1,4})\b",),
        risk_type="client-side route/API surface",
        impact_template="Possible Next.js application route/API surface on {label}{target}; manual validation required",
        validation_focus="Map observed routes, static asset metadata, API endpoints, and access-control boundaries without state-changing requests.",
    ),
    ApplicationKnowledgeEntry(
        kb_id="git_config_disclosure",
        label="exposed Git metadata",
        match_tokens=("/.git/config", "[core]", "repositoryformatversion"),
        path_tokens=(".git/config",),
        version_patterns=(),
        risk_type="source/configuration disclosure",
        impact_template="Possible exposed Git metadata/source disclosure{target}; manual validation required",
        validation_focus="Validate whether Git metadata is readable; do not attempt repository dumping automatically.",
    ),
    ApplicationKnowledgeEntry(
        kb_id="phpinfo_disclosure",
        label="phpinfo/debug page",
        match_tokens=("phpinfo()", "php version", "/phpinfo"),
        path_tokens=("phpinfo",),
        version_patterns=(r"\bphp version (?P<version>\d+(?:\.\d+){1,4})\b", r"\bphp/(?P<version>\d+(?:\.\d+){1,4})\b"),
        risk_type="environment disclosure",
        impact_template="Possible PHP environment disclosure on {label}{target}; manual validation required",
        validation_focus="Validate exposed environment details, paths, modules, and versions.",
    ),
    ApplicationKnowledgeEntry(
        kb_id="apache_server_status",
        label="Apache server-status",
        match_tokens=("server-status", "apache server status"),
        path_tokens=("server-status",),
        version_patterns=(),
        risk_type="server-status access-control validation",
        impact_template="Apache server-status access-control validation on {label}{target}; manual validation required",
        validation_focus="Validate the observed status and access controls; treat 403 as protected configuration, not metadata disclosure.",
    ),
    ApplicationKnowledgeEntry(
        kb_id="werkzeug_debug_console",
        label="Werkzeug debugger",
        match_tokens=("werkzeug", "console locked", "debugger active"),
        path_tokens=("console", "debug"),
        version_patterns=(r"\bwerkzeug[ /]*(?P<version>\d+(?:\.\d+){1,4})\b",),
        risk_type="debug console exposure",
        impact_template="Possible Werkzeug debug console exposure on {label}{target}; manual validation required",
        validation_focus="Validate debug console exposure and do not attempt PIN bypass automatically.",
    ),
    ApplicationKnowledgeEntry(
        kb_id="swagger_api_docs",
        label="Swagger/OpenAPI documentation",
        match_tokens=("swagger", "openapi", "api-docs"),
        path_tokens=("swagger", "api-docs", "openapi"),
        version_patterns=(r"\bopenapi[ /]*(?P<version>\d+(?:\.\d+){1,4})\b",),
        risk_type="API documentation exposure",
        impact_template="Possible API documentation exposure on {label}{target}; manual validation required",
        validation_focus="Validate exposed API routes and authentication boundaries without invoking state-changing operations.",
    ),
)

WEB_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])(?P<path>/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+/?)(?=(?:\.(?:\s|$))|[\s,;)]|$)"
)


def match_application_knowledge(notes: str | None) -> list[ApplicationKnowledgeMatch]:
    if not notes:
        return []
    text = notes.lower()
    paths = _web_paths_from_notes(notes)
    matches: list[ApplicationKnowledgeMatch] = []
    for entry in APP_KNOWLEDGE_BASE:
        if not any(token.lower() in text for token in entry.match_tokens):
            continue
        candidate_paths = tuple(
            path
            for path in paths
            if any(token.lower() in path.lower() for token in entry.path_tokens)
        )
        entry_paths = tuple(
            path
            for path in candidate_paths
            if _path_has_confirming_or_unknown_status(notes, path)
        )
        if candidate_paths and not entry_paths:
            continue
        if entry_paths and all(
            _path_has_status(notes, path, "404") or _path_is_marked_soft_404(notes, path)
            for path in entry_paths
        ):
            continue
        versions = _versions_for_entry(entry, notes)
        matches.append(ApplicationKnowledgeMatch(entry=entry, paths=entry_paths[:4], versions=versions[:3]))
    return matches


def _versions_for_entry(entry: ApplicationKnowledgeEntry, notes: str) -> tuple[str, ...]:
    versions: list[str] = []
    label = entry.label[:-4] if entry.label.endswith(" 2.x") else entry.label
    for pattern in entry.version_patterns:
        for match in re.finditer(pattern, notes, re.IGNORECASE):
            version = match.groupdict().get("version")
            if version:
                versions.append(f"{label} {version}")
    return tuple(dict.fromkeys(versions))


def _web_paths_from_notes(notes: str) -> tuple[str, ...]:
    paths = []
    for match in WEB_PATH_RE.finditer(notes):
        path = _normalize_observed_path(match.group("path").rstrip(".,;)"))
        if path != "/" and _is_probable_web_path(path):
            paths.append(path)
    return tuple(dict.fromkeys(paths))


def _normalize_observed_path(path: str) -> str:
    if not path.startswith("/"):
        path = f"/{path}"
    parts = [part for part in path.split("/") if part]
    if len(parts) >= 2 and _looks_like_host(parts[0]):
        normalized = "/" + "/".join(parts[1:])
        return f"{normalized}/" if path.endswith("/") and not normalized.endswith("/") else normalized
    return path


def _looks_like_host(value: str) -> bool:
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", value):
        return True
    return bool(re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", value, re.IGNORECASE))


def _is_probable_web_path(path: str) -> bool:
    lowered = path.lower()
    if lowered in {"/lfi-style", "/path-disclosure", "/file-inclusion", "/path", "/file"}:
        return False
    first_segment = lowered.strip("/").split("/", 1)[0]
    if _looks_like_host(first_segment):
        return False
    if re.search(r"/wp-content/(?:themes|plugins)/[a-z]$", lowered):
        return False
    return first_segment not in {"lfi-style", "path-disclosure", "file-inclusion", "path", "file"}


def _path_has_status(notes: str, path: str, status: str) -> bool:
    return any(value == status.lower() for value in _path_status_values(notes, path))


def _path_has_confirming_or_unknown_status(notes: str, path: str) -> bool:
    statuses = _path_status_values(notes, path)
    if not statuses:
        return True
    return any(_is_confirming_web_status(status) for status in statuses)


def _path_status_values(notes: str, path: str) -> list[str]:
    statuses: list[str] = []
    for candidate in _path_variants(path):
        escaped = re.escape(candidate)
        pattern = rf"(?<![A-Za-z0-9_.-]){escaped}(?=$|[\s,;.)])(?P<context>[^;\n]{{0,200}}?)\bstatus=(?P<status>[A-Za-z0-9_]+)\b"
        statuses.extend(match.group("status").lower() for match in re.finditer(pattern, notes, re.IGNORECASE))
    return list(dict.fromkeys(statuses))


def _path_variants(path: str) -> list[str]:
    stripped = path.strip()
    variants = [stripped]
    if stripped != "/":
        variants.append(stripped.rstrip("/"))
        variants.append(f"{stripped.rstrip('/')}/")
    return list(dict.fromkeys(value for value in variants if value))


def _is_confirming_web_status(status: str) -> bool:
    return status in {"200", "201", "202", "204", "301", "302", "303", "307", "308", "401", "403"}


def _path_is_marked_soft_404(notes: str, path: str) -> bool:
    escaped = re.escape(path)
    return bool(re.search(rf"{escaped}\b[^;\n]*\bsoft_404=true\b", notes, re.IGNORECASE))
