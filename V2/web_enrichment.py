"""Bounded web enrichment after directory discovery."""

from __future__ import annotations

import json
import re
import hashlib
from dataclasses import dataclass
from html import unescape
from urllib import error, request
from urllib.parse import parse_qsl, urljoin, urlparse

from V2.llm_provider import build_chat_client, resolve_llm_config, response_content_to_text
from V2.recon_models import WebPageFinding


DIRB_RESULT_RE = re.compile(
    r"^(?:\+|==>\s+DIRECTORY:)\s+(?P<url>https?://\S+)(?:\s+\(CODE:(?P<status>\d+)\|SIZE:(?P<size>\d+)\))?"
)
TITLE_RE = re.compile(r"<title[^>]*>(?P<title>.*?)</title>", re.IGNORECASE | re.DOTALL)
META_GENERATOR_RE = re.compile(
    r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"'](?P<value>[^\"']+)[\"']",
    re.IGNORECASE,
)
FORM_RE = re.compile(r"<form\b(?P<attrs>[^>]*)>", re.IGNORECASE)
FORM_ACTION_RE = re.compile(r"<form\b[^>]+action=[\"'](?P<action>[^\"']+)[\"']", re.IGNORECASE)
INPUT_RE = re.compile(r"<input\b(?P<attrs>[^>]*)>", re.IGNORECASE)
LINK_RE = re.compile(r"<a\b[^>]+href=[\"'](?P<href>[^\"']+)[\"']", re.IGNORECASE)
ATTR_RE = re.compile(
    r"(?P<key>[A-Za-z_:][-A-Za-z0-9_:.]*)"
    r"(?:\s*=\s*(?:[\"'](?P<quoted>[^\"']*)[\"']|(?P<bare>[^\s\"'=<>`]+)))?",
    re.IGNORECASE,
)
META_REFRESH_RE = re.compile(
    r"<meta\b[^>]+http-equiv=[\"']?refresh[\"']?[^>]+content=[\"'][^\"']*url=(?P<url>[^\"';>]+)",
    re.IGNORECASE,
)
SCRIPT_RE = re.compile(r"<script[^>]+src=[\"'](?P<src>[^\"']+)[\"']", re.IGNORECASE)
COMMENT_RE = re.compile(r"<!--(?P<comment>.*?)-->", re.DOTALL)
VERSION_RE = re.compile(
    r"\b(?P<name>[A-Za-z][A-Za-z0-9_. -]{1,40})[/ ](?P<version>\d+(?:\.\d+){1,4}[A-Za-z0-9_.-]*)\b"
)
PATH_LIKE_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])(?P<path>/?(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+\.(?:php|html?|jsp|asp|aspx|txt|conf|ini|bak|old|sql|json))",
    re.IGNORECASE,
)
COMMENT_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])(?P<path>/(?:[A-Za-z0-9_-]{2,40}/?)(?:[A-Za-z0-9_.-]{2,60})?)\b",
    re.IGNORECASE,
)
GENERIC_INTERESTING_TOKENS = (
    "admin",
    "login",
    "dashboard",
    "api",
    "config",
    "backup",
    "upload",
    "server-status",
    "phpinfo",
    "debug",
    "console",
    "manage",
    "dev-login",
    "lfi",
    "include",
)
DEEP_WEB_SEED_PATHS = (
    "/",
    "/robots.txt",
    "/sitemap.xml",
    "/.git/config",
    "/.env",
    "/config.php",
    "/config.php.bak",
    "/backup.zip",
    "/backup.tar.gz",
    "/db.sql",
    "/admin",
    "/login",
)
TECHNOLOGY_MARKERS = (
    ("wordpress", "WordPress"),
    ("drupal", "Drupal"),
    ("joomla", "Joomla"),
    ("laravel", "Laravel"),
    ("symfony", "Symfony"),
    ("django", "Django"),
    ("flask", "Flask"),
    ("express", "Express"),
    ("tomcat", "Apache Tomcat"),
    ("phpmyadmin", "phpMyAdmin"),
)
APPLICATION_ATTACK_HINTS = (
    ("local file inclusion", "possible LFI hint observed"),
    ("lfi", "possible LFI hint observed"),
    ("file inclusion", "possible file inclusion hint observed"),
    ("include_path", "file include configuration reference observed"),
    ("dev-login", "development login path observed"),
)
SOFT_404_BASELINE_PATHS = {"/", "/index.html", "/index.php", "/home"}
SOFT_404_SENSITIVE_PATH_PREFIXES = (
    "/.env",
    "/.git/",
    "/admin",
    "/login",
    "/dev-login",
    "/dashboard",
    "/config",
    "/backup",
    "/db.",
)
ENV_CONFIG_MARKERS = (
    "app_key=",
    "app_env=",
    "app_debug=",
    "db_host=",
    "db_database=",
    "db_username=",
    "db_password=",
)
GIT_CONFIG_MARKERS = ("[core]", "repositoryformatversion", "[remote ", "worktree =", "bare =")


@dataclass(frozen=True)
class WebPathCandidate:
    url: str
    path: str
    status_code: int | None
    content_length: int | None
    hostname: str | None = None
    discovery_source: str = "dirb"


def parse_dirb_candidates(stdout: str, *, hostname: str | None = None) -> list[WebPathCandidate]:
    candidates: list[WebPathCandidate] = []
    for line in stdout.splitlines():
        match = DIRB_RESULT_RE.match(line.strip())
        if not match:
            continue
        url = match.group("url")
        candidates.append(
            WebPathCandidate(
                url=url,
                path=_path_from_url(url),
                status_code=int(match.group("status")) if match.group("status") else None,
                content_length=int(match.group("size")) if match.group("size") else None,
                hostname=hostname,
            )
        )
    return list({candidate.path: candidate for candidate in candidates}.values())


def select_web_candidates(
    candidates: list[WebPathCandidate],
    *,
    max_pages: int = 6,
    use_llm: bool = False,
    llm_model: str | None = None,
    llm_provider: str | None = None,
) -> tuple[list[WebPathCandidate], str]:
    if not candidates:
        return [], "heuristic"
    if use_llm:
        selected = _select_with_llm(
            candidates,
            max_pages=max_pages,
            llm_model=llm_model,
            llm_provider=llm_provider,
        )
        if selected:
            return _merge_mandatory_web_candidates(candidates, selected, max_pages=max_pages), "llm"
    scored = sorted(
        candidates,
        key=lambda candidate: (_candidate_score(candidate), candidate.content_length or 0, candidate.path),
        reverse=True,
    )
    return scored[: max(1, max_pages)], "heuristic"


def _merge_mandatory_web_candidates(
    candidates: list[WebPathCandidate],
    selected: list[WebPathCandidate],
    *,
    max_pages: int,
) -> list[WebPathCandidate]:
    """Keep deterministic high-signal web paths even when LLM triage is used."""
    mandatory = [candidate for candidate in candidates if _is_mandatory_web_candidate(candidate)]
    mandatory_paths = {candidate.path for candidate in mandatory}
    merged = mandatory + [candidate for candidate in selected if candidate.path not in mandatory_paths]
    if len(merged) < max_pages:
        scored = sorted(
            candidates,
            key=lambda candidate: (_candidate_score(candidate), candidate.content_length or 0, candidate.path),
            reverse=True,
        )
        seen = {candidate.path for candidate in merged}
        merged.extend(candidate for candidate in scored if candidate.path not in seen)
    limit = max(max_pages, len(mandatory))
    return list({candidate.path: candidate for candidate in merged}.values())[:limit]


def _is_mandatory_web_candidate(candidate: WebPathCandidate) -> bool:
    path = candidate.path.lower()
    if path in {"/", "/index", "/index.html", "/index.php", "/robots.txt", "/sitemap.xml"}:
        return True
    return any(
        token in path
        for token in (
            "phpmyadmin",
            "server-status",
            "wp-login",
            "wp-content",
            ".env",
            ".git/config",
            "phpinfo",
        )
    )


def fetch_web_page_findings(
    candidates: list[WebPathCandidate],
    *,
    target_ip: str,
    port: int,
    hostname: str | None,
    selected_by: str = "heuristic",
    deep: bool = False,
    max_total_pages: int | None = None,
    timeout_seconds: int = 8,
) -> list[WebPageFinding]:
    findings: list[WebPageFinding] = []
    seen_paths: set[str] = set()
    initial_candidates = candidates[:max_total_pages] if deep and max_total_pages else candidates
    for candidate in initial_candidates:
        if candidate.path in seen_paths:
            continue
        seen_paths.add(candidate.path)
        result = _fetch_page(
            candidate,
            target_ip=target_ip,
            port=port,
            hostname=hostname or candidate.hostname,
            timeout_seconds=timeout_seconds,
        )
        if result is not None:
            findings.append(
                result.model_copy(
                    update={
                        "selected_by": selected_by,
                        "discovery_source": candidate.discovery_source,
                    }
                )
            )
    if deep:
        budget = max(0, (max_total_pages or len(candidates)) - len(findings))
        pending = _deep_candidates_from_findings(
            findings,
            target_ip=target_ip,
            port=port,
            hostname=hostname,
        )
        index = 0
        while index < len(pending):
            candidate = pending[index]
            index += 1
            if budget <= 0:
                break
            if candidate.path in seen_paths:
                continue
            seen_paths.add(candidate.path)
            result = _fetch_page(
                candidate,
                target_ip=target_ip,
                port=port,
                hostname=hostname or candidate.hostname,
                timeout_seconds=timeout_seconds,
            )
            if result is None:
                continue
            findings.append(
                result.model_copy(
                    update={
                        "selected_by": "heuristic",
                        "discovery_source": candidate.discovery_source,
                    }
                )
            )
            for link in result.links:
                if link not in seen_paths:
                    pending.append(
                        WebPathCandidate(
                            url=urljoin(result.url, link),
                            path=link,
                            status_code=None,
                            content_length=None,
                            hostname=hostname or candidate.hostname,
                            discovery_source=f"link:{result.path}",
                        )
                    )
            budget -= 1
    return _with_soft_404_flags(findings)


def _fetch_page(
    candidate: WebPathCandidate,
    *,
    target_ip: str,
    port: int,
    hostname: str | None,
    timeout_seconds: int,
) -> WebPageFinding | None:
    scheme = "https" if candidate.url.startswith("https://") or port == 443 else "http"
    url = f"{scheme}://{target_ip}:{port}{candidate.path}"
    headers = {"User-Agent": "AutoPlan-RT-safe-web-enrichment"}
    if hostname:
        headers["Host"] = hostname
    req = request.Request(url, headers=headers)
    try:
        with request.urlopen(req, timeout=timeout_seconds) as response:
            body = response.read(32768)
            response_headers = {key: value for key, value in response.headers.items()}
            status_code = response.status
    except error.HTTPError as exc:
        body = exc.read(32768)
        response_headers = {key: value for key, value in exc.headers.items()}
        status_code = exc.code
    except Exception:
        return None

    text = body.decode(errors="ignore")
    forms = _extract_forms(text)
    input_fields = _extract_inputs(text)
    allowed_hosts = _allowed_link_hosts(target_ip=target_ip, port=port, hostname=hostname, candidate_url=candidate.url)
    form_actions = _extract_form_actions(text, candidate.path, allowed_hosts=allowed_hosts)
    form_methods = _extract_form_methods(text)
    form_parameters = _extract_form_parameters(text)
    query_parameters = _extract_query_parameters(text, candidate.path, allowed_hosts=allowed_hosts)
    workflow_tags = _workflow_tags(
        path=candidate.path,
        forms=forms,
        input_fields=input_fields,
        form_actions=form_actions,
        form_parameters=form_parameters,
        query_parameters=query_parameters,
    )
    low_content, low_content_reason = _low_content_assessment(text, forms=forms, input_fields=input_fields)
    links = _extract_links(text, candidate.path, allowed_hosts=allowed_hosts)
    if candidate.path == "/robots.txt":
        links.extend(_extract_robots_paths(text))
    if candidate.path == "/sitemap.xml":
        links.extend(_extract_sitemap_paths(text, allowed_hosts=allowed_hosts))
    return WebPageFinding(
        hostname=hostname,
        path=candidate.path,
        url=url,
        status_code=status_code,
        content_length=len(body),
        title=_extract_title(text),
        headers=response_headers,
        meta_generator=_extract_meta_generator(text),
        forms=forms,
        form_actions=form_actions,
        form_methods=form_methods,
        form_parameters=form_parameters,
        input_fields=input_fields,
        query_parameters=query_parameters,
        links=list(dict.fromkeys(links)),
        scripts=_extract_scripts(text),
        comments=_extract_comments(text),
        detected_technologies=_extract_technologies(text, response_headers),
        extracted_versions=_extract_versions(text, response_headers),
        interesting_reasons=_interesting_reasons(candidate, text, response_headers, status_code),
        workflow_tags=workflow_tags,
        content_fingerprint=_content_fingerprint(text),
        raw_content=text if candidate.path in {"/robots.txt", "/sitemap.xml"} else None,
        low_content=low_content,
        low_content_reason=low_content_reason,
    )


def _select_with_llm(
    candidates: list[WebPathCandidate],
    *,
    max_pages: int,
    llm_model: str | None,
    llm_provider: str | None,
) -> list[WebPathCandidate]:
    provider, model = resolve_llm_config(provider=llm_provider, model=llm_model)
    payload = [
        {
            "path": candidate.path,
            "status_code": candidate.status_code,
            "content_length": candidate.content_length,
            "hostname": candidate.hostname,
        }
        for candidate in candidates[:60]
    ]
    prompt = (
        "Select the most useful web paths for safe fingerprinting. "
        "Return only JSON with key selected_paths. Prefer pages likely to expose product, "
        "version, authentication, API, admin, config, backup, or server metadata. "
        "Do not propose commands or exploitation.\n"
        f"Max pages: {max_pages}\n"
        f"Candidates:\n{json.dumps(payload, ensure_ascii=False, indent=2)}"
    )
    try:
        response = build_chat_client(provider=provider, model=model, temperature=0).invoke(prompt)
        content = response_content_to_text(response)
        data = json.loads(_extract_json_object(content))
    except Exception:
        return []
    selected_paths = data.get("selected_paths") if isinstance(data, dict) else None
    if not isinstance(selected_paths, list):
        return []
    by_path = {candidate.path: candidate for candidate in candidates}
    selected = [by_path[path] for path in selected_paths if isinstance(path, str) and path in by_path]
    return selected[:max_pages]


def _candidate_score(candidate: WebPathCandidate) -> int:
    path = candidate.path.lower()
    score = 10
    if candidate.status_code in {200, 401, 403}:
        score += 20
    if any(token in path for token in GENERIC_INTERESTING_TOKENS):
        score += 25
    if any(path.endswith(suffix) for suffix in (".zip", ".tar", ".gz", ".bak", ".old", ".sql", ".conf", ".json")):
        score += 20
    if candidate.content_length and candidate.content_length > 0:
        score += 5
    return score


def _extract_title(text: str) -> str | None:
    match = TITLE_RE.search(text)
    if not match:
        return None
    return _compact(match.group("title"))[:120] or None


def _extract_meta_generator(text: str) -> str | None:
    match = META_GENERATOR_RE.search(text)
    return _compact(match.group("value")) if match else None


def _extract_forms(text: str) -> list[str]:
    forms: list[str] = []
    for match in FORM_RE.finditer(text):
        attrs = _compact(match.group("attrs"))
        forms.append(attrs[:160] if attrs else "form")
        if len(forms) >= 5:
            break
    return forms


def _extract_form_actions(text: str, base_path: str, *, allowed_hosts: set[str] | None = None) -> list[str]:
    actions: list[str] = []
    for match in FORM_RE.finditer(text):
        attrs = _parse_attrs(match.group("attrs"))
        action = attrs.get("action") or base_path
        path = _normalize_in_scope_path(action, base_path=base_path, allowed_hosts=allowed_hosts)
        if path:
            actions.append(path)
        if len(actions) >= 5:
            break
    return list(dict.fromkeys(actions))


def _extract_form_methods(text: str) -> list[str]:
    methods: list[str] = []
    for match in FORM_RE.finditer(text):
        attrs = _parse_attrs(match.group("attrs"))
        methods.append((attrs.get("method") or "get").lower())
        if len(methods) >= 5:
            break
    return list(dict.fromkeys(methods))


def _extract_form_parameters(text: str) -> list[str]:
    parameters: list[str] = []
    for match in INPUT_RE.finditer(text):
        attrs = _parse_attrs(match.group("attrs"))
        name = attrs.get("name") or attrs.get("id")
        if not name:
            continue
        input_type = (attrs.get("type") or "text").lower()
        parameters.append(f"{name}:{input_type}")
        if len(parameters) >= 16:
            break
    return list(dict.fromkeys(parameters))


def _extract_query_parameters(text: str, base_path: str, *, allowed_hosts: set[str] | None = None) -> list[str]:
    parameters: list[str] = []
    for href in _href_values(text):
        parsed = urlparse(href)
        normalized_path = _normalize_in_scope_path(href, base_path=base_path, allowed_hosts=allowed_hosts)
        if not normalized_path:
            continue
        query = parsed.query
        if not query and not parsed.netloc:
            query = urlparse(urljoin(base_path, href)).query
        for key, _value in parse_qsl(query, keep_blank_values=True):
            if key:
                parameters.append(f"{key} on {normalized_path}")
        if len(parameters) >= 16:
            break
    return list(dict.fromkeys(parameters))


def _workflow_tags(
    *,
    path: str,
    forms: list[str],
    input_fields: list[str],
    form_actions: list[str],
    form_parameters: list[str],
    query_parameters: list[str],
) -> list[str]:
    tags: list[str] = []
    haystack = " ".join([path, *forms, *input_fields, *form_actions, *form_parameters, *query_parameters]).lower()
    if forms and any(token in haystack for token in ("password", "passwd", "login", "user", "username", "email")):
        tags.append("real_login_form_candidate")
    if any(":file" in parameter.lower() for parameter in form_parameters) or "multipart/form-data" in haystack:
        tags.append("file_upload_form_candidate")
    if _has_file_path_parameter(query_parameters) or _has_file_path_parameter(form_parameters):
        tags.append("file_path_parameter_candidate")
    if _has_sqli_relevant_parameter(query_parameters) or _has_sqli_relevant_parameter(form_parameters):
        tags.append("sqli_relevant_parameter_candidate")
    return list(dict.fromkeys(tags))


def _has_file_path_parameter(parameters: list[str]) -> bool:
    file_tokens = ("page", "file", "path", "include", "inc", "template", "view", "load", "doc", "document", "url")
    return any(_parameter_name(parameter).lower() in file_tokens for parameter in parameters)


def _has_sqli_relevant_parameter(parameters: list[str]) -> bool:
    sqli_tokens = ("id", "user", "username", "login", "email", "search", "query", "q", "cat", "category", "supplier")
    return any(_parameter_name(parameter).lower() in sqli_tokens for parameter in parameters)


def _parameter_name(parameter: str) -> str:
    return parameter.split(":", 1)[0].split(" on ", 1)[0].strip()


def _href_values(text: str) -> list[str]:
    values = [_compact(match.group("href")) for match in LINK_RE.finditer(text)]
    values.extend(_hidden_path_hrefs(text))
    return list(dict.fromkeys(value for value in values if value))


def _extract_inputs(text: str) -> list[str]:
    inputs: list[str] = []
    for match in INPUT_RE.finditer(text):
        attrs = _compact(match.group("attrs"))
        inputs.append(attrs[:160] if attrs else "input")
        if len(inputs) >= 12:
            break
    return inputs


def _parse_attrs(attrs: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for match in ATTR_RE.finditer(attrs):
        key = match.group("key")
        if not key:
            continue
        value = match.group("quoted") if match.group("quoted") is not None else match.group("bare")
        parsed[key.lower()] = unescape(value or "")
    return parsed


def _extract_links(text: str, base_path: str, *, allowed_hosts: set[str] | None = None) -> list[str]:
    links: list[str] = []
    for match in LINK_RE.finditer(text):
        href = _compact(match.group("href"))
        path = _normalize_in_scope_path(href, base_path=base_path, allowed_hosts=allowed_hosts)
        if path:
            links.append(path)
        if len(links) >= 30:
            break
    for href in _hidden_path_hrefs(text):
        path = _normalize_in_scope_path(href, base_path=base_path, allowed_hosts=allowed_hosts)
        if path:
            links.append(path)
        if len(links) >= 30:
            break
    return list(dict.fromkeys(links))


def _hidden_path_hrefs(text: str) -> list[str]:
    hrefs: list[str] = []
    for match in META_REFRESH_RE.finditer(text):
        hrefs.append(_compact(match.group("url")))
    for match in FORM_ACTION_RE.finditer(text):
        hrefs.append(_compact(match.group("action")))
    for comment in _extract_comments(text):
        for match in META_REFRESH_RE.finditer(comment):
            hrefs.append(_compact(match.group("url")))
        for match in PATH_LIKE_RE.finditer(comment):
            hrefs.append(_compact(match.group("path")))
        for match in COMMENT_PATH_RE.finditer(comment):
            path = _compact(match.group("path"))
            if path.lower().rstrip("/") not in {"/admin", "/login", "/css", "/js", "/images"}:
                hrefs.append(path)
    return list(dict.fromkeys(href for href in hrefs if href))


def _extract_robots_paths(text: str) -> list[str]:
    paths: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key.strip().lower() not in {"allow", "disallow", "sitemap"}:
            continue
        value = value.strip()
        if key.strip().lower() == "sitemap":
            parsed = urlparse(value)
            if parsed.path:
                paths.append(parsed.path)
        elif value.startswith("/"):
            paths.append(value)
    return list(dict.fromkeys(paths))


def _extract_sitemap_paths(text: str, *, allowed_hosts: set[str] | None = None) -> list[str]:
    paths: list[str] = []
    for match in re.finditer(r"<loc>(?P<loc>.*?)</loc>", text, re.IGNORECASE | re.DOTALL):
        value = _compact(match.group("loc"))
        parsed = urlparse(value)
        if parsed.netloc and allowed_hosts is not None and _host_without_port(parsed.netloc) not in allowed_hosts:
            continue
        if parsed.path:
            paths.append(parsed.path)
    return list(dict.fromkeys(paths))


def _extract_scripts(text: str) -> list[str]:
    scripts = [_compact(match.group("src"))[:160] for match in SCRIPT_RE.finditer(text)]
    return list(dict.fromkeys(scripts[:10]))


def _extract_technologies(text: str, headers: dict[str, str]) -> list[str]:
    haystack = "\n".join(
        [
            text[:30000],
            "\n".join(f"{key}: {value}" for key, value in headers.items()),
        ]
    ).lower()
    technologies = [label for marker, label in TECHNOLOGY_MARKERS if marker in haystack]
    for key in ("Server", "X-Powered-By"):
        value = headers.get(key)
        if value:
            technologies.append(value)
    return list(dict.fromkeys(technologies))


def _extract_comments(text: str) -> list[str]:
    comments = [_compact(match.group("comment"))[:160] for match in COMMENT_RE.finditer(text)]
    return [comment for comment in comments if comment][:5]


def _extract_versions(text: str, headers: dict[str, str]) -> list[str]:
    haystack = "\n".join([text[:20000], "\n".join(f"{key}: {value}" for key, value in headers.items())])
    versions = []
    for match in VERSION_RE.finditer(haystack):
        value = _compact(f"{match.group('name')} {match.group('version')}")
        if value.lower().startswith(("http", "html", "css", "js")):
            continue
        versions.append(value[:120])
        if len(versions) >= 12:
            break
    return list(dict.fromkeys(versions))


def _interesting_reasons(
    candidate: WebPathCandidate,
    text: str,
    headers: dict[str, str],
    status_code: int,
) -> list[str]:
    reasons: list[str] = [f"HTTP status {status_code}"]
    lower_path = candidate.path.lower()
    for token in GENERIC_INTERESTING_TOKENS:
        if token in lower_path:
            reasons.append(f"generic interesting path token: {token}")
    if _extract_title(text):
        reasons.append("HTML title observed")
    if _extract_forms(text):
        reasons.append("HTML form observed")
    if _extract_versions(text, headers):
        reasons.append("version-like strings observed")
    if _hidden_path_hrefs(text):
        reasons.append("hidden path or redirect target observed")
    if _looks_like_env_config(text):
        reasons.append("environment configuration marker observed")
    if _looks_like_git_config(text):
        reasons.append("git configuration marker observed")
    for marker, reason in APPLICATION_ATTACK_HINTS:
        if marker in text.lower() or marker in lower_path:
            reasons.append(reason)
    if headers.get("WWW-Authenticate"):
        reasons.append("authentication challenge observed")
    if headers.get("Server") or headers.get("X-Powered-By"):
        reasons.append("technology header observed")
    return list(dict.fromkeys(reasons))


def _deep_candidates_from_findings(
    findings: list[WebPageFinding],
    *,
    target_ip: str,
    port: int,
    hostname: str | None,
) -> list[WebPathCandidate]:
    scheme = "https" if port == 443 else "http"
    base = f"{scheme}://{target_ip}:{port}/"
    paths: list[tuple[str, str]] = []
    for finding in findings:
        for link in finding.links:
            paths.append((link, f"link:{finding.path}"))
        if finding.path == "/robots.txt":
            for path in _paths_from_robots_comments(finding.comments + finding.links):
                paths.append((path, "robots"))
        if finding.path == "/sitemap.xml":
            for path in finding.links:
                paths.append((path, "sitemap"))
    paths.extend((path, "seed") for path in DEEP_WEB_SEED_PATHS)
    candidates = []
    seen = set()
    for path, source in paths:
        if path in seen:
            continue
        seen.add(path)
        candidates.append(
            WebPathCandidate(
                url=urljoin(base, path.lstrip("/")),
                path=path,
                status_code=None,
                content_length=None,
                hostname=hostname,
                discovery_source=source,
            )
        )
    return candidates


def _with_soft_404_flags(findings: list[WebPageFinding]) -> list[WebPageFinding]:
    baseline_fingerprints = {
        finding.content_fingerprint
        for finding in findings
        if finding.path in SOFT_404_BASELINE_PATHS and finding.status_code == 200 and finding.content_fingerprint
    }
    sensitive_by_fingerprint: dict[str, list[WebPageFinding]] = {}
    for finding in findings:
        if (
            finding.status_code == 200
            and finding.content_fingerprint
            and _is_soft_404_sensitive_path(finding.path)
            and not _has_path_specific_disclosure_marker(finding)
        ):
            sensitive_by_fingerprint.setdefault(finding.content_fingerprint, []).append(finding)

    updated: list[WebPageFinding] = []
    for finding in findings:
        reason = _soft_404_reason(
            finding,
            baseline_fingerprints=baseline_fingerprints,
            sensitive_by_fingerprint=sensitive_by_fingerprint,
        )
        if reason:
            interesting = list(dict.fromkeys(finding.interesting_reasons + ["probable soft-404/catch-all response"]))
            updated.append(
                finding.model_copy(
                    update={
                        "soft_404": True,
                        "soft_404_reason": reason,
                        "interesting_reasons": interesting,
                    }
                )
            )
        else:
            updated.append(finding)
    return updated


def _soft_404_reason(
    finding: WebPageFinding,
    *,
    baseline_fingerprints: set[str | None],
    sensitive_by_fingerprint: dict[str, list[WebPageFinding]],
) -> str | None:
    if finding.status_code != 200 or not finding.content_fingerprint:
        return None
    if not _is_soft_404_sensitive_path(finding.path):
        return None
    if _has_path_specific_disclosure_marker(finding):
        return None
    if finding.content_fingerprint in baseline_fingerprints:
        return "response body matches baseline page for a sensitive seed path"
    similar_sensitive = sensitive_by_fingerprint.get(finding.content_fingerprint, [])
    distinct_paths = {item.path for item in similar_sensitive}
    if len(distinct_paths) >= 2:
        return "multiple sensitive seed paths returned the same body without path-specific markers"
    return None


def _is_soft_404_sensitive_path(path: str) -> bool:
    lowered = path.lower()
    return any(lowered == prefix.rstrip("/") or lowered.startswith(prefix) for prefix in SOFT_404_SENSITIVE_PATH_PREFIXES)


def _has_path_specific_disclosure_marker(finding: WebPageFinding) -> bool:
    markers = " ".join(finding.interesting_reasons).lower()
    return "environment configuration marker observed" in markers or "git configuration marker observed" in markers


def _looks_like_env_config(text: str) -> bool:
    lower = text.lower()
    return any(marker in lower for marker in ENV_CONFIG_MARKERS)


def _looks_like_git_config(text: str) -> bool:
    lower = text.lower()
    return any(marker in lower for marker in GIT_CONFIG_MARKERS)


def _content_fingerprint(text: str) -> str | None:
    normalized = re.sub(r"\s+", "", text).lower()
    if not normalized:
        return None
    return hashlib.sha256(normalized.encode("utf-8", errors="ignore")).hexdigest()[:16]


def _paths_from_robots_comments(values: list[str]) -> list[str]:
    paths: list[str] = []
    for value in values:
        for token in value.split():
            if token.startswith("/"):
                paths.append(token)
    return paths


def _extract_json_object(content: str) -> str:
    text = content.strip()
    if text.startswith("{") and text.endswith("}"):
        return text
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        return text[start : end + 1]
    return "{}"


def _low_content_assessment(text: str, *, forms: list[str], input_fields: list[str]) -> tuple[bool, str | None]:
    visible = re.sub(r"<script\b.*?</script>", " ", text, flags=re.IGNORECASE | re.DOTALL)
    visible = re.sub(r"<style\b.*?</style>", " ", visible, flags=re.IGNORECASE | re.DOTALL)
    visible = _compact(re.sub(r"<[^>]+>", " ", visible))
    if forms or input_fields:
        return False, None
    if not visible:
        return True, "empty response body after HTML stripping"
    if len(visible) < 25:
        return True, f"very small visible body ({len(visible)} chars)"
    return False, None


def _path_from_url(url: str) -> str:
    without_scheme = url.split("://", 1)[-1]
    slash = without_scheme.find("/")
    if slash == -1:
        return "/"
    return without_scheme[slash:] or "/"


def _normalize_in_scope_path(
    href: str,
    *,
    base_path: str,
    allowed_hosts: set[str] | None = None,
) -> str | None:
    if not href or href.startswith(("#", "mailto:", "tel:", "javascript:")):
        return None
    parsed = urlparse(href)
    if parsed.scheme and parsed.scheme not in {"http", "https"}:
        return None
    if parsed.netloc:
        if allowed_hosts is not None and _host_without_port(parsed.netloc) not in allowed_hosts:
            return None
        return parsed.path or "/"
    joined = urljoin(base_path, href)
    parsed_joined = urlparse(joined)
    path = parsed_joined.path or "/"
    if not path.startswith("/"):
        path = f"/{path}"
    return path


def _allowed_link_hosts(
    *,
    target_ip: str,
    port: int,
    hostname: str | None,
    candidate_url: str,
) -> set[str]:
    hosts = {target_ip}
    if hostname:
        hosts.add(hostname)
    parsed = urlparse(candidate_url)
    if parsed.netloc:
        hosts.add(_host_without_port(parsed.netloc))
    return {host for host in hosts if host}


def _host_without_port(netloc: str) -> str:
    if netloc.startswith("[") and "]" in netloc:
        return netloc[1 : netloc.index("]")]
    return netloc.split("@")[-1].split(":", 1)[0]


def _compact(value: str) -> str:
    return unescape(" ".join(value.split()))
