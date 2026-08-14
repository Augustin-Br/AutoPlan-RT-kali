"""Extract structured application evidence from static infrastructure notes."""

from __future__ import annotations

import re

from V2.models import InfraDocumentInput, ServiceFinding, extract_service_findings
from V4.models import EvidenceGraph, EvidenceItem

WEB_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])(?P<path>/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+/?)(?=[\s,.;)]|$)"
)


def extract_evidence_graph(infra: InfraDocumentInput) -> EvidenceGraph:
    """Build a conservative evidence graph from service notes and banners."""

    items: list[EvidenceItem] = []
    for finding in extract_service_findings(infra):
        items.extend(_service_evidence(finding))
    return EvidenceGraph(items=_dedupe(items))


def evidence_prompt_payload(graph: EvidenceGraph) -> list[dict]:
    """Compact JSON payload for the LLM prompt."""

    return [
        {
            "id": item.id,
            "target_ip": item.target_ip,
            "port": item.port,
            "service": item.service,
            "kind": item.kind,
            "value": item.value,
            "tags": item.tags,
            "status": item.status,
            "source": item.source,
        }
        for item in graph.items
    ]


def _service_evidence(finding: ServiceFinding) -> list[EvidenceItem]:
    text = " ".join(
        part
        for part in [finding.service, finding.version or "", finding.cve or "", finding.notes or ""]
        if part
    )
    lowered = text.lower()
    negative_wordlist = _negates(lowered, "wordlist") or _negates(lowered, "dictionary")
    negative_login = _negates(lowered, "login")
    negative_parameter = _negates(lowered, "parameter")
    negative_encoded = _negates(lowered, "encoded") or _negates(lowered, "license")
    negative_admin = _negates(lowered, "theme editor") or _negates(lowered, "admin")
    negative_local_user = _negates(lowered, "local user") or _negates(lowered, "robot user")
    negative_hash = _negates(lowered, "hash") or _negates(lowered, "password.raw-md5")
    negative_ssh = _negates(lowered, "ssh")
    negative_suid = _negates(lowered, "suid")
    negative_privesc = _negates(lowered, "privilege-escalation") or _negates(lowered, "privilege escalation")
    negative_ftp = _negates(lowered, "ftp")
    negative_sqli = _negates(lowered, "sql injection") or _negates(lowered, "sqli")
    negative_webmail = _negates(lowered, "webmail") or _negates(lowered, "squirrelmail")
    negative_backdoor = _negates(lowered, "backdoor")
    negative_sudo = _negates(lowered, "sudo")
    negative_local_binary = (
        negative_privesc
        or _negates(lowered, "helper binary")
        or _negates(lowered, "helper-binary")
        or _negates(lowered, "path hijack")
        or _negates(lowered, "path-hijack")
        or _negates(lowered, "command injection")
        or _negates(lowered, "msgmike")
        or _negates(lowered, "msg2root")
    )
    items: list[EvidenceItem] = []

    if finding.version:
        items.append(_item(finding, "technology", finding.version, tags=["banner", "version"]))
    if finding.cve:
        items.append(_item(finding, "sensitive_resource", finding.cve, tags=["cve", "known_vulnerability"]))
    if "mysql" in lowered or "mariadb" in lowered or finding.service.lower() in {"mysql", "mariadb"}:
        items.append(_item(finding, "database_service", finding.service, tags=["database"]))
    if finding.service.lower() == "ftp" and not negative_ftp:
        items.append(_item(finding, "ftp_service", finding.service, tags=["ftp", "remote_login"]))
    if finding.service.lower() == "ssh" and not negative_ssh:
        items.append(_item(finding, "ssh_service", finding.service, tags=["ssh", "remote_login"]))

    paths = list(dict.fromkeys(match.group("path").rstrip(".,;)") for match in WEB_PATH_RE.finditer(text)))
    for path in paths:
        kind, tags, status = _classify_path(path, lowered)
        if kind == "wordlist_resource" and negative_wordlist:
            continue
        if kind == "encoded_resource" and negative_encoded:
            continue
        if kind == "local_hash" and negative_hash:
            continue
        if kind == "webmail_surface" and negative_webmail:
            continue
        if kind == "backdoor_surface" and negative_backdoor:
            continue
        items.append(_item(finding, kind, path, tags=tags, status=status))

    for token, kind, tags in [
        ("wordpress", "cms_surface", ["cms", "wordpress"]),
        ("wp-content", "cms_surface", ["cms", "wordpress"]),
        ("drupal", "cms_surface", ["cms", "drupal"]),
        ("joomla", "cms_surface", ["cms", "joomla"]),
        ("tomcat", "cms_surface", ["app_server", "tomcat"]),
        ("pchart", "technology", ["php_app", "pchart"]),
        ("wp-login", "login_surface", ["login", "wordpress"]),
        ("login form", "login_surface", ["login", "form"]),
        ("auth workflow", "login_surface", ["auth", "workflow"]),
        ("parameter", "file_parameter", ["parameter"]),
        ("sqli", "file_parameter", ["sqli", "parameter"]),
        ("wordlist", "wordlist_resource", ["wordlist"]),
        ("soft-404", "soft_404", ["negative_evidence"]),
        ("catch-all", "soft_404", ["negative_evidence"]),
        ("encoded-looking", "encoded_resource", ["encoded", "credential_review"]),
        ("base64", "encoded_resource", ["encoded", "credential_review"]),
        ("theme editor", "admin_capability", ["wordpress", "admin", "theme_editor"]),
        ("wordpress admin", "admin_capability", ["wordpress", "admin"]),
        ("admin dashboard", "admin_capability", ["wordpress", "admin"]),
        ("robot user", "local_user", ["local_user", "post_exploitation"]),
        ("user robot", "local_user", ["local_user", "post_exploitation"]),
        ("password.raw-md5", "local_hash", ["hash", "credential_review"]),
        ("hash", "local_hash", ["hash", "credential_review"]),
        ("suid nmap", "suid_binary", ["suid", "nmap", "privilege_escalation"]),
        ("nmap has suid", "suid_binary", ["suid", "nmap", "privilege_escalation"]),
        ("privilege escalation", "privilege_escalation_hint", ["privilege_escalation"]),
        ("root shell", "privilege_escalation_hint", ["privilege_escalation", "root"]),
        ("ftp-login", "ftp_credential_clue", ["ftp", "credential_review"]),
        ("ftp login", "ftp_credential_clue", ["ftp", "credential_review"]),
        ("ftp credential", "ftp_credential_clue", ["ftp", "credential_review"]),
        ("sql injection", "sql_injection_parameter", ["sqli", "parameter", "auth_bypass"]),
        ("sqli", "sql_injection_parameter", ["sqli", "parameter", "auth_bypass"]),
        ("sparepartid", "sql_injection_parameter", ["sqli", "parameter"]),
        ("squirrelmail", "webmail_surface", ["webmail", "mail"]),
        ("inbox", "mail_secret", ["mail", "secret"]),
        ("draft", "mail_secret", ["mail", "secret"]),
        ("encrypted mail", "mail_secret", ["mail", "secret", "encoded"]),
        ("cipher mail", "mail_secret", ["mail", "secret", "encoded"]),
        ("backdoor.php", "backdoor_surface", ["backdoor", "web"]),
        ("kgbbackdoor", "backdoor_surface", ["backdoor", "web"]),
        ("backdoor password", "backdoor_credential", ["backdoor", "credential_review"]),
        ("hailkgb", "backdoor_credential", ["backdoor", "credential_review"]),
        ("dimitrihateapple", "local_secret", ["local_secret", "credential_review"]),
        (".secret", "local_secret", ["local_secret", "credential_review"]),
        ("dimitri", "local_user", ["local_user", "post_exploitation"]),
        ("sudo rights", "sudo_rights", ["sudo", "privilege_escalation"]),
        ("(all : all) all", "sudo_rights", ["sudo", "privilege_escalation"]),
        ("sudo su", "sudo_rights", ["sudo", "privilege_escalation"]),
        ("msgmike", "local_suid_helper_binary", ["local_binary", "suid_helper", "privilege_escalation"]),
        ("msg2root", "local_command_injection_binary", ["local_binary", "command_injection", "privilege_escalation"]),
        ("helper binaries", "local_suid_helper_binary", ["local_binary", "suid_helper", "privilege_escalation"]),
        ("helper binary", "local_suid_helper_binary", ["local_binary", "suid_helper", "privilege_escalation"]),
        ("path hijack", "path_hijack_privilege_escalation", ["path_hijack", "privilege_escalation"]),
        ("path-hijack", "path_hijack_privilege_escalation", ["path_hijack", "privilege_escalation"]),
        ("command injection", "local_command_injection_binary", ["local_binary", "command_injection", "privilege_escalation"]),
        ("local binary", "local_suid_helper_binary", ["local_binary", "privilege_escalation"]),
    ]:
        if token in lowered and not _token_is_negated(
            token,
            kind=kind,
            negative_wordlist=negative_wordlist,
            negative_login=negative_login,
            negative_parameter=negative_parameter,
            negative_encoded=negative_encoded,
            negative_admin=negative_admin,
            negative_local_user=negative_local_user,
            negative_hash=negative_hash,
            negative_ssh=negative_ssh,
            negative_suid=negative_suid,
            negative_privesc=negative_privesc,
            negative_ftp=negative_ftp,
            negative_sqli=negative_sqli,
            negative_webmail=negative_webmail,
            negative_backdoor=negative_backdoor,
            negative_sudo=negative_sudo,
            negative_local_binary=negative_local_binary,
        ):
            items.append(_item(finding, kind, token, tags=tags, status="soft_404" if kind == "soft_404" else None))
    return items


def _classify_path(path: str, note_text: str) -> tuple[str, list[str], str | None]:
    path_l = path.lower()
    if _path_is_soft_404(path_l, note_text):
        return "soft_404", ["negative_evidence", "login_guess"], "soft_404"
    if any(token in path_l for token in ("login", "wp-login", "admin")):
        return "login_surface", ["login", "auth"], None
    if any(token in path_l for token in (".dic", "wordlist", "dictionary")):
        return "wordlist_resource", ["wordlist", "credential_review"], None
    if any(token in path_l for token in ("config.php", ".env")):
        return "config_file", ["configuration", "credential_clue"], None
    if "password.raw-md5" in path_l or "hash" in path_l:
        return "local_hash", ["hash", "credential_review"], None
    if ".git" in path_l:
        return "source_metadata", ["source", "configuration"], None
    if "license" in path_l:
        if any(token in note_text for token in ("encoded", "base64", "credential", "credentials")):
            return "encoded_resource", ["encoded", "credential_review"], None
        return "web_path", ["web_path", "license"], None
    if "upload" in path_l:
        return "upload_surface", ["upload", "file_workflow"], None
    if "squirrelmail" in path_l:
        return "webmail_surface", ["webmail", "mail"], None
    if "backdoor" in path_l:
        return "backdoor_surface", ["backdoor", "web"], None
    if "sparepartsstoremore" in path_l:
        return "sql_injection_parameter", ["sqli", "parameter"], None
    if any(token in path_l for token in ("pchart", "index.php", "file", "path")):
        return "file_parameter", ["file_or_path_review"], None
    if any(token in path_l for token in ("wp-content", "wordpress", "sites/default", "modules", "profiles")):
        return "cms_surface", ["cms"], None
    if "server-status" in path_l:
        return "server_status", ["server_metadata"], None
    if any(token in path_l for token in ("key", "backup", "bak", "old")):
        return "sensitive_resource", ["sensitive_resource"], None
    return "web_path", ["web_path"], None


def _path_is_soft_404(path_l: str, note_text: str) -> bool:
    if not any(token in note_text for token in ("soft-404", "soft 404", "catch-all", "catch all")):
        return False
    return any(token in path_l for token in ("login", "admin", "user"))


def _negates(text: str, token: str) -> bool:
    patterns = [
        rf"\bno\s+(?:actual\s+)?{re.escape(token)}\b",
        rf"\bno\b[^\n]{{0,120}}\b{re.escape(token)}\b",
        rf"\bwithout\s+(?:any\s+)?{re.escape(token)}\b",
        rf"\bnot\s+(?:an?\s+)?{re.escape(token)}\b",
        rf"\baucun(?:e)?\s+{re.escape(token)}\b",
        rf"\bpas\s+de\s+{re.escape(token)}\b",
    ]
    return any(re.search(pattern, text) for pattern in patterns)


def _token_is_negated(
    token: str,
    *,
    kind: str,
    negative_wordlist: bool,
    negative_login: bool,
    negative_parameter: bool,
    negative_encoded: bool = False,
    negative_admin: bool = False,
    negative_local_user: bool = False,
    negative_hash: bool = False,
    negative_ssh: bool = False,
    negative_suid: bool = False,
    negative_privesc: bool = False,
    negative_ftp: bool = False,
    negative_sqli: bool = False,
    negative_webmail: bool = False,
    negative_backdoor: bool = False,
    negative_sudo: bool = False,
    negative_local_binary: bool = False,
) -> bool:
    if kind == "wordlist_resource" and negative_wordlist:
        return True
    if kind == "login_surface" and negative_login:
        return True
    if kind == "file_parameter" and token == "parameter" and negative_parameter:
        return True
    if kind == "encoded_resource" and negative_encoded:
        return True
    if kind == "admin_capability" and negative_admin:
        return True
    if kind == "local_user" and negative_local_user:
        return True
    if kind == "local_hash" and negative_hash:
        return True
    if kind == "ssh_service" and negative_ssh:
        return True
    if kind == "suid_binary" and negative_suid:
        return True
    if kind == "privilege_escalation_hint" and negative_privesc:
        return True
    if kind in {"ftp_service", "ftp_credential_clue"} and negative_ftp:
        return True
    if kind == "sql_injection_parameter" and negative_sqli:
        return True
    if kind in {"webmail_surface", "mail_secret"} and negative_webmail:
        return True
    if kind in {"backdoor_surface", "backdoor_credential"} and negative_backdoor:
        return True
    if kind == "sudo_rights" and negative_sudo:
        return True
    if kind in {
        "local_suid_helper_binary",
        "path_hijack_privilege_escalation",
        "local_command_injection_binary",
    } and negative_local_binary:
        return True
    return False


def _item(
    finding: ServiceFinding,
    kind: str,
    value: str,
    *,
    tags: list[str] | None = None,
    status: str | None = None,
) -> EvidenceItem:
    return EvidenceItem(
        id=_evidence_id(finding, kind, value),
        target_id=finding.target_id,
        target_ip=finding.target_ip,
        port=finding.port,
        service=finding.service,
        kind=kind,  # type: ignore[arg-type]
        value=value,
        tags=tags or [],
        status=status,
        source_text=finding.notes,
    )


def _evidence_id(finding: ServiceFinding, kind: str, value: str) -> str:
    safe = re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")[:50] or "evidence"
    return f"evidence:{finding.target_id}:{finding.port}:{kind}:{safe}"


def _dedupe(items: list[EvidenceItem]) -> list[EvidenceItem]:
    deduped: dict[str, EvidenceItem] = {}
    for item in items:
        deduped.setdefault(item.id, item)
    return list(deduped.values())
