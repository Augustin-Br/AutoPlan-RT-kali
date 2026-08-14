"""Convert scan-only reconnaissance reports into V2/V3 infrastructure input."""

from __future__ import annotations

import re

from V2.app_knowledge import match_application_knowledge
from V2.models import InfraDocumentInput, InfraMachineInput, InfraServiceInput
from V2.recon_models import ReconObservation, ReconReport

DEFAULT_SCAN_OBJECTIVE = "Identify and rank plausible attack vectors for authorized SOC training."
HTTP_LIKE_PORTS = {80, 3000, 5000, 5601, 7000, 8000, 8080, 8180, 9000}
HTTPS_LIKE_PORTS = {443, 8443}
NON_HTTP_TLS_SERVICE_PORTS = {465: "SMTPS", 636: "LDAPS", 993: "IMAPS", 995: "POP3S"}

_CVE_HINTS: tuple[tuple[tuple[str, ...], str], ...] = (
    (("samba", "3.0.20"), "CVE-2007-2447"),
    (("vsftpd", "2.3.4"), "CVE-2011-2523"),
    (("distcc",), "CVE-2004-2687"),
    (("php", "cgi"), "CVE-2012-1823"),
    (("unrealircd", "3.2.8.1"), "CVE-2010-2075"),
)


def infra_from_recon_report(
    report: ReconReport,
    *,
    target_ip: str | None = None,
    objective: str = DEFAULT_SCAN_OBJECTIVE,
) -> InfraDocumentInput:
    observations = [
        observation
        for observation in report.observations
        if target_ip is None or observation.target_ip == target_ip
    ]
    by_port = _merge_by_port(observations)
    ip = target_ip or _first_target_ip(observations) or _target_from_infra_path(report.infra_path)
    services = [
        _service_from_observation(observation)
        for observation in sorted(by_port.values(), key=lambda item: item.port)
    ]
    return InfraDocumentInput(
        entreprise="Scan-only authorized lab target",
        reseaux=[{"nom": "scan-only-target", "sous_reseau": f"{ip}/32"}],
        machines=[
            InfraMachineInput(
                id=f"scan_{_safe_id(ip)}",
                ip=ip,
                zone="scan-only",
                os=_observed_os(observations),
                services=services,
                regles_firewall="Unknown; inferred from reachable services during bounded reconnaissance.",
            )
        ],
        objective=objective,
        pistes_documentees=[],
    )


def _merge_by_port(observations: list[ReconObservation]) -> dict[tuple[str, int], ReconObservation]:
    merged: dict[tuple[str, int], ReconObservation] = {}
    for observation in observations:
        key = (observation.target_ip, observation.port)
        if key not in merged:
            merged[key] = observation
            continue
        existing = merged[key]
        merged[key] = existing.model_copy(
            update={
                "service": _prefer_service(existing.service, observation.service),
                "version": existing.version or observation.version,
                "product": existing.product or observation.product,
                "cpe": list(dict.fromkeys(existing.cpe + observation.cpe)),
                "scripts": {**existing.scripts, **observation.scripts},
                "ftp_anonymous": existing.ftp_anonymous if existing.ftp_anonymous is not None else observation.ftp_anonymous,
                "ftp_features": list(dict.fromkeys(existing.ftp_features + observation.ftp_features)),
                "ssh_hostkeys": list(dict.fromkeys(existing.ssh_hostkeys + observation.ssh_hostkeys)),
                "ssh_algorithms": list(dict.fromkeys(existing.ssh_algorithms + observation.ssh_algorithms)),
                "db_info": {**existing.db_info, **observation.db_info},
                "rpc_services": list(dict.fromkeys(existing.rpc_services + observation.rpc_services)),
                "nfs_exports": list(dict.fromkeys(existing.nfs_exports + observation.nfs_exports)),
                "tls_cert": {**existing.tls_cert, **observation.tls_cert},
                "tls_ciphers": list(dict.fromkeys(existing.tls_ciphers + observation.tls_ciphers)),
                "smb_os": existing.smb_os or observation.smb_os,
                "smb_computer_name": existing.smb_computer_name or observation.smb_computer_name,
                "smb_domain": existing.smb_domain or observation.smb_domain,
                "smb_workgroup": existing.smb_workgroup or observation.smb_workgroup,
                "smb_dialects": list(dict.fromkeys(existing.smb_dialects + observation.smb_dialects)),
                "smb_security_mode": {**existing.smb_security_mode, **observation.smb_security_mode},
                "web_headers": {**existing.web_headers, **observation.web_headers},
                "web_paths": list(dict.fromkeys(existing.web_paths + observation.web_paths)),
                "web_vhosts": list(dict.fromkeys(existing.web_vhosts + observation.web_vhosts)),
                "web_pages": existing.web_pages + observation.web_pages,
                "detected_technologies": list(
                    dict.fromkeys(existing.detected_technologies + observation.detected_technologies)
                ),
                "raw_evidence_ref": existing.raw_evidence_ref or observation.raw_evidence_ref,
            }
        )
    return merged


def _service_from_observation(observation: ReconObservation) -> InfraServiceInput:
    service = _normalize_service(observation)
    notes = _notes(observation)
    cve = _cve_hint(observation)
    module_hint = _module_hint(observation)
    if cve:
        notes = _append_note(
            notes,
            f"Recon-derived vulnerability hint: service/version fingerprint is associated with {cve}; not proof of exploitability.",
        )
    if module_hint:
        notes = _append_note(notes, module_hint)
    return InfraServiceInput(
        port=observation.port,
        service=service,
        version=observation.version,
        cve=cve,
        notes=notes,
    )


def _normalize_service(observation: ReconObservation) -> str:
    service = (observation.service or "").strip()
    blob = _observation_blob(observation)
    if observation.port in {139, 445} and ("windows" in blob or "microsoft" in blob):
        return "SMB"
    if "samba" in blob:
        return "Samba"
    if observation.port in {139, 445} or "smb" in blob:
        return "SMB"
    if observation.port == 21 or "ftp" in blob:
        return "FTP"
    if observation.port == 22 or "ssh" in blob:
        return "SSH"
    if observation.port in NON_HTTP_TLS_SERVICE_PORTS:
        return NON_HTTP_TLS_SERVICE_PORTS[observation.port]
    if observation.port == 143 or "imap" in blob:
        return "IMAP"
    if observation.port == 110 or "pop3" in blob:
        return "POP3"
    if observation.port == 25 or observation.port == 587 or "smtp" in blob:
        return "SMTP"
    if observation.port == 3306 or "mysql" in blob:
        return "MySQL"
    if observation.port == 5432 or "postgres" in blob:
        return "PostgreSQL"
    if observation.port == 1433 or "mssql" in blob or "ms-sql" in blob:
        return "MSSQL"
    if observation.port == 2049 or "nfs" in blob:
        return "NFS"
    if observation.port == 111 or "rpcbind" in blob:
        return "RPC"
    if observation.port in HTTP_LIKE_PORTS or "http" in blob:
        return "HTTP"
    if observation.port in HTTPS_LIKE_PORTS or "ssl/http" in blob or "https" in blob:
        return "HTTPS"
    if "distcc" in blob or "distccd" in blob:
        return "distccd"
    if "unrealircd" in blob or "unreal ircd" in blob:
        return "UnrealIRCd"
    return service or "unknown"


def _notes(observation: ReconObservation) -> str | None:
    fragments: list[str] = []
    if observation.product:
        fragments.append(f"Recon product hint: {observation.product}.")
    if observation.web_headers:
        headers = ", ".join(f"{key}: {value}" for key, value in sorted(observation.web_headers.items()))
        fragments.append(f"Recon HTTP headers: {headers}.")
    if observation.ftp_anonymous is not None or observation.ftp_features:
        ftp_bits = []
        if observation.ftp_anonymous is not None:
            ftp_bits.append(f"anonymous_login={observation.ftp_anonymous}")
        if observation.ftp_features:
            ftp_bits.append(f"features={'; '.join(observation.ftp_features[:8])}")
        fragments.append(f"Recon FTP fingerprint: {'; '.join(ftp_bits)}.")
    if observation.ssh_hostkeys or observation.ssh_algorithms:
        ssh_bits = []
        if observation.ssh_hostkeys:
            ssh_bits.append(f"hostkeys={'; '.join(observation.ssh_hostkeys[:4])}")
        if observation.ssh_algorithms:
            ssh_bits.append(f"algorithms={'; '.join(observation.ssh_algorithms[:8])}")
        fragments.append(f"Recon SSH fingerprint: {'; '.join(ssh_bits)}.")
    if observation.db_info:
        db_bits = ", ".join(f"{key}={value}" for key, value in sorted(observation.db_info.items()))
        fragments.append(f"Recon database fingerprint: {db_bits}.")
    if observation.rpc_services:
        fragments.append(f"Recon RPC services: {'; '.join(observation.rpc_services[:10])}.")
    if observation.nfs_exports:
        fragments.append(f"Recon NFS exports: {'; '.join(observation.nfs_exports[:10])}.")
    if observation.tls_cert or observation.tls_ciphers:
        tls_bits = []
        if observation.tls_cert:
            tls_bits.append(", ".join(f"{key}={value}" for key, value in sorted(observation.tls_cert.items())))
        if observation.tls_ciphers:
            tls_bits.append(f"ciphers={'; '.join(observation.tls_ciphers[:8])}")
        fragments.append(f"Recon TLS fingerprint: {'; '.join(tls_bits)}.")
    if observation.scripts:
        script_bits = [
            f"{key}={_truncate(value, 500)}"
            for key, value in sorted(observation.scripts.items())
            if value
        ]
        if script_bits:
            fragments.append(f"Recon script findings: {'; '.join(script_bits)}.")
    if observation.smb_os or observation.smb_dialects or observation.smb_security_mode:
        smb_bits = []
        if observation.smb_os:
            smb_bits.append(f"OS={observation.smb_os}")
        if observation.smb_computer_name:
            smb_bits.append(f"computer={observation.smb_computer_name}")
        if observation.smb_domain:
            smb_bits.append(f"domain={observation.smb_domain}")
        if observation.smb_workgroup:
            smb_bits.append(f"workgroup={observation.smb_workgroup}")
        if observation.smb_dialects:
            smb_bits.append(f"dialects={', '.join(observation.smb_dialects[:6])}")
        if observation.smb_security_mode:
            security = ", ".join(
                f"{key}={value}" for key, value in sorted(observation.smb_security_mode.items())
            )
            smb_bits.append(f"security={security}")
        fragments.append(f"Recon SMB fingerprint: {'; '.join(smb_bits)}.")
    if observation.web_paths:
        fragments.append(f"Recon web paths: {'; '.join(observation.web_paths[:12])}.")
    if observation.web_pages:
        for page in observation.web_pages:
            path_norm = page.path.lstrip("/")
            if (
                path_norm in {"robots.txt", "sitemap.xml"}
                and getattr(page, "raw_content", None)
                and _metadata_file_content_is_usable(page)
            ):
                raw_text = _filtered_metadata_content(page.raw_content).strip()
                truncated = raw_text[:600]
                if truncated:
                    fragments.append(f"Extracted {path_norm} content: {truncated}")
        robots_resources = _robots_txt_resources(observation)
        if robots_resources:
            fragments.append(f"Robots.txt exposed resources: {', '.join(robots_resources[:8])}.")
            sensitive_files = _sensitive_looking_resources(robots_resources)
            if sensitive_files:
                fragments.append(
                    "Direct information disclosure hint: robots.txt lists sensitive-looking resource(s) "
                    f"{', '.join(sensitive_files[:4])}."
                )
        page_fragments = []
        for page in observation.web_pages[:8]:
            page_bits = [page.path]
            if page.status_code:
                page_bits.append(f"status={page.status_code}")
            if page.title:
                page_bits.append(f"title={page.title!r}")
            if page.meta_generator:
                page_bits.append(f"generator={page.meta_generator!r}")
            if page.detected_technologies:
                page_bits.append(f"technologies={', '.join(page.detected_technologies[:5])}")
            if page.extracted_versions:
                page_bits.append(f"versions={', '.join(page.extracted_versions[:5])}")
            if page.forms:
                page_bits.append("forms=observed")
            if page.form_actions:
                page_bits.append(f"form_actions={', '.join(page.form_actions[:3])}")
            if page.form_methods:
                page_bits.append(f"form_methods={', '.join(page.form_methods[:3])}")
            if page.form_parameters:
                page_bits.append(f"form_parameters={', '.join(page.form_parameters[:6])}")
            if page.input_fields:
                page_bits.append("inputs=observed")
            if page.query_parameters:
                page_bits.append(f"query_parameters={', '.join(page.query_parameters[:6])}")
            if page.workflow_tags:
                page_bits.append(f"workflow_tags={', '.join(page.workflow_tags[:6])}")
            if page.low_content:
                page_bits.append("low_content=true")
                if page.low_content_reason:
                    page_bits.append(f"low_content_reason={page.low_content_reason!r}")
            if page.links:
                page_bits.append(f"links={', '.join(page.links[:5])}")
            if page.scripts:
                page_bits.append(f"scripts={', '.join(page.scripts[:3])}")
            auth_realm = page.headers.get("WWW-Authenticate")
            if auth_realm:
                page_bits.append(f"auth_realm={auth_realm!r}")
            if page.discovery_source:
                page_bits.append(f"source={page.discovery_source}")
            if page.soft_404:
                page_bits.append("soft_404=true")
                if page.soft_404_reason:
                    page_bits.append(f"soft_404_reason={page.soft_404_reason!r}")
            if page.interesting_reasons:
                page_bits.append(f"reasons={', '.join(page.interesting_reasons[:4])}")
            page_fragments.append(" ".join(page_bits))
        fragments.append(f"Recon enriched web pages: {'; '.join(page_fragments)}.")
        app_hints = _web_application_hints(observation)
        if app_hints:
            fragments.append(f"Recon application attack hints: {'; '.join(app_hints)}.")
    if observation.web_vhosts:
        fragments.append(f"Recon vhost candidates: {'; '.join(observation.web_vhosts[:12])}.")
    if observation.detected_technologies:
        fragments.append(f"Recon detected technologies: {', '.join(observation.detected_technologies)}.")
    if observation.raw_evidence_ref:
        fragments.append(f"Evidence reference: {observation.raw_evidence_ref}.")
    return " ".join(fragments) or None


def _cve_hint(observation: ReconObservation) -> str | None:
    blob = _observation_blob(observation)
    if _is_windows_xp_smb(observation):
        return "CVE-2008-4250"
    if observation.port == 21 and "vsftpd 2.3.4" in blob:
        return "CVE-2011-2523"
    for keywords, cve in _CVE_HINTS:
        if all(keyword in blob for keyword in keywords):
            return cve
    return None


def _module_hint(observation: ReconObservation) -> str | None:
    blob = _observation_blob(observation)
    if _is_windows_xp_smb(observation):
        return (
            "Recon-derived lab module hypothesis: exploit/windows/smb/ms08_067_netapi. "
            "The SMB fingerprint indicates Windows XP over SMB, which is historically associated "
            "with MS08-067/CVE-2008-4250 on unpatched systems; this is a candidate for authorized "
            "validation rather than proof that the host is vulnerable."
        )
    if observation.port == 21 and observation.ftp_anonymous is True:
        return (
            "Recon-derived lab module hypothesis: auxiliary/scanner/ftp/anonymous. "
            "Anonymous FTP access is a configuration finding for authorized validation, not code execution."
        )
    if observation.service and observation.service.lower() in {"ssh"} and observation.ssh_algorithms:
        return (
            "Recon-derived module hypothesis: auxiliary/scanner/ssh/ssh_version. "
            "SSH enrichment observed host keys or algorithms; this supports version/crypto assessment only."
        )
    if observation.nfs_exports:
        return (
            "Recon-derived module hypothesis: auxiliary/scanner/nfs/nfsmount. "
            "NFS exports were observed and should be validated as exposure, not exploited automatically."
        )
    if observation.port in {139, 445} and "samba" in blob and "3.x" in blob:
        return (
            "Recon-derived lab module hypothesis: exploit/multi/samba/usermap_script. "
            "Nmap did not identify the exact Samba 3.0.20 version, so this is a candidate for "
            "authorized validation rather than a confirmed CVE assertion."
        )
    return None


def _web_application_hints(observation: ReconObservation) -> list[str]:
    hints: list[str] = []
    robots_resources = _robots_txt_resources(observation)
    if robots_resources:
        hints.append(f"robots.txt exposes resource(s): {', '.join(robots_resources[:8])}.")
    for page in observation.web_pages:
        if page.status_code == 404 or page.soft_404:
            continue
        haystack = " ".join(
            [
                page.path,
                page.title or "",
                page.meta_generator or "",
                " ".join(page.links),
                " ".join(page.detected_technologies),
                " ".join(page.extracted_versions),
                " ".join(page.interesting_reasons),
                " ".join(page.comments),
                " ".join(f"{key}: {value}" for key, value in page.headers.items()),
            ]
        ).lower()
        if "local file inclusion" in haystack or "lfi" in haystack or "file inclusion" in haystack:
            hints.append(
                f"Possible LFI/file inclusion clue observed around {page.path}; validate manually without automated exploit execution."
            )
        if "auth_realm" in haystack or "www-authenticate" in haystack or page.status_code == 401:
            hints.append(f"Authentication-protected web path observed at {page.path}; investigate exposure and access policy.")
        if any(token in page.path.lower() for token in ("dev-login", "admin", "login")) and not page.low_content:
            hints.append(f"Interesting authentication or admin-like path observed at {page.path}.")
        if "real_login_form_candidate" in page.workflow_tags:
            hints.append(
                f"Application workflow hint: real login form candidate observed at {page.path}; "
                "validate authentication behavior manually without credential attacks."
            )
        if "file_upload_form_candidate" in page.workflow_tags:
            hints.append(
                f"Application workflow hint: upload form candidate observed at {page.path}; "
                "validate file handling and access policy manually without uploading payloads."
            )
        if "file_path_parameter_candidate" in page.workflow_tags:
            params = ", ".join(page.query_parameters[:4] or page.form_parameters[:4])
            hints.append(
                f"Application workflow hint: file/path-like parameter(s) observed at {page.path}"
                f"{f' ({params})' if params else ''}; consider LFI/path traversal manual validation."
            )
        if "sqli_relevant_parameter_candidate" in page.workflow_tags:
            params = ", ".join(page.query_parameters[:4] or page.form_parameters[:4])
            hints.append(
                f"Application workflow hint: SQLi-relevant form/query parameter(s) observed at {page.path}"
                f"{f' ({params})' if params else ''}; validate input handling manually without automated exploitation."
            )
        for match in match_application_knowledge(haystack):
            location = f" at {page.path}" if page.path else ""
            hints.append(
                f"Knowledge-base application hint ({match.entry.kb_id}){location}: "
                f"{match.entry.risk_type}; {match.entry.validation_focus}"
            )
    return list(dict.fromkeys(hints))[:8]


def _robots_txt_resources(observation: ReconObservation) -> list[str]:
    resources: list[str] = []
    for page in observation.web_pages:
        if (
            page.path.rstrip("/").lower() != "/robots.txt"
            or not page.raw_content
            or not _metadata_file_content_is_usable(page)
        ):
            continue
        for raw_line in page.raw_content.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            lowered = line.lower()
            if lowered.startswith(("user-agent:", "allow:", "crawl-delay:", "host:", "clean-param:", "request-rate:", "visit-time:")):
                continue
            if lowered.startswith(("disallow:", "sitemap:")):
                line = line.split(":", 1)[1].strip()
            if not line or line == "/":
                continue
            if ":" in line and not line.startswith(("http://", "https://")):
                continue
            resources.append(line)
    return list(dict.fromkeys(resources))


def _filtered_metadata_content(raw_content: str) -> str:
    lines: list[str] = []
    for raw_line in raw_content.splitlines():
        line = raw_line.strip()
        lowered = line.lower()
        if lowered.startswith(("user-agent:", "allow:", "crawl-delay:", "host:", "clean-param:", "request-rate:", "visit-time:")):
            continue
        lines.append(raw_line)
    return "\n".join(lines)


def _metadata_file_content_is_usable(page) -> bool:
    if page.status_code not in {200, 204, None}:
        return False
    content_type = " ".join(
        value for key, value in page.headers.items() if key.lower() == "content-type"
    ).lower()
    text = (page.raw_content or "").lstrip("\ufeff").lstrip().lower()
    if "text/html" in content_type or "application/xhtml+xml" in content_type:
        return False
    if text.startswith("<"):
        return False
    if text.startswith(("<!doctype html", "<html", "<head", "<body")):
        return False
    if any(marker in text[:300] for marker in ("<title>404", "<title>403", "not found</title>", "forbidden</title>")):
        return False
    return True


def _login_surface_observed(observation: ReconObservation) -> bool:
    for page in observation.web_pages:
        haystack = " ".join(
            [
                page.path,
                page.title or "",
                page.meta_generator or "",
                " ".join(page.links),
                " ".join(page.forms),
                " ".join(page.input_fields),
                " ".join(page.detected_technologies),
            ]
        ).lower()
        if "wp-login.php" in haystack or "loginform" in haystack:
            return True
        if any(token in page.path.lower() for token in ("login", "signin", "auth", "admin")) and (
            page.forms or page.input_fields or "password" in haystack
        ):
            return True
    return False


def _sensitive_looking_resources(resources: list[str]) -> list[str]:
    markers = ("key", "flag", "secret", "token", "credential", "password", "backup", "config")
    return [resource for resource in resources if any(marker in resource.lower() for marker in markers)]


def _truncate(value: str, limit: int) -> str:
    text = " ".join(value.split())
    return text[:limit] + ("..." if len(text) > limit else "")


def _is_windows_xp_smb(observation: ReconObservation) -> bool:
    blob = _observation_blob(observation)
    return observation.port in {139, 445} and "windows xp" in blob and (
        "microsoft-ds" in blob or "netbios" in blob or "smb" in blob
    )


def _observation_blob(observation: ReconObservation) -> str:
    return " ".join(
        part.lower()
        for part in [
            observation.service or "",
            observation.version or "",
            observation.product or "",
            " ".join(observation.ftp_features),
            " ".join(observation.ssh_algorithms),
            " ".join(observation.rpc_services),
            " ".join(observation.nfs_exports),
            " ".join(f"{key} {value}" for key, value in observation.db_info.items()),
            " ".join(f"{key} {value}" for key, value in observation.tls_cert.items()),
            observation.smb_os or "",
            " ".join(observation.smb_dialects),
            " ".join(observation.cpe),
        ]
        if part
    )


def _append_note(existing: str | None, addition: str) -> str:
    if not existing:
        return addition
    if addition in existing:
        return existing
    return f"{existing} {addition}"


def _prefer_service(left: str | None, right: str | None) -> str | None:
    if not left:
        return right
    if not right:
        return left
    if left.lower() in {"http", "https"}:
        return left
    if right.lower() in {"http", "https"}:
        return right
    return left


def _first_target_ip(observations: list[ReconObservation]) -> str | None:
    return observations[0].target_ip if observations else None


def _observed_os(observations: list[ReconObservation]) -> str | None:
    for observation in observations:
        if observation.smb_os:
            return observation.smb_os
    return None


def _target_from_infra_path(infra_path: str) -> str:
    if infra_path.startswith("scan-only:"):
        return infra_path.split(":", 1)[1]
    return "0.0.0.0"


def _safe_id(ip: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]+", "_", ip).strip("_") or "target"
