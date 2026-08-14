"""Parsers for bounded reconnaissance outputs."""

from __future__ import annotations

import re

from V2.recon_models import ReconObservation

NMAP_SERVICE_RE = re.compile(
    r"^(?P<port>\d+)/(?P<protocol>\w+)\s+open\s+(?P<service>\S+)(?:\s+(?P<version>.*))?$"
)


def parse_nmap_sv(output: str, *, target_ip: str, evidence_ref: str | None = None) -> list[ReconObservation]:
    observations: list[ReconObservation] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        match = NMAP_SERVICE_RE.match(line)
        if not match:
            continue
        version = (match.group("version") or "").strip() or None
        observations.append(
            ReconObservation(
                target_ip=target_ip,
                port=int(match.group("port")),
                protocol=match.group("protocol"),
                service=match.group("service"),
                version=version,
                product=_product_from_version(version),
                raw_evidence_ref=evidence_ref,
            )
        )
    return observations


def parse_curl_headers(output: str, *, target_ip: str, port: int, evidence_ref: str | None = None) -> ReconObservation:
    headers: dict[str, str] = {}
    technologies: list[str] = []
    for line in output.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        headers[key] = value
        if key.lower() in {"server", "x-powered-by"}:
            technologies.append(value)
    return ReconObservation(
        target_ip=target_ip,
        port=port,
        protocol="tcp",
        service="HTTP",
        web_headers=headers,
        detected_technologies=technologies,
        raw_evidence_ref=evidence_ref,
    )


def parse_nmap_smb_metadata(
    output: str,
    *,
    target_ip: str,
    ports: list[int],
    evidence_ref: str | None = None,
) -> list[ReconObservation]:
    metadata = _parse_smb_script_metadata(output)
    if not metadata:
        return []
    observations: list[ReconObservation] = []
    for port in sorted(set(ports or [445])):
        observations.append(
            ReconObservation(
                target_ip=target_ip,
                port=port,
                protocol="tcp",
                service="SMB",
                version=metadata.get("os"),
                product="Microsoft" if "windows" in (metadata.get("os") or "").lower() else None,
                cpe=[metadata["os_cpe"]] if metadata.get("os_cpe") else [],
                smb_os=metadata.get("os"),
                smb_computer_name=metadata.get("computer_name") or metadata.get("netbios_computer_name"),
                smb_domain=metadata.get("domain_name"),
                smb_workgroup=metadata.get("workgroup"),
                smb_dialects=metadata.get("dialects", []),
                smb_security_mode=metadata.get("security_mode", {}),
                raw_evidence_ref=evidence_ref,
            )
        )
    return observations


def parse_nmap_protocol_metadata(
    output: str,
    *,
    target_ip: str,
    ports: list[int],
    probe: str,
    evidence_ref: str | None = None,
) -> list[ReconObservation]:
    metadata = _parse_script_sections(output)
    if not metadata:
        return []
    observations: list[ReconObservation] = []
    for port in sorted(set(ports)):
        service = _service_for_probe(probe, port)
        observations.append(
            ReconObservation(
                target_ip=target_ip,
                port=port,
                protocol="tcp",
                service=service,
                scripts=metadata,
                ftp_anonymous=_ftp_anonymous(metadata) if probe == "ftp" else None,
                ftp_features=_script_lines(metadata, ("ftp-syst",)),
                ssh_hostkeys=_script_lines(metadata, ("ssh-hostkey",)),
                ssh_algorithms=_script_lines(metadata, ("ssh2-enum-algos",)),
                db_info=_db_info(metadata) if probe == "db" else {},
                rpc_services=_script_lines(metadata, ("rpcinfo",)),
                nfs_exports=_nfs_exports(metadata),
                tls_cert=_tls_cert(metadata) if probe == "tls" else {},
                tls_ciphers=_script_lines(metadata, ("ssl-enum-ciphers",)),
                raw_evidence_ref=evidence_ref,
            )
        )
    return observations


def _product_from_version(version: str | None) -> str | None:
    if not version:
        return None
    return version.split(" ", 1)[0]


def _parse_smb_script_metadata(output: str) -> dict:
    metadata: dict = {"dialects": [], "security_mode": {}}
    current_script: str | None = None
    for raw_line in output.splitlines():
        stripped = raw_line.strip()
        if stripped.startswith("| smb-os-discovery:"):
            current_script = "os"
            continue
        if stripped.startswith("| smb-protocols:"):
            current_script = "protocols"
            continue
        if stripped.startswith("| smb-security-mode:"):
            current_script = "security"
            continue
        if stripped.startswith("|_"):
            content = stripped[2:].strip()
            _parse_smb_script_line(content, current_script, metadata)
            current_script = None
            continue
        if stripped.startswith("|"):
            content = stripped[1:].strip()
            _parse_smb_script_line(content, current_script, metadata)
    return metadata if any(value for value in metadata.values()) else {}


def _parse_smb_script_line(content: str, current_script: str | None, metadata: dict) -> None:
    if not content:
        return
    if current_script == "protocols":
        if content.endswith(":") or content == "dialects:":
            return
        metadata.setdefault("dialects", []).append(content)
        return
    if ":" not in content:
        return
    key, value = content.split(":", 1)
    key_norm = key.strip().lower().replace(" ", "_")
    value = value.strip()
    if not value:
        return
    if current_script == "security":
        metadata.setdefault("security_mode", {})[key_norm] = value
        return
    if current_script == "os":
        metadata[key_norm] = value


def _parse_script_sections(output: str) -> dict[str, str]:
    sections: dict[str, list[str]] = {}
    current_script: str | None = None
    for raw_line in output.splitlines():
        stripped = raw_line.strip()
        if stripped.startswith("|_"):
            content = stripped[2:].strip()
            if current_script and content:
                sections.setdefault(current_script, []).append(content)
            current_script = None
            continue
        if not stripped.startswith("|"):
            continue
        content = stripped[1:].strip()
        if not content:
            continue
        if ":" in content:
            maybe_script, rest = content.split(":", 1)
            if _looks_like_script_name(maybe_script):
                current_script = maybe_script.strip()
                if rest.strip():
                    sections.setdefault(current_script, []).append(rest.strip())
                continue
        if current_script:
            sections.setdefault(current_script, []).append(content)
    return {script: "\n".join(lines).strip() for script, lines in sections.items() if lines}


def _looks_like_script_name(value: str) -> bool:
    return value.strip() in {
        "ftp-anon",
        "ftp-syst",
        "ssh-hostkey",
        "ssh2-enum-algos",
        "mysql-info",
        "pgsql-info",
        "ms-sql-info",
        "rpcinfo",
        "nfs-showmount",
        "ssl-cert",
        "ssl-enum-ciphers",
    }


def _service_for_probe(probe: str, port: int) -> str:
    if probe == "ftp":
        return "FTP"
    if probe == "ssh":
        return "SSH"
    if probe == "db":
        if port == 5432:
            return "PostgreSQL"
        if port == 1433:
            return "MSSQL"
        return "MySQL"
    if probe == "rpc_nfs":
        return "NFS" if port == 2049 else "RPC"
    if probe == "tls":
        return "HTTPS"
    return probe.upper()


def _script_lines(metadata: dict[str, str], names: tuple[str, ...]) -> list[str]:
    lines: list[str] = []
    for name in names:
        for line in metadata.get(name, "").splitlines():
            value = line.strip()
            if value:
                lines.append(value)
    return list(dict.fromkeys(lines))


def _ftp_anonymous(metadata: dict[str, str]) -> bool | None:
    text = metadata.get("ftp-anon", "").lower()
    if not text:
        return None
    if "anonymous ftp login allowed" in text or "anonymous login allowed" in text:
        return True
    if "can't get directory listing" in text or "anonymous ftp login" in text:
        return False
    return None


def _db_info(metadata: dict[str, str]) -> dict[str, str]:
    info: dict[str, str] = {}
    for script in ("mysql-info", "pgsql-info", "ms-sql-info"):
        for line in metadata.get(script, "").splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            key = key.strip().lower().replace(" ", "_")
            value = value.strip()
            if key and value:
                info[key] = value
    return info


def _nfs_exports(metadata: dict[str, str]) -> list[str]:
    exports = []
    for line in metadata.get("nfs-showmount", "").splitlines():
        value = line.strip()
        if value.startswith("/"):
            exports.append(value)
    return list(dict.fromkeys(exports))


def _tls_cert(metadata: dict[str, str]) -> dict[str, str]:
    cert: dict[str, str] = {}
    for line in metadata.get("ssl-cert", "").splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower().replace(" ", "_")
        value = value.strip()
        if key in {"subject", "issuer", "not_valid_before", "not_valid_after"} and value:
            cert[key] = value
    return cert
