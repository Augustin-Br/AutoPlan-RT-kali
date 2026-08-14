"""Safety policy for bounded reconnaissance.

The policy only builds commands from structured topology data. It never accepts
free-form commands from an LLM or user input.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict

from V2.models import InfraDocumentInput, load_infra_document
from V2.recon_models import ReconCommandPlan

DEFAULT_TOOLS = ("nmap", "curl")
IP_ONLY_SAFE_TOOLS = ("nmap", "curl", "dirb", "wpscan")
DEFAULT_VHOST_PREFIXES = ("www", "admin", "dev", "test", "api", "app", "portal", "intranet")


def allowed_networks(infra: InfraDocumentInput) -> list[ipaddress._BaseNetwork]:
    networks: list[ipaddress._BaseNetwork] = []
    for item in infra.reseaux:
        cidr = item.get("sous_reseau") if isinstance(item, dict) else None
        if not cidr:
            continue
        try:
            networks.append(ipaddress.ip_network(str(cidr), strict=False))
        except ValueError:
            continue
    return networks


def is_target_allowed(infra: InfraDocumentInput, target_ip: str) -> bool:
    try:
        ip = ipaddress.ip_address(target_ip)
    except ValueError:
        return False
    networks = allowed_networks(infra)
    return bool(networks) and any(ip in network for network in networks)


def is_private_lab_target(target_ip: str) -> bool:
    try:
        ip = ipaddress.ip_address(target_ip)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback


def allowed_ports_by_ip(infra: InfraDocumentInput) -> dict[str, set[int]]:
    ports: dict[str, set[int]] = defaultdict(set)
    for machine in infra.machines:
        for service in machine.services:
            ports[machine.ip].add(service.port)
    return dict(ports)


def build_command_plan(
    infra_or_path: InfraDocumentInput | str,
    *,
    tools: tuple[str, ...] = DEFAULT_TOOLS,
    profile: str = "safe",
) -> tuple[list[ReconCommandPlan], list[ReconCommandPlan]]:
    infra = load_infra_document(infra_or_path) if isinstance(infra_or_path, str) else infra_or_path
    allowed_tools = set(tools)
    planned: list[ReconCommandPlan] = []
    skipped: list[ReconCommandPlan] = []
    ports_by_ip = allowed_ports_by_ip(infra)

    for machine in infra.machines:
        ports = sorted(ports_by_ip.get(machine.ip, set()))
        if not ports:
            continue
        if not is_target_allowed(infra, machine.ip):
            skipped.append(
                ReconCommandPlan(
                    tool="nmap",
                    target_ip=machine.ip,
                    ports=ports,
                    profile=profile,
                    command="",
                    rationale="Target IP is outside declared CyberRange networks.",
                    safety_status="blocked",
                )
            )
            continue
        if "nmap" in allowed_tools:
            planned.append(
                ReconCommandPlan(
                    tool="nmap",
                    target_ip=machine.ip,
                    ports=ports,
                    profile=profile,
                    command=f"nmap -sV -p {','.join(str(port) for port in ports)} {machine.ip}",
                    rationale="Safe service/version detection restricted to ports declared in the JSON topology.",
                    safety_status="allowed",
                )
            )
        if "curl" in allowed_tools:
            for service in machine.services:
                if service.service.lower() not in {"http", "https"}:
                    continue
                scheme = "https" if service.service.lower() == "https" or service.port == 443 else "http"
                planned.append(
                    ReconCommandPlan(
                        tool="curl",
                        target_ip=machine.ip,
                        ports=[service.port],
                        profile=profile,
                        command=f"curl -I {scheme}://{machine.ip}:{service.port}/",
                        rationale="HTTP header retrieval only; no crawling, brute force, or exploit probe.",
                        safety_status="allowed",
                    )
                )
    return planned, skipped


def build_ip_command_plan(
    target_ip: str,
    *,
    tools: tuple[str, ...] = IP_ONLY_SAFE_TOOLS,
    profile: str = "safe",
) -> tuple[list[ReconCommandPlan], list[ReconCommandPlan]]:
    """Build a bounded reconnaissance plan from a single lab IP.

    This path intentionally starts with lightweight service/version detection.
    Follow-up HTTP header checks are added after nmap observations are parsed.
    """

    allowed_tools = {tool.strip().lower() for tool in tools}
    planned: list[ReconCommandPlan] = []
    skipped: list[ReconCommandPlan] = []

    if not is_private_lab_target(target_ip):
        return [], [
            ReconCommandPlan(
                tool="nmap",
                target_ip=target_ip,
                ports=[],
                profile=profile,
                command="",
                rationale="Target IP is not a private or loopback lab address.",
                safety_status="blocked",
            )
        ]

    if "nmap" in allowed_tools:
        planned.append(
            ReconCommandPlan(
                tool="nmap",
                target_ip=target_ip,
                ports=[],
                profile=profile,
                command=f"nmap -sV --version-light -Pn {target_ip}",
                rationale="Safe service/version detection against the target IP only.",
                safety_status="allowed",
            )
        )

    for unsupported in sorted(allowed_tools - {"nmap", "curl", "dirb", "wpscan"}):
        skipped.append(
            ReconCommandPlan(
                tool=unsupported,
                target_ip=target_ip,
                ports=[],
                profile=profile,
                command="",
                rationale="Tool not enabled in the safe IP-only reconnaissance profile.",
                safety_status="skipped",
            )
        )

    return planned, skipped


def build_http_followup_plan(
    target_ip: str,
    ports: list[int],
    *,
    profile: str = "safe",
) -> list[ReconCommandPlan]:
    planned: list[ReconCommandPlan] = []
    for port in sorted(set(ports)):
        scheme = "https" if port == 443 else "http"
        planned.append(
            ReconCommandPlan(
                tool="curl",
                target_ip=target_ip,
                ports=[port],
                profile=profile,
                command=f"curl -I --max-time 10 {scheme}://{target_ip}:{port}/",
                rationale="HTTP header retrieval only after nmap identified an HTTP-like service.",
                safety_status="allowed",
            )
        )
    return planned


def build_web_probe_plan(
    target_ip: str,
    ports: list[int],
    *,
    hostnames: tuple[str, ...] = (),
    profile: str = "safe",
) -> list[ReconCommandPlan]:
    planned: list[ReconCommandPlan] = []
    for port in sorted(set(ports)):
        scheme = "https" if port == 443 else "http"
        hosts = tuple(dict.fromkeys([*hostnames, target_ip]))
        for host in hosts:
            planned.append(
                ReconCommandPlan(
                    tool="dirb",
                    target_ip=target_ip,
                    hostname=host if host != target_ip else None,
                    ports=[port],
                    profile=profile,
                    command=_dirb_command(target_ip, port, scheme, host),
                    rationale=(
                        "Bounded directory discovery with dirb; no vulnerability scripts, "
                        "payloads, credential attempts, or recursive crawling."
                    ),
                    safety_status="allowed",
                )
            )
    return planned


def build_wpscan_followup_plan(
    target_ip: str,
    port: int,
    *,
    base_path: str = "/",
    sort_strategy: str = "success",
    profile: str = "safe",
) -> list[ReconCommandPlan]:
    scheme = "https" if port == 443 else "http"
    normalized_base = base_path if base_path.startswith("/") else f"/{base_path}"
    if not normalized_base.endswith("/"):
        normalized_base = normalized_base.rsplit("/", 1)[0] + "/"
    enumerate_flags = "vp,vt" if (sort_strategy or "").lower() == "stealth" else "vp,vt,u"
    return [
        ReconCommandPlan(
            tool="wpscan",
            target_ip=target_ip,
            ports=[port],
            profile=profile,
            command=(
                f"wpscan --url {scheme}://{target_ip}:{port}{normalized_base} "
                f"--enumerate {enumerate_flags} --no-update"
            ),
            rationale=(
                "Bounded WordPress enumeration after WordPress was observed in HTTP evidence; "
                "no password attack, payload, exploit execution, or brute-force option is used."
            ),
            safety_status="allowed",
        )
    ]


def build_smb_followup_plan(
    target_ip: str,
    ports: list[int],
    *,
    profile: str = "safe",
) -> list[ReconCommandPlan]:
    smb_ports = sorted(port for port in set(ports) if port in {139, 445})
    if not smb_ports:
        return []
    return [
        ReconCommandPlan(
            tool="nmap",
            target_ip=target_ip,
            ports=smb_ports,
            profile=profile,
            command=(
                "nmap -Pn --max-retries 1 --host-timeout 60s "
                f"-p {','.join(str(port) for port in smb_ports)} "
                "--script smb-os-discovery,smb-protocols,smb-security-mode "
                f"{target_ip}"
            ),
            rationale=(
                "Bounded SMB metadata discovery with non-vulnerability Nmap scripts; "
                "no brute force, payloads, or exploit checks."
            ),
            safety_status="allowed",
        )
    ]


def build_protocol_followup_plan(
    target_ip: str,
    service_ports: dict[str, list[int]],
    *,
    profile: str = "safe",
) -> list[ReconCommandPlan]:
    planned: list[ReconCommandPlan] = []
    for probe, ports in sorted(service_ports.items()):
        scripts = _scripts_for_probe(probe)
        if not scripts:
            continue
        for port in sorted(set(ports)):
            planned.append(
                ReconCommandPlan(
                    tool="nmap",
                    target_ip=target_ip,
                    ports=[port],
                    profile=profile,
                    command=(
                        "nmap -Pn --max-retries 1 --host-timeout 60s "
                        f"-p {port} --script {scripts} {target_ip}"
                    ),
                    rationale=(
                        f"Bounded {probe.upper()} metadata discovery with non-vulnerability Nmap scripts; "
                        "no brute force, payloads, or exploit checks."
                    ),
                    safety_status="allowed",
                )
            )
    return planned


def _scripts_for_probe(probe: str) -> str | None:
    return {
        "ftp": "ftp-anon,ftp-syst",
        "ssh": "ssh2-enum-algos,ssh-hostkey",
        "db": "mysql-info,pgsql-info,ms-sql-info",
        "rpc_nfs": "rpcinfo,nfs-showmount",
        "tls": "ssl-cert,ssl-enum-ciphers",
    }.get(probe)


def _dirb_command(target_ip: str, port: int, scheme: str, host: str) -> str:
    base_url = f"{scheme}://{target_ip}:{port}/"
    if host == target_ip:
        return f"dirb {base_url} -S -r"
    return f"dirb {base_url} -S -r -H 'Host: {host}'"


FORBIDDEN_TOKENS = (
    "metasploit",
    "msfconsole",
    "hydra",
    "sqlmap",
    "--script vuln",
    "brute",
    "payload",
    "reverse",
    "shell",
)


def command_is_safe(command: str) -> bool:
    text = command.lower()
    return not any(token in text for token in FORBIDDEN_TOKENS)
