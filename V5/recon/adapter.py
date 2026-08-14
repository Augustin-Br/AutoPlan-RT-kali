"""Bridge recon reports / V2 infra into V5InfraDocument and compute diffs."""

from __future__ import annotations

from V2.models import InfraDocumentInput
from V2.recon_models import ReconReport
from V2.recon_to_infra import DEFAULT_SCAN_OBJECTIVE, infra_from_recon_report
from V5.models import V5InfraDocument
from V5.recon.models import InfraDiff

DEFAULT_SECURITY_NOTES = (
    "Lab environment: symbolic scenario generation only after optional bounded recon. "
    "Documented service observations are training evidence, not confirmed exploitability."
)


def v2_infra_to_v5(infra: InfraDocumentInput, *, objective: str | None = None) -> V5InfraDocument:
    payload = infra.model_dump(mode="json")
    resolved_objective = objective or payload.get("objective") or payload.get("scenario_objective") or ""
    machines = []
    for machine in payload.get("machines", []):
        services = []
        for service in machine.get("services", []):
            notes = service.get("notes") or service.get("service_observations")
            services.append(
                {
                    "port": service.get("port"),
                    "service": service.get("service") or "unknown",
                    "version": service.get("version"),
                    "cve": service.get("cve"),
                    "service_observations": notes,
                }
            )
        machines.append(
            {
                "id": machine.get("id"),
                "ip": machine.get("ip"),
                "zone": machine.get("zone"),
                "os": machine.get("os"),
                "services": services,
                "regles_firewall": machine.get("regles_firewall"),
                "security_notes": machine.get("security_notes"),
            }
        )
    return V5InfraDocument.model_validate(
        {
            "entreprise": payload.get("entreprise"),
            "reseaux": payload.get("reseaux") or [],
            "machines": machines,
            "attaquant": payload.get("attaquant"),
            "attack_objective": resolved_objective,
            "scenario_objective": resolved_objective,
            "apt_profile": payload.get("apt_profile"),
            "pistes_documentees": payload.get("pistes_documentees") or [],
            "security_notes": payload.get("security_notes") or DEFAULT_SECURITY_NOTES,
            "network_policies": payload.get("network_policies") or [],
        }
    )


def recon_report_to_v5(
    report: ReconReport,
    *,
    target_ip: str | None = None,
    objective: str = DEFAULT_SCAN_OBJECTIVE,
) -> V5InfraDocument:
    v2_infra = infra_from_recon_report(report, target_ip=target_ip, objective=objective)
    return v2_infra_to_v5(v2_infra, objective=objective)


def merge_v5_infras(base: V5InfraDocument, enrichment: V5InfraDocument) -> V5InfraDocument:
    """Merge scan-derived facts into a seed infra (add ports / enrich notes)."""

    merged = base.model_copy(deep=True)
    if enrichment.attack_objective and not merged.attack_objective:
        merged.attack_objective = enrichment.attack_objective
    machines_by_ip = {machine.ip: machine for machine in merged.machines}

    for incoming in enrichment.machines:
        existing = machines_by_ip.get(incoming.ip)
        if existing is None:
            merged.machines.append(incoming.model_copy(deep=True))
            machines_by_ip[incoming.ip] = merged.machines[-1]
            continue
        if incoming.os and (not existing.os or existing.os.lower() in {"unknown", "linux", "linux lab"}):
            existing.os = incoming.os
        services_by_port = {service.port: service for service in existing.services}
        for service in incoming.services:
            current = services_by_port.get(service.port)
            if current is None:
                existing.services.append(service.model_copy(deep=True))
                continue
            if service.service and (
                not current.service or current.service.lower() in {"unknown", "tcp", "other"}
            ):
                current.service = service.service
            if service.version and not current.version:
                current.version = service.version
            if service.cve and not current.cve:
                current.cve = service.cve
            if service.service_observations:
                current.service_observations = _append_note(
                    current.service_observations,
                    service.service_observations,
                )
    if enrichment.reseaux and not merged.reseaux:
        merged.reseaux = list(enrichment.reseaux)
    return merged


def empty_seed_infra(*, target_ip: str, objective: str) -> V5InfraDocument:
    return V5InfraDocument.model_validate(
        {
            "entreprise": "Scan-only authorized lab target",
            "reseaux": [{"nom": "scan-only-target", "sous_reseau": f"{target_ip}/32"}],
            "machines": [
                {
                    "id": f"scan_{target_ip.replace('.', '_')}",
                    "ip": target_ip,
                    "zone": "scan-only",
                    "os": "Unknown",
                    "services": [],
                }
            ],
            "attack_objective": objective,
            "security_notes": (
                "Seed for bounded reconnaissance; services are filled from scan observations."
            ),
        }
    )


def diff_infras(before: V5InfraDocument | None, after: V5InfraDocument) -> InfraDiff:
    if before is None:
        added = [
            {"ip": machine.ip, "port": service.port, "service": service.service}
            for machine in after.machines
            for service in machine.services
        ]
        return InfraDiff(
            ports_added=added,
            machines_added=[machine.id for machine in after.machines],
            summary=f"Created infra with {len(added)} observed service(s).",
        )

    before_ports = {
        (machine.ip, service.port): service
        for machine in before.machines
        for service in machine.services
    }
    before_machines = {machine.ip: machine for machine in before.machines}
    ports_added: list[dict] = []
    ports_updated: list[dict] = []
    notes_enriched: list[dict] = []
    machines_added: list[str] = []

    for machine in after.machines:
        if machine.ip not in before_machines:
            machines_added.append(machine.id)
        for service in machine.services:
            key = (machine.ip, service.port)
            previous = before_ports.get(key)
            if previous is None:
                ports_added.append(
                    {"ip": machine.ip, "port": service.port, "service": service.service}
                )
                continue
            changed: list[str] = []
            if (service.version or "") != (previous.version or ""):
                changed.append("version")
            if (service.service or "") != (previous.service or ""):
                changed.append("service")
            prev_notes = previous.service_observations or ""
            new_notes = service.service_observations or ""
            if new_notes and new_notes != prev_notes and len(new_notes) > len(prev_notes):
                notes_enriched.append({"ip": machine.ip, "port": service.port})
                changed.append("notes")
            if changed:
                ports_updated.append(
                    {"ip": machine.ip, "port": service.port, "changed": changed}
                )

    summary = (
        f"+{len(ports_added)} port(s), "
        f"{len(ports_updated)} updated, "
        f"{len(notes_enriched)} notes enriched, "
        f"{len(machines_added)} machine(s) added."
    )
    return InfraDiff(
        ports_added=ports_added,
        ports_updated=ports_updated,
        machines_added=machines_added,
        notes_enriched=notes_enriched,
        summary=summary,
    )


def _append_note(existing: str | None, addition: str) -> str:
    addition = addition.strip()
    if not addition:
        return existing or ""
    if not existing:
        return addition
    if addition in existing:
        return existing
    return f"{existing.rstrip()} | {addition}"
