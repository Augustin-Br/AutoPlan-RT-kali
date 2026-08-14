"""Load V5 infrastructure documents with backward-compatible field aliases."""

from __future__ import annotations

import json
from pathlib import Path

from V2.models import InfraDocumentInput
from V5.models import V5InfraDocument


def load_v5_infra(path: str | Path) -> V5InfraDocument:
  payload = json.loads(Path(path).read_text(encoding="utf-8"))
  return V5InfraDocument.model_validate(payload)


def to_v2_infra_input(infra: V5InfraDocument) -> InfraDocumentInput:
  """Bridge V5 service_observations to V2 notes for evidence extraction."""
  machines = []
  for machine in infra.machines:
    services = []
    for service in machine.services:
      services.append(
        {
          "port": service.port,
          "service": service.service,
          "version": service.version,
          "cve": service.cve,
          "notes": service.service_observations,
        }
      )
    machines.append(
      {
        "id": machine.id,
        "ip": machine.ip,
        "zone": machine.zone,
        "os": machine.os,
        "services": services,
        "regles_firewall": machine.regles_firewall,
      }
    )
  objective = infra.attack_objective or infra.scenario_objective or ""
  return InfraDocumentInput.model_validate(
    {
      "entreprise": infra.entreprise,
      "reseaux": infra.reseaux,
      "machines": machines,
      "attaquant": infra.attaquant,
      "scenario_objective": objective,
      "apt_profile": infra.apt_profile,
    }
  )


def normalize_for_prompt(infra: V5InfraDocument) -> dict:
  """Flatten infra for LLM prompts with V5 field names."""
  data = infra.model_dump(mode="json", by_alias=False)
  machines = []
  for machine in infra.machines:
    services = []
    for service in machine.services:
      services.append(
        {
          "port": service.port,
          "service": service.service,
          "version": service.version,
          "cve": service.cve,
          "service_observations": service.service_observations,
        }
      )
    machines.append(
      {
        "id": machine.id,
        "ip": machine.ip,
        "zone": machine.zone,
        "os": machine.os,
        "security_notes": machine.security_notes,
        "regles_firewall": machine.regles_firewall,
        "services": services,
      }
    )
  return {
    "attack_objective": infra.attack_objective,
    "security_notes": infra.security_notes,
    "network_policies": [policy.model_dump() for policy in infra.network_policies],
    "apt_profile": infra.apt_profile,
    "attaquant": infra.attaquant,
    "pistes_documentees": data.get("pistes_documentees") or [],
    "machines": machines,
    "raw": data,
  }


def retarget_machines(infra: V5InfraDocument, target_ip: str) -> V5InfraDocument:
    """Rewrite every machine IP (lab DHCP) while keeping writeup notes."""
    updated = infra.model_copy(deep=True)
    for machine in updated.machines:
        machine.ip = target_ip
    return updated
