# V5 bounded reconnaissance layer

Optional **pre-phase** in front of the V5 attack-scenario loop. Recon collects inventory facts on **authorized private/lab targets**; it does **not** exploit hosts. Attack-path generation remains a separate loop.

## Autonomy levels

| Level | Flag | Behavior |
|-------|------|----------|
| **L0** | default without `--execute-recon` | Plan allowlisted commands only (dry-run). |
| **L1** | `--execute-recon` | Deterministic V2 pipeline: `nmap` then conditional `curl` / dirb / SMB / protocol / WPScan follow-ups. |
| **L2** | `--recon-llm` | After L1, propose extra scans from a **closed template catalog** (LLM or offline heuristics). No free-form shell. |
| Aggressive | `--recon-aggressive` | Unlocks deeper allowlisted enums (e.g. WPScan user enum). Still no exploit/brute tools. |

Live execution always requires **`--execute-recon`**. Public IPs are blocked.

## Safety

- Commands are built only by code ([`V2/recon_policy.py`](../V2/recon_policy.py) + [`V5/recon/policy_catalog.py`](../V5/recon/policy_catalog.py)).
- LLM output is `{template_id, target_ip, ports, …}` only; unknown templates are rejected.
- Blocklist includes Metasploit, hydra, sqlmap, vuln scripts, brute/payload/reverse/shell tokens.
- Budgets: `--recon-max-commands`, `--recon-max-seconds`, max L2 proposal rounds (default 3).

## CLI

### Recon only

```bash
PYTHONPATH=. python -m V5.recon.cli \
  --target-ip 192.168.56.114 \
  --objective "Obtain root on the lab VM" \
  --infra-output /tmp/enriched_infra.json \
  --recon-output /tmp/recon_phase.json
```

Execute L1:

```bash
PYTHONPATH=. python -m V5.recon.cli \
  --target-ip 192.168.56.114 \
  --objective "Obtain root on the lab VM" \
  --execute-recon \
  --infra-output /tmp/enriched_infra.json
```

Enrich an existing fixture (declared hosts):

```bash
PYTHONPATH=. python -m V5.recon.cli \
  --infra V5/benchmarks/infras/ms2_v5.json \
  --execute-recon \
  --infra-output /tmp/ms2_enriched.json
```

### Recon then attack-path loop

```bash
PYTHONPATH=. python -m V5.cli \
  --target-ip 192.168.56.114 \
  --objective "Obtain root on the lab VM" \
  --execute-recon \
  --recon-llm \
  --enable-llm \
  --infra-output /tmp/enriched_infra.json \
  --output /tmp/v5_paths.json
```

Static offline path generation (unchanged FPS workflow):

```bash
PYTHONPATH=. python -m V5.cli --infra V5/benchmarks/infras/ms2_v5.json --output /tmp/out.json
```

## Artifacts

- **Enriched infra** (`--infra-output`): `V5InfraDocument` with `service_observations` filled from scans.
- **Recon phase** (`--recon-output`): planned/executed/skipped commands, proposals, limitations, before/after diff.
- Path-loop exports include `trace.recon` when recon ran.

## Boundary vs attack loop

| Recon loop | Attack-scenario loop |
|------------|----------------------|
| Inventory scans only | Draft multi-step attack paths |
| Allowlisted templates | Neuro-symbolic path validator |
| Feeds evidence notes | Ranks strategies (`balanced`, …) |

Instructor review remains mandatory before cyber-range use.
