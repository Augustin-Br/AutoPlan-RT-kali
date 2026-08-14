# V5 HITL ranked-path runtime (post-FPS)

Optional **human-in-the-loop** execution of ranked attack-path drafts after the offline V5 generation/validation loop. This layer was added **after FPS 2026 submission (#6489)**; it does not change the paper’s drafting claims.

## Flow

1. Load `ranked_paths` (from a V5 result JSON or live CLI).
2. For each path (best first):
   - **Allowlist review:** tools outside the effective allowlist (base ∪ session) are listed; the operator may `add` them to the session allowlist, `skip`, `skip-all`, or `abort-path`.
   - **Per step:** `y` / `n` / `skip` / `abort`.
   - `y` + tool on allowlist + template + not exploit/MSF → **auto-run**.
   - otherwise → **manual** outcome (`success` / `fail`).
3. On `n`, auto-run failure, or manual `fail` → **fallback** to the next ranked path.
4. Session JSON records promotions, outcomes, and fallbacks.

## Allowlist

| Layer | Contents |
|-------|----------|
| Base | `nmap`, `curl`, `dirb`, `wpscan` |
| Session | Operator-promoted tools for this run only |

- LLM drafts may propose **any** tool; execution never auto-runs them until promotion.
- `exploit/*`, `auxiliary/*`, `post/*`, `msfconsole`: may be promoted for tracking; **auto-run only** if `--allow-auto-exploits` + `--i-understand-lab-only` (lab agent mode). Without that flag they stay manual / blocked in `--auto-execute`.
- Promoted tools without a command template stay **manual** (or block auto mode).

## Autonomous lab agent mode

See [`docs/v5_cyberrange_agent.md`](v5_cyberrange_agent.md). Summary:

```bash
PYTHONPATH=. python -m V5.cli \
  --target-ip 192.168.2.10 \
  --execute-recon --enable-llm \
  --execute-paths --auto-execute --allow-auto-exploits \
  --i-understand-lab-only
```

`--auto-execute` skips per-step prompts and auto-promotes missing tools. Exploits still require `--allow-auto-exploits`.

## CLI

```bash
# From a saved V5 result
PYTHONPATH=. python -m V5.runtime.cli \
  --from-result results/v5_out.json \
  --i-understand-lab-only \
  --runtime-output /tmp/runtime_session.json \
  --runtime-noninteractive /tmp/answers.txt

# Chained after generation
PYTHONPATH=. python -m V5.cli \
  --infra V5/benchmarks/infras/ms2_v5.json \
  --execute-paths \
  --i-understand-lab-only \
  --runtime-noninteractive answers.txt \
  --runtime-output /tmp/runtime.json \
  --output /tmp/v5_out.json
```

`--i-understand-lab-only` is **required**. Use only on authorized isolated lab targets.

## Scripted answers (tests)

One answer per line, in order of prompts (allowlist then steps):

```
add
y
y
success
```

## Boundary

| Drafting (FPS) | Runtime HITL |
|----------------|--------------|
| Offline path generation + neuro-symbolic validation | Assisted lab replay |
| No live exploitation claim | Explicit operator approvals |
| Ranked strategies | Fallback across top-k paths |
