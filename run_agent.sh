#!/usr/bin/env bash
# One-shot AutoPlan-RT agent on Kali (lab only).
set -euo pipefail
cd "$(dirname "$0")"
if [[ -f .venv/bin/activate ]]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi
export PYTHONPATH=.
TARGET_IP="${1:-192.168.2.10}"
OBJECTIVE="${2:-Authorized lab: recon then attempt ranked paths}"
INFRA="${INFRA:-}"
export HOME="${HOME:-/home/lade}"
export AUTOPLAN_LHOST="${AUTOPLAN_LHOST:-192.168.1.10}"

if [[ ! -f .env ]]; then
  echo "Create .env from .env.example and set your API key." >&2
  exit 1
fi

# shellcheck disable=SC1091
set -a
source .env
set +a

mkdir -p outputs
EXTRA=()
if [[ -n "$INFRA" ]]; then
  EXTRA+=(--infra "$INFRA")
fi
python -m V5.cli \
  "${EXTRA[@]}" \
  --target-ip "$TARGET_IP" \
  --objective "$OBJECTIVE" \
  --execute-recon \
  --recon-level 1 \
  --scan-tools nmap,curl,dirb,wpscan \
  --enable-llm \
  --llm-provider "${LLM_PROVIDER:-openai}" \
  --strategy balanced \
  --top-k 5 \
  --execute-paths \
  --auto-execute \
  --allow-auto-exploits \
  --runtime-timeout 300 \
  --output "outputs/v5_agent.json" \
  --runtime-output "outputs/v5_runtime.json" \
  --infra-output "outputs/v5_infra_enriched.json"

echo "Done. See outputs/"
