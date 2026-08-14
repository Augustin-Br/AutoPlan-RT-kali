# AutoPlan-RT — pack Kali (cyberrange)

Dépôt **minimal** à cloner sur la Kali LADE (recon → draft LLM → exécution lab).

Lab isolé uniquement (`--i-understand-lab-only --auto-execute --allow-auto-exploits`).

## Clone + install

```bash
git clone https://github.com/REPLACE_ME/AutoPlan-RT-kali.git
cd AutoPlan-RT-kali
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# éditer .env : GOOGLE_API_KEY=...  (ou OPENAI_API_KEY)
```

Outils système : `nmap`, `curl`, `dirb`, `wpscan`, `msfconsole`.

Si `git clone` échoue (pas de DNS), uploader le zip du dépôt via LADE.

## Lancer

Shopping (Net2) :

```bash
./run_agent.sh 192.168.2.10
```

MrRobot (infra writeup + IP DHCP) :

```bash
export HOME=/home/lade
export AUTOPLAN_LHOST=192.168.1.10
bash commande_kali
# ou :
INFRA=V5/benchmarks/infras/lade_mrrobot_v5.json ./run_agent.sh 192.168.2.12 \
  "Authorized lab: obtain foothold/root on MrRobot WordPress lab VM"
```

## Sorties

- `outputs/v5_agent.json` (ou `outputs/mrrobot/` via `commande_kali`)
- `outputs/v5_runtime.json`
- `outputs/v5_infra_enriched.json`

`path_success` = session MSF ouverte (ou recon utile), pas un simple exit 0.
