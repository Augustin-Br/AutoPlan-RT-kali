# Agent AutoPlan-RT sur Kali (cyberrange LADE)

## Objectif

Faire tourner **AutoPlan-RT sur la machine attaquante (Kali)** de la workzone LADE, pour enchaîner :

1. **Recon** bornée (`--execute-recon`)
2. **Draft** de chemins V5 (LLM)
3. **Exécution** des chemins rankés — mode autonome lab sous flags

Ce n’est **pas** le pack scénario LADE (Actions UI). Ici Kali *est* l’agent.

## Garde-fous

Triple acknowledgement obligatoire pour l’autonomie complète :

| Flag | Rôle |
|------|------|
| `--i-understand-lab-only` | Lab isolé autorisé uniquement |
| `--auto-execute` | Pas de `y/n` par étape ; auto-promotion des outils du chemin |
| `--allow-auto-exploits` | Autorise `exploit/*` / `msfconsole` en subprocess |

Sans `--allow-auto-exploits`, les exploits restent manuels (HITL) ou bloquent le mode auto.

Cibles : IP **privées / lab** uniquement.

## Déploiement sur Kali LADE

Sur la console Kali de la workzone :

```bash
# 1. Récupérer le code
git clone <URL_DU_DEPOT_Stage_LRSI> AutoPlan-RT
cd AutoPlan-RT

# 2. Environnement Python
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install langchain-openai langchain-google-genai   # selon le provider

# 3. Clé API (ne pas committer)
cp .env.example .env
# éditer .env : OPENAI_API_KEY=... ou GOOGLE_API_KEY=...

# 4. Outils offensifs (selon le draft)
which nmap curl dirb wpscan msfconsole
```

Si `git` / Internet sont limités : uploader un zip du dépôt via LADE (bundle files → Kali).

## Commande one-shot (recon → draft → auto-exec)

Contre la cible shopping de la topo d’exemple (`192.168.2.10`) :

```bash
cd AutoPlan-RT
source .venv/bin/activate
export PYTHONPATH=.

python -m V5.cli \
  --target-ip 192.168.2.10 \
  --objective "Authorized lab: draft and attempt plausible paths against shopping host" \
  --execute-recon \
  --recon-level 1 \
  --scan-tools nmap,curl,dirb \
  --enable-llm \
  --llm-provider openai \
  --strategy balanced \
  --top-k 5 \
  --execute-paths \
  --auto-execute \
  --allow-auto-exploits \
  --i-understand-lab-only \
  --runtime-timeout 300 \
  --output /tmp/v5_agent.json \
  --runtime-output /tmp/v5_runtime.json \
  --infra-output /tmp/v5_infra_enriched.json
```

Variante depuis un résultat déjà drafté :

```bash
python -m V5.runtime.cli \
  --from-result /tmp/v5_agent.json \
  --auto-execute \
  --allow-auto-exploits \
  --i-understand-lab-only \
  --runtime-timeout 300 \
  --runtime-output /tmp/v5_runtime.json
```

## Cibles

- **Shopping `192.168.2.10`** : valide la boucle recon→draft→exec ; peu de modules MSF « classiques ».
- Pour un exploit lab plus réaliste : déployer Metasploitable / MrRobot (si dispo dans la library LADE) sur un troisième host, puis `--target-ip` sur cette IP.

## Sorties à journaliser (rapport)

- `/tmp/v5_agent.json` — `ranked_paths`
- `/tmp/v5_runtime.json` — tentatives, commandes, exit codes, fallbacks
- Notes : date, workzone, IPs, `stop_reason`, chemin réussi ou causes d’échec

## Voir aussi

- [`docs/v5_runtime_hitl.md`](v5_runtime_hitl.md) — mode HITL (sans auto)
- [`docs/v5_recon_layer.md`](v5_recon_layer.md) — recon bornée
- [`docs/v5_cyberrange_bridge.md`](v5_cyberrange_bridge.md) — pont pédagogique pack→scénarios LADE (distinct)
