# SentinelSOC

**Agent IA autonome de triage et d'investigation d'alertes SOC**

> Projet 3 — Candidature Master Cybersécurité (Open Doors 2026)

## Objectif

SentinelSOC reçoit une alerte de sécurité brute (type SIEM), extrait automatiquement les indicateurs de compromission, interroge les journaux pertinents, corrèle les événements, vérifie une base de threat intelligence, score la sévérité, et produit un rapport d'investigation structuré.

## Architecture

```
Alerte brute → Extraction IOCs → Collecte logs → Corrélation → Threat Intel → Scoring → Rapport
```

## Stack technique

| Composant | Technologie | Justification |
|---|---|---|
| Agent IA | smolagents (Hugging Face) + LiteLLM | Framework léger, code-first, transparent |
| LLM | Ollama (Mistral 7B) | Gratuit, offline, reproductible |
| Backend | FastAPI + SQLite/SQLAlchemy | Async, typé, zéro config DB |
| Frontend | React + Vite | Build rapide, moderne |
| ML Scoring | scikit-learn (RandomForest) | Interprétable, features CICIDS2017 |
| Tests | pytest + ruff + mypy | Qualité code stricte |

## Données

**Logs synthétiques haute-fidélité** basés sur [Splunk BOTS v1](https://github.com/splunk/botsv1) (Boss of the SOC) — le jeu de données de référence pour l'entraînement à l'investigation SOC.

8 scénarios couvrant le spectre de sévérité :
1. 🔴 Web Defacement (Acunetix → SQLi → webshell)
2. 🔴 Brute Force SSH (15 tentatives → login réussi → post-exploitation)
3. 🔴 Ransomware Cerber (USB → C2 → encryption fichiers)
4. 🔴 Data Exfiltration (accès hors heures → compression → upload 48 Mo)
5. 🟡 Reconnaissance interne (Nmap port scan)
6. 🟢 Faux positif (maintenance admin planifiée)
7. 🟡 Mouvement latéral ambigu (PsExec → domain enum)
8. 🔴 Credential stuffing OWA (12 users ciblés → 2 compromis)

**Limites documentées** : Logs synthétiques, pas de bruit de fond réel, événements condensés temporellement. Voir [DECISIONS.md](DECISIONS.md) pour les arbitrages.

**Scoring ML** : CICIDS2017 (University of New Brunswick) pour l'entraînement du modèle binaire (malveillant/bénin) avec score de confiance.

## Installation rapide

```bash
git clone https://github.com/your-username/SentinelSOC.git
cd SentinelSOC
pip install -e ".[dev]"
python scripts/generate_scenarios.py
# TODO Phase 5 : docker compose up
```

## Statut

- [x] Phase 1 — Données et scénarios
- [ ] Phase 2 — Agent d'investigation
- [ ] Phase 3 — Scoring et threat intel
- [ ] Phase 4 — Rapports
- [ ] Phase 5 — Dashboard
- [ ] Phase 6 — Documentation finale

## Licence

MIT — Voir [LICENSE](LICENSE).
