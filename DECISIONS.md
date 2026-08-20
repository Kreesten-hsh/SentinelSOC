# SentinelSOC — Decisions Log

Chaque décision technique significative est documentée ici avec son contexte et sa justification.

---

## D001 — Dataset : Logs synthétiques basés sur Splunk BOTS v1
**Date** : 2026-08-20
**Contexte** : BOTS v1 attack-only (~135 Mo) est au format interne Splunk (nécessite Splunk pour l'ingestion). La version JSON (`botsv1.json.gz`) fait ~11 Go compressé / ~120 Go décompressé — impraticable pour un MVP.
**Décision** : Générer des logs synthétiques haute-fidélité reproduisant les 8 scénarios d'attaque documentés de BOTS v1 (web defacement, brute force, ransomware, exfiltration, reconnaissance, faux positif, mouvement latéral ambigu, credential stuffing). Les champs et patterns sont fidèles aux sourcetypes BOTS (Fortinet, Suricata, WinEventLog, Sysmon, IIS).
**Limites** : Logs synthétiques = absence du bruit de fond réel. Un vrai dataset aurait des milliers d'événements bénins entre les signaux. Documenté dans le README.
**Alternative rejetée** : Installer Splunk Free Trial pour extraire les logs → trop de friction pour un MVP, complexifie la reproductibilité.

## D002 — LLM : Ollama local + LiteLLM
**Date** : 2026-08-20
**Contexte** : L'agent d'investigation a besoin d'un LLM pour raisonner. Options : API payante (OpenAI/Anthropic), HF Inference API (gratuit mais dépendant réseau), Ollama local (gratuit, offline).
**Décision** : Ollama + Mistral 7B via LiteLLM. Zéro coût, démontrable offline, reproductible. Fallback sur HF Inference API si Ollama indisponible.
**Justification** : Le jury doit pouvoir reproduire sans clé API. La qualité de raisonnement de Mistral 7B est suffisante pour les 8 scénarios bornés.

## D003 — Base de données : SQLite
**Date** : 2026-08-20
**Contexte** : Persistence des alertes, investigations, et rapports.
**Décision** : SQLite via SQLAlchemy + aiosqlite. Zéro configuration, fichier unique, portable.
**Justification** : MVP avec 8 scénarios, pas besoin de concurrent writes. Migration vers PostgreSQL triviale via SQLAlchemy si nécessaire.

## D004 — Scoring ML : Binaire + confiance
**Date** : 2026-08-20
**Contexte** : CICIDS2017 fournit des labels binaires (BENIGN vs type d'attaque). Option : 3 classes (Low/Medium/Critical) ou binaire + score de confiance.
**Décision** : Modèle binaire (malveillant/bénin) avec score de confiance [0, 1]. La sévérité finale (Low/Medium/Critical) est dérivée par combinaison : `rules_score * 0.4 + ml_confidence * 0.6`, avec seuils calibrés.
**Justification** : Plus honnête — le modèle sait distinguer trafic normal vs attaque, pas la "gravité" d'une attaque. La sévérité est un jugement humain/règles, pas un problème de classification binaire.

## D005 — Threat Intel : Mode dual (local + API optionnelle)
**Date** : 2026-08-20
**Décision** : Base JSON locale embarquée avec les IOCs connus de BOTS v1. Si `ABUSEIPDB_API_KEY` est configurée, enrichissement supplémentaire via API. La démo ne dépend jamais d'une clé API tierce.

## D006 — Frontend : React + Vite
**Date** : 2026-08-20
**Décision** : Vite pour le build, React pour le UI, vanilla CSS avec design system SOC dark mode. Pas de Tailwind (non demandé explicitement).

## D007 — Étanchéité de la télémétrie et isolation de la vérité terrain (Ground Truth)
**Date** : 2026-08-20
**Contexte** : Dans la version initiale des scénarios de test, certains champs de `metadata` (ex: `scheduled_maintenance: true`, `script_description`, `file_classification`, `description`) contenaient des annotations d'analyse humaine ou des flags explicites révélant le verdict directement dans la télémétrie brute.
**Décision** :
1. Purge intégrale de tout champ d'annotation, description ou flag artificiel dans les logs normalisés (JSONL). Les logs ne contiennent strictement que ce qu'un SIEM/EDR réel émettrait (Event ID 4624/4625/4663/106, Sysmon EID 1/11, Suricata alerts, pare-feu Fortinet, requêtes Web IIS/Apache).
2. Déportation de la vérité terrain dans un fichier isolé `data/scenarios/ground_truth.json`, strictement non chargé par le `LogStore` ni accessible aux tools de l'agent. Ce fichier sert exclusivement aux benchmarks et à l'évaluation post-hoc de la justesse du raisonnement de l'agent.
**Justification** : Évite tout biais d'évaluation ou raccourci d'inférence pour l'agent. Le raisonnement de l'agent doit reposer à 100% sur la corrélation authentique de faits télémétriques.

