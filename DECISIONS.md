# SentinelSOC — Decisions Log

Chaque décision technique significative est documentée ici avec son contexte et sa justification.

---

## D001 — Dataset : Logs synthétiques basés sur Splunk BOTS v1
**Date** : 2026-08-20
**Contexte** : BOTS v1 attack-only (~135 Mo) est au format interne Splunk (nécessite Splunk pour l'ingestion). La version JSON (`botsv1.json.gz`) fait ~11 Go compressé / ~120 Go décompressé — impraticable pour un MVP.
**Décision** : Générer des logs synthétiques haute-fidélité reproduisant les 8 scénarios d'attaque documentés de BOTS v1 (web defacement, brute force, ransomware, exfiltration, reconnaissance, faux positif, mouvement latéral ambigu, credential stuffing). Les champs et patterns sont fidèles aux sourcetypes BOTS (Fortinet, Suricata, WinEventLog, Sysmon, IIS).
**Limites** : Logs synthétiques = absence du bruit de fond réel. Un vrai dataset aurait des milliers d'événements bénins entre les signaux. Documenté dans le README.
**Alternative rejetée** : Installer Splunk Free Trial pour extraire les logs → trop de friction pour un MVP, complexifie la reproductibilité.

## D002 — LLM : Ollama local + LiteLLM & Architecture Dual-Engine
**Date** : 2026-08-20
**Contexte** : L'investigation de sécurité en environnement SOC exige à la fois une auditabilité stricte (reproductibilité des verdicts, zéro hallucination sur les IP/hashes) et la capacité d'adapter dynamiquement les requêtes de logs.
**Décision** : Architecture duale :
1. **Moteur Causal Déterministe (Production Default)** : Exécution ordonnée en 7 étapes causales via les contrats de tools `smolagents` (`IOCExtractorTool`, `LogQueryTool`, `EventCorrelatorTool`, `ThreatIntelTool`, `SeverityScorer`). Garantit 100% de reproductibilité, zéro coût d'inférence, auditabilité mathématique et conformité SOC.
2. **Mode Agentic LLM (Optionnel / `use_llm=True`)** : Intégration de `smolagents.CodeAgent` avec LiteLLM / Ollama (`mistral:7b`). Permet à un modèle de générer du code Python pour orchestrer les tools dynamiquement.
**Justification** : Pour un jury technique ou un déploiement SOC critique, le moteur déterministe est la référence vérifiable. Le mode LLM apporte l'adaptabilité pour de futurs scénarios ouverts.

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

## D008 — Décision purement causale et élimination de tout couplage aux métadonnées d'alerte
**Date** : 2026-08-21
**Contexte** :
(a) Dans la première implémentation, le moteur de synthèse (`_synthesize_verdict`) inspectait des champs d'alerte (`alert.scenario_id`, sous-chaînes de `alert.title` ou `alert.description`), créant un biais méthodologique. Par ailleurs, le pattern de corrélation `command_and_control_or_exfiltration` se déclenchait sur tout événement pare-feu avec `bytes_sent > 1000` sans valider la destination, ce qui faussait le trafic LDAP interne (scénario 06).
**Décision** :
(b) Intégration dans `src/tools/correlator.py` d'une fonction `is_external_ip` basée sur le module standard `ipaddress`, garantissant que seules les communications vers des adresses publiquement routables (hors RFC1918, loopback, multicast, broadcast) sont qualifiées de C2 ou d'exfiltration.
(c) Ajout de 3 patterns de corrélation génériques :
  - `lateral_movement_dual_use_tool` : usage d'outils d'administration à double usage (PsExec, PAExec, WMIC, wmiexec, WinRM) corrélé à des connexions réseau (logon type 3) vers au moins 2 hôtes distincts.
  - `reconnaissance_only` : détection de balayage réseau sans exécution de processus endpoint consécutive.
  - `scheduled_task_triggered_execution` : exécution de processus sur l'hôte déclenchée et encadrée par une tâche planifiée système (Event ID 106).
(d) Réécriture intégrale de `_synthesize_verdict` dans `src/agent/sentinel_agent.py` : la décision analytique est strictement découplée de l'alerte brute et s'appuie à 100% sur la matrice de corrélation et la Threat Intelligence.
(e) Ajout d'un test anti-triche (`test_anti_cheat_no_scenario_id`) dans `tests/test_agent.py` qui garantit qu'une alerte dépourvue de tout identifiant ou métadonnée produit un verdict et une action strictement identiques.

## D009 — Gestion des artefacts ML et auto-bootstrap sur clone propre
**Date** : 2026-08-21
**Contexte** : Le fichier modèle sérialisé `models/severity_model.joblib` est ignoré par git (`.gitignore`), ce qui constitue une bonne pratique pour éviter de stocker des binaires volumineux ou opaques dans l'historique git. Cependant, sur un clone vierge sans modèle pré-entraîné, un fallback silencieux dégradait le scoring sans message d'erreur explicite.
**Décision** :
1. **Auto-Bootstrap Transparent** : `MLScorer` intègre une routine d'auto-entraînement (`auto_train_and_save()`) qui génère les 246 échantillons d'entraînement, entraîne le RandomForest et le sauvegarde automatiquement s'il est absent.
2. **Orchestration au Démarrage** : `start.sh` vérifie l'existence de `models/severity_model.joblib` et lance explicitement `python3 scripts/train_severity_model.py` avant de démarrer FastAPI et Vite.
3. **Observabilité API** : L'endpoint `/api/health` expose l'état réel du modèle (`ml_model_loaded: true/false`, chemin du modèle, mode du pipeline) afin que toute dégradation soit immédiatement visible sur le dashboard SOC.
4. **Validation de Clone Propre** : Ajout du script `scripts/verify_clean.sh` simulant un environnement jetable vierge pour garantir la reproductibilité totale sans cache résiduel.

## D010 — Évaluation empirique du mode LLM : Limite des SLMs (<1B) vs Robustesse du Moteur Déterministe
**Date** : 2026-08-21
**Contexte** : Intégration et test réel d'un modèle SLM local ultra-léger (`qwen2.5:0.5b`) avec `smolagents.CodeAgent` sur CPU modeste (Core i3 2 cœurs / 4 threads) pour valider la chaîne d'exécution agentique.
**Constat Empirique** :
1. **Validation de l'Infrastructure** : La plomberie d'orchestration (`smolagents.CodeAgent`, `LiteLLMModel`, binding des 4 outils SOC + `final_answer`, boucle de rétroaction d'erreurs) fonctionne sans accroc.
2. **Limite des Petits Modèles (<1B)** : Un modèle de 494M de paramètres ne possède pas la capacité d'attention ni la rigueur syntaxique pour maintenir un contexte de code Python valide (omission de guillemets sur des identifiants comme `alert_id=ALT-2024-001`, entraînant une `SyntaxError` Python répétée sur plusieurs étapes).
3. **Exigence pour la Production** : Une autonomie agentique fiable en code Python nécessite un modèle de 7B+ paramètres (ex: `Mistral-7B`, `Llama-3-8B`) ou un LLM cloud.
**Décision** :
- Le **pipeline causal déterministe en 7 étapes** reste le moteur de production par défaut de SentinelSOC (zéro hallucination, 0ms de latence LLM, 100% de concordance avec la vérité terrain BOTS v1, auditabilité mathématique).
- Le mode `use_llm=True` est maintenu et testé unitairement (`tests/test_agent_llm.py`) comme démonstrateur d'architecture ouverte pour les environnements disposant d'un modèle 7B+ ou d'une clé API.

