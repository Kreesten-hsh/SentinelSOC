# Rapport d'Investigation — Alerte ALT-2024-006

**Généré le** : 2026-08-21 10:10:24 UTC

---

## Résumé Exécutif

L'investigation de l'alerte **Suspicious PowerShell Execution — srv-dc01** conclut à un **faux positif** (sévérité **LOW**, score 11/100). L'activité observée correspond à un comportement légitime sans indicateur de compromission. **Aucune action corrective nécessaire.** L'alerte peut être clôturée.

---

## Informations de l'Alerte

| Champ | Valeur |
|---|---|
| **ID** | `ALT-2024-006` |
| **Timestamp** | 2024-08-15T10:02:00 |
| **Source** | Sysmon |
| **Titre** | Suspicious PowerShell Execution — srv-dc01 |
| **Verdict** | 🟢 **FALSE POSITIVE** |
| **Sévérité** | 🟢 **LOW** (score: 11.1/100) |
| **Action recommandée** | ✅ IGNORE |

---

## IOCs Extraits

| Type | Valeur | Contexte |
|---|---|---|
| hostname | `srv-dc01` | alert_ALT-2024-006 |
| user | `WAYNE\sysadmin.jones` | user |

---

## Chronologie des Événements

| Heure | Source | Action | Entité |
|---|---|---|---|
| 09:59:00 | endpoint | scheduled_task | SYSTEM |
| 10:00:00 | auth | login_success | 192.168.250.10→192.168.250.50 |
| 10:02:00 | endpoint | process_create | WAYNE\sysadmin.jones |
| 10:03:00 | firewall | allow | 192.168.250.50→192.168.250.255 |

---

## Corrélation des Preuves

L'analyse croisée des 4 événements télémétriques a identifié **1 pattern(s)** de corrélation :

- **scheduled_task_triggered_execution** (confiance 70%) : Endpoint process execution correlates with scheduled task trigger (['Weekly-AD-Maintenance'])

### Patterns Détectés
- **scheduled_task_triggered_execution** (high) : Endpoint process execution correlates with scheduled task trigger (['Weekly-AD-Maintenance'])

---

## Vérification Threat Intel

_Aucun IOC vérifié._

---

## Scoring de Sévérité

### Score Combiné

- **Score Règles** : 0.0/100
- **Confiance ML** : 18.50%
- **Score Final** : **11.1/100** → LOW

### Règles Déclenchées

- 🔽 pattern_scheduled_task → -15 pts — _Process execution triggered by scheduled task (benign indicator)_
- 🔽 all_internal_traffic → -20 pts — _All observed network traffic is internal — no external communication_

### Top Features ML

| Feature | Importance |
|---|---|
| event_count | 0.1573 |
| pattern_count_critical | 0.1533 |
| ti_malicious_count | 0.1345 |
| ti_max_confidence | 0.1134 |
| external_dest_count | 0.0916 |

---

## Recommandation

**Action : IGNORE**

1. Clôturer l'alerte comme faux positif documenté
2. Envisager un tuning de la règle de détection pour réduire le bruit

---

## Raisonnement de l'Agent

### Étape 1 — Extract Indicators of Compromise (IOCs)

- **Tool** : `extract_iocs`
- **Raisonnement** : Extract all atomic observables (IPs, domains, hashes, users, hosts) from raw alert payload
- **Résultat** : Extracted 2 IOCs: 0 IPs, 0 hashes, 1 users, 0 domains.

### Étape 2 — Query network and perimeter telemetry for relevant network traffic

- **Tool** : `query_logs`
- **Raisonnement** : Determine whether inbound/outbound connection volume, targeted ports, or IDS signatures indicate malicious probing
- **Résultat** : Identified 4 matching network/IDS telemetry events.

### Étape 3 — Query authentication and endpoint activity for user 'WAYNE\sysadmin.jones' and host 'srv-dc01'

- **Tool** : `query_logs`
- **Raisonnement** : Assess whether user account suffered brute forcing, unauthorized privilege escalation, or executed suspicious processes
- **Résultat** : Retrieved 2 authentication/endpoint events.

### Étape 4 — Cross-source temporal correlation and attack pattern reconstruction

- **Tool** : `correlate_events`
- **Raisonnement** : Synthesize event timeline across perimeter, authentication, and endpoint telemetry to identify multi-stage attack patterns
- **Résultat** : Correlated 4 events. Detected 1 attack pattern(s): ['scheduled_task_triggered_execution'].

### Étape 5 — Query Threat Intelligence feeds for all extracted external IOCs

- **Tool** : `lookup_threat_intel`
- **Raisonnement** : Validate external indicators against known C2 servers, vulnerability scanners, and malicious hash feeds
- **Résultat** : Evaluated 0 indicators. Malicious tags found: [].

### Étape 6 — Compute combined severity score (rules + ML)

- **Tool** : `score_severity`
- **Raisonnement** : Combine explicit rule-based scoring with ML binary classification to produce calibrated severity
- **Résultat** : Score: 11.1/100 | Severity: LOW | Rules: ['pattern_scheduled_task', 'all_internal_traffic']

### Étape 7 — Synthesize final investigation verdict and containment action

- **Tool** : `investigation_synthesis`
- **Raisonnement** : Weigh threat intel confidence, correlation patterns, and administrative context to assign verdict
- **Résultat** : Verdict: FALSE_POSITIVE | Recommended Action: IGNORE

