# Rapport d'Investigation — Alerte ALT-2024-007

**Généré le** : 2026-08-21 09:05:43 UTC

---

## Résumé Exécutif

L'alerte **PsExec Remote Execution Detected — ws-bobsmith → srv-dc01** présente une activité ambiguë (sévérité **MEDIUM**, score 42/100) nécessitant une investigation complémentaire. Patterns détectés : lateral_movement_dual_use_tool. **Action recommandée : ESCALATE.**

---

## Informations de l'Alerte

| Champ | Valeur |
|---|---|
| **ID** | `ALT-2024-007` |
| **Timestamp** | 2024-08-16T15:35:00 |
| **Source** | Sysmon |
| **Titre** | PsExec Remote Execution Detected — ws-bobsmith → srv-dc01 |
| **Verdict** | 🟡 **SUSPICIOUS** |
| **Sévérité** | 🟠 **MEDIUM** (score: 42.0/100) |
| **Action recommandée** | ⬆️ ESCALATE |

---

## IOCs Extraits

| Type | Valeur | Contexte |
|---|---|---|
| ipv4 | `192.168.250.100` | alert_ALT-2024-007 |
| ipv4 | `192.168.250.50` | alert_ALT-2024-007 |
| hostname | `ws-bobsmith` | alert_ALT-2024-007 |
| hostname | `srv-dc01` | alert_ALT-2024-007 |
| user | `WAYNE\bob.smith` | user |

---

## Chronologie des Événements

| Heure | Source | Action | Entité |
|---|---|---|---|
| 15:30:00 | auth | login_success | WAYNE\bob.smith |
| 15:35:00 | endpoint | process_create | WAYNE\bob.smith |
| 15:35:05 | auth | login_success | 192.168.250.100→192.168.250.50 |
| 15:35:10 | firewall | allow | 192.168.250.100→192.168.250.50 |
| 15:36:00 | endpoint | process_create | WAYNE\bob.smith |
| 15:38:00 | auth | login_success | 192.168.250.100→192.168.250.60 |
| 15:38:30 | endpoint | file_access | WAYNE\bob.smith |

---

## Corrélation des Preuves

L'analyse croisée des 7 événements télémétriques a identifié **1 pattern(s)** de corrélation :

- **lateral_movement_dual_use_tool** (confiance 70%) : Dual-use administrative tool execution detected (['PsExec.exe']) accompanied by network logons across 4 distinct target hosts (['srv-fileserver', 'srv-dc01', '192.168.250.50', '192.168.250.60'])

### Patterns Détectés
- **lateral_movement_dual_use_tool** (high) : Dual-use administrative tool execution detected (['PsExec.exe']) accompanied by network logons across 4 distinct target hosts (['srv-fileserver', 'srv-dc01', '192.168.250.50', '192.168.250.60'])

---

## Vérification Threat Intel

| IOC | Réputation | Confiance | Tags | Source |
|---|---|---|---|---|
| `192.168.250.100` | ⚪ unknown | 0% | — | none |
| `192.168.250.50` | 🟢 clean | 99% | internal, domain-controller | local_known_iocs |

---

## Scoring de Sévérité

### Score Combiné

- **Score Règles** : 0.0/100
- **Confiance ML** : 70.00%
- **Score Final** : **42.0/100** → MEDIUM

### Règles Déclenchées

- ✅ pattern_lateral_movement →  pts — __
- 🔽 all_internal_traffic →  pts — __

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

**Action : ESCALATE**

1. Transmettre à un analyste SOC niveau 3 pour investigation approfondie
2. Contacter le propriétaire du compte pour vérifier la légitimité de l'activité
3. Renforcer la surveillance sur les hôtes impliqués pendant 72h
4. Documenter les observations pour le rapport d'incident

---

## Raisonnement de l'Agent

### Étape 1 — Extract Indicators of Compromise (IOCs)

- **Tool** : `extract_iocs`
- **Raisonnement** : Extract all atomic observables (IPs, domains, hashes, users, hosts) from raw alert payload
- **Résultat** : Extracted 5 IOCs: 2 IPs, 0 hashes, 1 users, 0 domains.

### Étape 2 — Query network and perimeter telemetry for source IP '192.168.250.100'

- **Tool** : `query_logs`
- **Raisonnement** : Determine whether inbound/outbound connection volume, targeted ports, or IDS signatures indicate malicious probing
- **Résultat** : Identified 4 matching network/IDS telemetry events.

### Étape 3 — Query authentication and endpoint activity for user 'WAYNE\bob.smith' and host 'ws-bobsmith'

- **Tool** : `query_logs`
- **Raisonnement** : Assess whether user account suffered brute forcing, unauthorized privilege escalation, or executed suspicious processes
- **Résultat** : Retrieved 2 authentication/endpoint events.

### Étape 4 — Cross-source temporal correlation and attack pattern reconstruction

- **Tool** : `correlate_events`
- **Raisonnement** : Synthesize event timeline across perimeter, authentication, and endpoint telemetry to identify multi-stage attack patterns
- **Résultat** : Correlated 7 events. Detected 1 attack pattern(s): ['lateral_movement_dual_use_tool'].

### Étape 5 — Query Threat Intelligence feeds for all extracted external IOCs

- **Tool** : `lookup_threat_intel`
- **Raisonnement** : Validate external indicators against known C2 servers, vulnerability scanners, and malicious hash feeds
- **Résultat** : Evaluated 2 indicators. Malicious tags found: [].

### Étape 6 — Compute combined severity score (rules + ML)

- **Tool** : `score_severity`
- **Raisonnement** : Combine explicit rule-based scoring with ML binary classification to produce calibrated severity
- **Résultat** : Score: 42.0/100 | Severity: MEDIUM | Rules: ['pattern_lateral_movement', 'all_internal_traffic']

### Étape 7 — Synthesize final investigation verdict and containment action

- **Tool** : `investigation_synthesis`
- **Raisonnement** : Weigh threat intel confidence, correlation patterns, and administrative context to assign verdict
- **Résultat** : Verdict: SUSPICIOUS | Recommended Action: ESCALATE

