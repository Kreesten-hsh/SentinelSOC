# Rapport d'Investigation — Alerte ALT-2024-004

**Généré le** : 2026-08-21 09:05:43 UTC

---

## Résumé Exécutif

L'investigation de l'alerte **Large Outbound Data Transfer — ws-jdoe to External IP** a confirmé une menace réelle (sévérité **CRITICAL**, score 100/100). Les patterns d'attaque identifiés incluent : command_and_control_or_exfiltration. Les indicateurs malveillants confirmés : `91.234.99.42`. **Action immédiate requise : CONTAIN.**

---

## Informations de l'Alerte

| Champ | Valeur |
|---|---|
| **ID** | `ALT-2024-004` |
| **Timestamp** | 2024-08-13T22:42:00 |
| **Source** | Fortinet Firewall |
| **Titre** | Large Outbound Data Transfer — ws-jdoe to External IP |
| **Verdict** | 🔴 **TRUE POSITIVE** |
| **Sévérité** | 🔴 **CRITICAL** (score: 100.0/100) |
| **Action recommandée** | 🛑 CONTAIN |

---

## IOCs Extraits

| Type | Valeur | Contexte |
|---|---|---|
| ipv4 | `192.168.250.120` | alert_ALT-2024-004 |
| ipv4 | `91.234.99.42` | alert_ALT-2024-004 |
| hostname | `ws-jdoe` | alert_ALT-2024-004 |
| user | `WAYNE\j.doe` | user |

---

## Chronologie des Événements

| Heure | Source | Action | Entité |
|---|---|---|---|
| 22:30:00 | auth | login_success | WAYNE\j.doe |
| 22:35:00 | endpoint | file_access | WAYNE\j.doe |
| 22:36:00 | endpoint | file_access | WAYNE\j.doe |
| 22:38:00 | endpoint | process_create | WAYNE\j.doe |
| 22:41:50 | dns | dns_query | 192.168.250.120→192.168.250.10 |
| 22:42:00 | firewall | allow | 192.168.250.120→91.234.99.42 |
| 22:42:00 | ids | alert | 192.168.250.120→91.234.99.42 |

---

## Corrélation des Preuves

L'analyse croisée des 7 événements télémétriques a identifié **1 pattern(s)** de corrélation :

- **command_and_control_or_exfiltration** (confiance 90%) : Endpoint activity directly correlates with outbound external communication/IDS alert

### Patterns Détectés
- **command_and_control_or_exfiltration** (high) : Endpoint activity directly correlates with outbound external communication/IDS alert

---

## Vérification Threat Intel

| IOC | Réputation | Confiance | Tags | Source |
|---|---|---|---|---|
| `192.168.250.120` | ⚪ unknown | 0% | — | none |
| `91.234.99.42` | 🔴 malicious | 90% | exfiltration, data-theft, drop-server | local_known_iocs |

---

## Scoring de Sévérité

### Score Combiné

- **Score Règles** : 100.0/100
- **Confiance ML** : 100.00%
- **Score Final** : **100.0/100** → CRITICAL

### Règles Déclenchées

- ✅ ti_malicious_high_confidence →  pts — __
- ✅ pattern_c2_exfiltration →  pts — __
- ✅ after_hours_activity →  pts — __
- ✅ external_dest_ip →  pts — __
- ✅ high_volume_outbound →  pts — __

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

**Action : CONTAIN**

1. Isoler immédiatement le(s) hôte(s) compromis du réseau
2. Bloquer les adresses IP malveillantes identifiées au pare-feu périmétrique
3. Réinitialiser les identifiants des comptes compromis
4. Lancer une analyse forensique complète des systèmes affectés
5. Notifier l'équipe de réponse aux incidents (CSIRT)

---

## Raisonnement de l'Agent

### Étape 1 — Extract Indicators of Compromise (IOCs)

- **Tool** : `extract_iocs`
- **Raisonnement** : Extract all atomic observables (IPs, domains, hashes, users, hosts) from raw alert payload
- **Résultat** : Extracted 4 IOCs: 2 IPs, 0 hashes, 1 users, 0 domains.

### Étape 2 — Query network and perimeter telemetry for source IP '192.168.250.120'

- **Tool** : `query_logs`
- **Raisonnement** : Determine whether inbound/outbound connection volume, targeted ports, or IDS signatures indicate malicious probing
- **Résultat** : Identified 4 matching network/IDS telemetry events.

### Étape 3 — Query authentication and endpoint activity for user 'WAYNE\j.doe' and host 'ws-jdoe'

- **Tool** : `query_logs`
- **Raisonnement** : Assess whether user account suffered brute forcing, unauthorized privilege escalation, or executed suspicious processes
- **Résultat** : Retrieved 4 authentication/endpoint events.

### Étape 4 — Cross-source temporal correlation and attack pattern reconstruction

- **Tool** : `correlate_events`
- **Raisonnement** : Synthesize event timeline across perimeter, authentication, and endpoint telemetry to identify multi-stage attack patterns
- **Résultat** : Correlated 7 events. Detected 1 attack pattern(s): ['command_and_control_or_exfiltration'].

### Étape 5 — Query Threat Intelligence feeds for all extracted external IOCs

- **Tool** : `lookup_threat_intel`
- **Raisonnement** : Validate external indicators against known C2 servers, vulnerability scanners, and malicious hash feeds
- **Résultat** : Evaluated 2 indicators. Malicious tags found: [['exfiltration', 'data-theft', 'drop-server']].

### Étape 6 — Compute combined severity score (rules + ML)

- **Tool** : `score_severity`
- **Raisonnement** : Combine explicit rule-based scoring with ML binary classification to produce calibrated severity
- **Résultat** : Score: 100.0/100 | Severity: CRITICAL | Rules: ['ti_malicious_high_confidence', 'pattern_c2_exfiltration', 'after_hours_activity', 'external_dest_ip', 'high_volume_outbound']

### Étape 7 — Synthesize final investigation verdict and containment action

- **Tool** : `investigation_synthesis`
- **Raisonnement** : Weigh threat intel confidence, correlation patterns, and administrative context to assign verdict
- **Résultat** : Verdict: TRUE_POSITIVE | Recommended Action: CONTAIN

