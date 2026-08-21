# Rapport d'Investigation — Alerte ALT-2024-008

**Généré le** : 2026-08-21 09:05:43 UTC

---

## Résumé Exécutif

L'investigation de l'alerte **Multiple Failed OWA Logins from Single External IP** a confirmé une menace réelle (sévérité **CRITICAL**, score 74/100). Les patterns d'attaque identifiés incluent : brute_force_followed_by_success. Les indicateurs malveillants confirmés : `198.71.247.91`. **Action immédiate requise : CONTAIN.**

---

## Informations de l'Alerte

| Champ | Valeur |
|---|---|
| **ID** | `ALT-2024-008` |
| **Timestamp** | 2024-08-17T07:00:30 |
| **Source** | Windows Event Log |
| **Titre** | Multiple Failed OWA Logins from Single External IP |
| **Verdict** | 🔴 **TRUE POSITIVE** |
| **Sévérité** | 🔴 **CRITICAL** (score: 74.3/100) |
| **Action recommandée** | 🛑 CONTAIN |

---

## IOCs Extraits

| Type | Valeur | Contexte |
|---|---|---|
| ipv4 | `198.71.247.91` | alert_ALT-2024-008 |
| ipv4 | `192.168.250.70` | alert_ALT-2024-008 |

---

## Chronologie des Événements

| Heure | Source | Action | Entité |
|---|---|---|---|
| 07:00:00 | webserver | POST | 198.71.247.91→192.168.250.70 |
| 07:00:00 | auth | login_failed | 198.71.247.91→192.168.250.70 |
| 07:00:00 | firewall | allow | 198.71.247.91→192.168.250.70 |
| 07:00:05 | webserver | POST | 198.71.247.91→192.168.250.70 |
| 07:00:05 | auth | login_failed | 198.71.247.91→192.168.250.70 |
| 07:00:10 | webserver | POST | 198.71.247.91→192.168.250.70 |
| 07:00:10 | auth | login_failed | 198.71.247.91→192.168.250.70 |
| 07:00:15 | webserver | POST | 198.71.247.91→192.168.250.70 |
| 07:00:15 | auth | login_failed | 198.71.247.91→192.168.250.70 |
| 07:00:20 | webserver | POST | 198.71.247.91→192.168.250.70 |
| 07:00:20 | auth | login_failed | 198.71.247.91→192.168.250.70 |
| 07:00:25 | webserver | POST | 198.71.247.91→192.168.250.70 |
| 07:00:25 | auth | login_failed | 198.71.247.91→192.168.250.70 |
| 07:00:30 | webserver | POST | 198.71.247.91→192.168.250.70 |
| 07:00:30 | auth | login_failed | 198.71.247.91→192.168.250.70 |
| 07:00:35 | webserver | POST | 198.71.247.91→192.168.250.70 |
| 07:00:35 | auth | login_failed | 198.71.247.91→192.168.250.70 |
| 07:00:40 | webserver | POST | 198.71.247.91→192.168.250.70 |
| 07:00:40 | auth | login_failed | 198.71.247.91→192.168.250.70 |
| 07:00:45 | webserver | POST | 198.71.247.91→192.168.250.70 |
| 07:00:45 | auth | login_failed | 198.71.247.91→192.168.250.70 |
| 07:00:50 | webserver | POST | 198.71.247.91→192.168.250.70 |
| 07:00:50 | auth | login_failed | 198.71.247.91→192.168.250.70 |
| 07:00:55 | webserver | POST | 198.71.247.91→192.168.250.70 |
| 07:00:55 | auth | login_failed | 198.71.247.91→192.168.250.70 |
| 07:01:00 | auth | login_success | 198.71.247.91→192.168.250.70 |
| 07:01:05 | webserver | GET | 198.71.247.91→192.168.250.70 |
| 07:01:15 | auth | login_success | 198.71.247.91→192.168.250.70 |
| 07:01:20 | webserver | GET | 198.71.247.91→192.168.250.70 |

---

## Corrélation des Preuves

L'analyse croisée des 29 événements télémétriques a identifié **1 pattern(s)** de corrélation :

- **brute_force_followed_by_success** (confiance 90%) : 12 failed authentications followed by successful login for user 'WAYNE\lucius.fox' from 198.71.247.91

### Patterns Détectés
- **brute_force_followed_by_success** (high) : 12 failed authentications followed by successful login for user 'WAYNE\lucius.fox' from 198.71.247.91

---

## Vérification Threat Intel

| IOC | Réputation | Confiance | Tags | Source |
|---|---|---|---|---|
| `198.71.247.91` | 🔴 malicious | 92% | credential-stuffing, brute-force, webmail-attack | local_known_iocs |
| `192.168.250.70` | ⚪ unknown | 0% | — | none |

---

## Scoring de Sévérité

### Score Combiné

- **Score Règles** : 55.0/100
- **Confiance ML** : 87.25%
- **Score Final** : **74.3/100** → CRITICAL

### Règles Déclenchées

- ✅ ti_malicious_high_confidence →  pts — __
- ✅ pattern_brute_force_success →  pts — __
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
- **Résultat** : Extracted 2 IOCs: 2 IPs, 0 hashes, 0 users, 0 domains.

### Étape 2 — Query network and perimeter telemetry for source IP '198.71.247.91'

- **Tool** : `query_logs`
- **Raisonnement** : Determine whether inbound/outbound connection volume, targeted ports, or IDS signatures indicate malicious probing
- **Résultat** : Identified 29 matching network/IDS telemetry events.

### Étape 3 — Query authentication and endpoint activity for user 'None' and host 'None'

- **Tool** : `query_logs`
- **Raisonnement** : Assess whether user account suffered brute forcing, unauthorized privilege escalation, or executed suspicious processes
- **Résultat** : Retrieved 29 authentication/endpoint events.

### Étape 4 — Cross-source temporal correlation and attack pattern reconstruction

- **Tool** : `correlate_events`
- **Raisonnement** : Synthesize event timeline across perimeter, authentication, and endpoint telemetry to identify multi-stage attack patterns
- **Résultat** : Correlated 29 events. Detected 1 attack pattern(s): ['brute_force_followed_by_success'].

### Étape 5 — Query Threat Intelligence feeds for all extracted external IOCs

- **Tool** : `lookup_threat_intel`
- **Raisonnement** : Validate external indicators against known C2 servers, vulnerability scanners, and malicious hash feeds
- **Résultat** : Evaluated 2 indicators. Malicious tags found: [['credential-stuffing', 'brute-force', 'webmail-attack']].

### Étape 6 — Compute combined severity score (rules + ML)

- **Tool** : `score_severity`
- **Raisonnement** : Combine explicit rule-based scoring with ML binary classification to produce calibrated severity
- **Résultat** : Score: 74.3/100 | Severity: CRITICAL | Rules: ['ti_malicious_high_confidence', 'pattern_brute_force_success', 'all_internal_traffic']

### Étape 7 — Synthesize final investigation verdict and containment action

- **Tool** : `investigation_synthesis`
- **Raisonnement** : Weigh threat intel confidence, correlation patterns, and administrative context to assign verdict
- **Résultat** : Verdict: TRUE_POSITIVE | Recommended Action: CONTAIN

