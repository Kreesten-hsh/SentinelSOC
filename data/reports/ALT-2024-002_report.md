# Rapport d'Investigation — Alerte ALT-2024-002

**Généré le** : 2026-08-21 09:05:43 UTC

---

## Résumé Exécutif

L'investigation de l'alerte **Multiple Failed Login Attempts — srv-dc01** a confirmé une menace réelle (sévérité **CRITICAL**, score 79/100). Les patterns d'attaque identifiés incluent : brute_force_followed_by_success. Les indicateurs malveillants confirmés : `40.80.148.42`. **Action immédiate requise : CONTAIN.**

---

## Informations de l'Alerte

| Champ | Valeur |
|---|---|
| **ID** | `ALT-2024-002` |
| **Timestamp** | 2024-08-11T03:16:00 |
| **Source** | Windows Event Log |
| **Titre** | Multiple Failed Login Attempts — srv-dc01 |
| **Verdict** | 🔴 **TRUE POSITIVE** |
| **Sévérité** | 🔴 **CRITICAL** (score: 79.2/100) |
| **Action recommandée** | 🛑 CONTAIN |

---

## IOCs Extraits

| Type | Valeur | Contexte |
|---|---|---|
| ipv4 | `40.80.148.42` | alert_ALT-2024-002 |
| ipv4 | `192.168.250.50` | alert_ALT-2024-002 |

---

## Chronologie des Événements

| Heure | Source | Action | Entité |
|---|---|---|---|
| 03:15:00 | auth | login_failed | 40.80.148.42→192.168.250.50 |
| 03:15:00 | firewall | allow | 40.80.148.42→192.168.250.50 |
| 03:15:12 | auth | login_failed | 40.80.148.42→192.168.250.50 |
| 03:15:12 | firewall | allow | 40.80.148.42→192.168.250.50 |
| 03:15:24 | auth | login_failed | 40.80.148.42→192.168.250.50 |
| 03:15:24 | firewall | allow | 40.80.148.42→192.168.250.50 |
| 03:15:36 | auth | login_failed | 40.80.148.42→192.168.250.50 |
| 03:15:36 | firewall | allow | 40.80.148.42→192.168.250.50 |
| 03:15:48 | auth | login_failed | 40.80.148.42→192.168.250.50 |
| 03:15:48 | firewall | allow | 40.80.148.42→192.168.250.50 |
| 03:16:00 | auth | login_failed | 40.80.148.42→192.168.250.50 |
| 03:16:00 | firewall | allow | 40.80.148.42→192.168.250.50 |
| 03:16:12 | auth | login_failed | 40.80.148.42→192.168.250.50 |
| 03:16:12 | firewall | allow | 40.80.148.42→192.168.250.50 |
| 03:16:24 | auth | login_failed | 40.80.148.42→192.168.250.50 |
| 03:16:24 | firewall | allow | 40.80.148.42→192.168.250.50 |
| 03:16:36 | auth | login_failed | 40.80.148.42→192.168.250.50 |
| 03:16:36 | firewall | allow | 40.80.148.42→192.168.250.50 |
| 03:16:48 | auth | login_failed | 40.80.148.42→192.168.250.50 |
| 03:16:48 | firewall | allow | 40.80.148.42→192.168.250.50 |
| 03:17:00 | auth | login_failed | 40.80.148.42→192.168.250.50 |
| 03:17:00 | firewall | allow | 40.80.148.42→192.168.250.50 |
| 03:17:12 | auth | login_failed | 40.80.148.42→192.168.250.50 |
| 03:17:12 | firewall | allow | 40.80.148.42→192.168.250.50 |
| 03:17:24 | auth | login_failed | 40.80.148.42→192.168.250.50 |
| 03:17:24 | firewall | allow | 40.80.148.42→192.168.250.50 |
| 03:17:36 | auth | login_failed | 40.80.148.42→192.168.250.50 |
| 03:17:36 | firewall | allow | 40.80.148.42→192.168.250.50 |
| 03:17:48 | auth | login_failed | 40.80.148.42→192.168.250.50 |
| 03:17:48 | firewall | allow | 40.80.148.42→192.168.250.50 |

---

## Corrélation des Preuves

L'analyse croisée des 33 événements télémétriques a identifié **1 pattern(s)** de corrélation :

- **brute_force_followed_by_success** (confiance 90%) : 15 failed authentications followed by successful login for user 'admin' from 40.80.148.42

### Patterns Détectés
- **brute_force_followed_by_success** (high) : 15 failed authentications followed by successful login for user 'admin' from 40.80.148.42

---

## Vérification Threat Intel

| IOC | Réputation | Confiance | Tags | Source |
|---|---|---|---|---|
| `40.80.148.42` | 🔴 malicious | 99% | apt, brute-force, po1s0n1vy | local_known_iocs |
| `192.168.250.50` | 🟢 clean | 99% | internal, domain-controller | local_known_iocs |

---

## Scoring de Sévérité

### Score Combiné

- **Score Règles** : 70.0/100
- **Confiance ML** : 85.25%
- **Score Final** : **79.2/100** → CRITICAL

### Règles Déclenchées

- ✅ ti_malicious_high_confidence →  pts — __
- ✅ pattern_brute_force_success →  pts — __
- ✅ after_hours_activity →  pts — __
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

### Étape 2 — Query network and perimeter telemetry for source IP '40.80.148.42'

- **Tool** : `query_logs`
- **Raisonnement** : Determine whether inbound/outbound connection volume, targeted ports, or IDS signatures indicate malicious probing
- **Résultat** : Identified 31 matching network/IDS telemetry events.

### Étape 3 — Query authentication and endpoint activity for user 'None' and host 'None'

- **Tool** : `query_logs`
- **Raisonnement** : Assess whether user account suffered brute forcing, unauthorized privilege escalation, or executed suspicious processes
- **Résultat** : Retrieved 33 authentication/endpoint events.

### Étape 4 — Cross-source temporal correlation and attack pattern reconstruction

- **Tool** : `correlate_events`
- **Raisonnement** : Synthesize event timeline across perimeter, authentication, and endpoint telemetry to identify multi-stage attack patterns
- **Résultat** : Correlated 33 events. Detected 1 attack pattern(s): ['brute_force_followed_by_success'].

### Étape 5 — Query Threat Intelligence feeds for all extracted external IOCs

- **Tool** : `lookup_threat_intel`
- **Raisonnement** : Validate external indicators against known C2 servers, vulnerability scanners, and malicious hash feeds
- **Résultat** : Evaluated 2 indicators. Malicious tags found: [['apt', 'brute-force', 'po1s0n1vy']].

### Étape 6 — Compute combined severity score (rules + ML)

- **Tool** : `score_severity`
- **Raisonnement** : Combine explicit rule-based scoring with ML binary classification to produce calibrated severity
- **Résultat** : Score: 79.2/100 | Severity: CRITICAL | Rules: ['ti_malicious_high_confidence', 'pattern_brute_force_success', 'after_hours_activity', 'all_internal_traffic']

### Étape 7 — Synthesize final investigation verdict and containment action

- **Tool** : `investigation_synthesis`
- **Raisonnement** : Weigh threat intel confidence, correlation patterns, and administrative context to assign verdict
- **Résultat** : Verdict: TRUE_POSITIVE | Recommended Action: CONTAIN

