# Rapport d'Investigation — Alerte ALT-2024-005

**Généré le** : 2026-08-21 10:10:23 UTC

---

## Résumé Exécutif

L'alerte **Internal Network Port Scan Detected — 10.0.0.88** présente une activité ambiguë (sévérité **MEDIUM**, score 50/100) nécessitant une investigation complémentaire. Patterns détectés : reconnaissance_only. **Action recommandée : MONITOR.**

---

## Informations de l'Alerte

| Champ | Valeur |
|---|---|
| **ID** | `ALT-2024-005` |
| **Timestamp** | 2024-08-14T11:00:30 |
| **Source** | Suricata IDS |
| **Titre** | Internal Network Port Scan Detected — 10.0.0.88 |
| **Verdict** | 🟡 **SUSPICIOUS** |
| **Sévérité** | 🟠 **MEDIUM** (score: 50.3/100) |
| **Action recommandée** | 👁️ MONITOR |

---

## IOCs Extraits

| Type | Valeur | Contexte |
|---|---|---|
| ipv4 | `10.0.0.88` | alert_ALT-2024-005 |
| ipv4 | `192.168.250.0` | alert_ALT-2024-005 |

---

## Chronologie des Événements

| Heure | Source | Action | Entité |
|---|---|---|---|
| 11:00:00 | firewall | allow | 10.0.0.88→192.168.250.50 |
| 11:00:01 | firewall | allow | 10.0.0.88→192.168.250.50 |
| 11:00:02 | firewall | allow | 10.0.0.88→192.168.250.50 |
| 11:00:03 | firewall | allow | 10.0.0.88→192.168.250.50 |
| 11:00:04 | firewall | deny | 10.0.0.88→192.168.250.50 |
| 11:00:05 | firewall | allow | 10.0.0.88→192.168.250.50 |
| 11:00:06 | firewall | deny | 10.0.0.88→192.168.250.50 |
| 11:00:07 | firewall | allow | 10.0.0.88→192.168.250.70 |
| 11:00:08 | firewall | allow | 10.0.0.88→192.168.250.70 |
| 11:00:09 | firewall | allow | 10.0.0.88→192.168.250.70 |
| 11:00:10 | firewall | allow | 10.0.0.88→192.168.250.70 |
| 11:00:11 | firewall | deny | 10.0.0.88→192.168.250.70 |
| 11:00:12 | firewall | allow | 10.0.0.88→192.168.250.70 |
| 11:00:13 | firewall | deny | 10.0.0.88→192.168.250.70 |
| 11:00:14 | firewall | allow | 10.0.0.88→192.168.250.100 |
| 11:00:15 | firewall | allow | 10.0.0.88→192.168.250.100 |
| 11:00:16 | firewall | allow | 10.0.0.88→192.168.250.100 |
| 11:00:17 | firewall | allow | 10.0.0.88→192.168.250.100 |
| 11:00:18 | firewall | deny | 10.0.0.88→192.168.250.100 |
| 11:00:19 | firewall | allow | 10.0.0.88→192.168.250.100 |
| 11:00:20 | firewall | deny | 10.0.0.88→192.168.250.100 |
| 11:00:21 | firewall | allow | 10.0.0.88→192.168.250.120 |
| 11:00:22 | firewall | allow | 10.0.0.88→192.168.250.120 |
| 11:00:23 | firewall | allow | 10.0.0.88→192.168.250.120 |
| 11:00:24 | firewall | allow | 10.0.0.88→192.168.250.120 |
| 11:00:25 | firewall | deny | 10.0.0.88→192.168.250.120 |
| 11:00:26 | firewall | allow | 10.0.0.88→192.168.250.120 |
| 11:00:27 | firewall | deny | 10.0.0.88→192.168.250.120 |
| 11:00:30 | ids | alert | 10.0.0.88→192.168.250.0/24 |

---

## Corrélation des Preuves

L'analyse croisée des 29 événements télémétriques a identifié **1 pattern(s)** de corrélation :

- **reconnaissance_only** (confiance 70%) : Network/port scanning activity detected (1 scan events) without subsequent endpoint process execution

### Patterns Détectés
- **reconnaissance_only** (high) : Network/port scanning activity detected (1 scan events) without subsequent endpoint process execution

---

## Vérification Threat Intel

| IOC | Réputation | Confiance | Tags | Source |
|---|---|---|---|---|
| `10.0.0.88` | ⚪ unknown | 30% | internal, scanning | local_known_iocs |
| `192.168.250.0` | ⚪ unknown | 0% | — | none |

---

## Scoring de Sévérité

### Score Combiné

- **Score Règles** : 0.0/100
- **Confiance ML** : 83.92%
- **Score Final** : **50.3/100** → MEDIUM

### Règles Déclenchées

- ✅ pattern_recon_only → +10 pts — _Network scanning without subsequent execution_
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

**Action : MONITOR**

1. Ajouter les IOCs identifiés aux watchlists de surveillance
2. Programmer une revue dans 24h si l'activité persiste
3. Vérifier les logs des 7 derniers jours pour un historique similaire

---

## Raisonnement de l'Agent

### Étape 1 — Extract Indicators of Compromise (IOCs)

- **Tool** : `extract_iocs`
- **Raisonnement** : Extract all atomic observables (IPs, domains, hashes, users, hosts) from raw alert payload
- **Résultat** : Extracted 2 IOCs: 2 IPs, 0 hashes, 0 users, 0 domains.

### Étape 2 — Query network and perimeter telemetry for source IP '10.0.0.88'

- **Tool** : `query_logs`
- **Raisonnement** : Determine whether inbound/outbound connection volume, targeted ports, or IDS signatures indicate malicious probing
- **Résultat** : Identified 29 matching network/IDS telemetry events.

### Étape 3 — Query authentication and endpoint activity for all active identities and hosts

- **Tool** : `query_logs`
- **Raisonnement** : Assess whether user account suffered brute forcing, unauthorized privilege escalation, or executed suspicious processes
- **Résultat** : Retrieved 29 authentication/endpoint events.

### Étape 4 — Cross-source temporal correlation and attack pattern reconstruction

- **Tool** : `correlate_events`
- **Raisonnement** : Synthesize event timeline across perimeter, authentication, and endpoint telemetry to identify multi-stage attack patterns
- **Résultat** : Correlated 29 events. Detected 1 attack pattern(s): ['reconnaissance_only'].

### Étape 5 — Query Threat Intelligence feeds for all extracted external IOCs

- **Tool** : `lookup_threat_intel`
- **Raisonnement** : Validate external indicators against known C2 servers, vulnerability scanners, and malicious hash feeds
- **Résultat** : Evaluated 2 indicators. Malicious tags found: [].

### Étape 6 — Compute combined severity score (rules + ML)

- **Tool** : `score_severity`
- **Raisonnement** : Combine explicit rule-based scoring with ML binary classification to produce calibrated severity
- **Résultat** : Score: 50.3/100 | Severity: MEDIUM | Rules: ['pattern_recon_only', 'all_internal_traffic']

### Étape 7 — Synthesize final investigation verdict and containment action

- **Tool** : `investigation_synthesis`
- **Raisonnement** : Weigh threat intel confidence, correlation patterns, and administrative context to assign verdict
- **Résultat** : Verdict: SUSPICIOUS | Recommended Action: MONITOR

