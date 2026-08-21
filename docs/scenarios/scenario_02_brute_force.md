# Scénario ALT-2024-002 : Multiple Failed Login Attempts — srv-dc01

**Scénario de référence** : `scenario_02_brute_force`  
**Source SIEM** : `Windows Event Log`  
**Horodatage alerte** : `2024-08-11T03:16:00`

---

## 1. Alerte Brute (Ingestion SIEM)

```json
{
  "src_ip": "40.80.148.42",
  "dest_ip": "192.168.250.50",
  "dest_port": 22,
  "event_id": 4625,
  "failure_count": 15,
  "time_window_seconds": 180,
  "timestamp": "2024-08-11T03:15:00"
}
```

---

## 2. Vérité Terrain (Ground Truth Baseline)

- **Verdict Attendu** : `TRUE_POSITIVE`
- **Sévérité Attendue** : `CRITICAL`
- **Action Recommandée** : `CONTAIN`
- **Chaîne d'attaque documentée** :
  - Network Ingress (Port 22 SSH connection)
  - Credential Guessing (15 rapid failed auth attempts, Event ID 4625)
  - Successful Authentication (Event ID 4624 for user 'admin')
  - Post-Compromise Activity (/bin/bash reading /etc/shadow, wget backdoor download)
- **Justification experte** :
  > Classic SSH dictionary brute force followed immediately by successful logon from the same source IP, then immediate privileged reconnaissance and staging commands on the server.

---

## 3. Déroulement de l'Investigation Autonome (Agent SentinelSOC)

L'agent a exécuté sa chaîne de raisonnement en 7 étapes causales strictes :

### Étape 1 : Extract Indicators of Compromise (IOCs)
- **Tool mobilisé** : `extract_iocs`
- **Raisonnement** : Extract all atomic observables (IPs, domains, hashes, users, hosts) from raw alert payload
- **Requête / Entrées** : `content={"src_ip": "40.80.148.42", "dest_ip": "192.168.250.50", "dest_port": 22, "event_...`
- **Résultat intermédiaire** : Extracted 2 IOCs: 2 IPs, 0 hashes, 0 users, 0 domains.

### Étape 2 : Query network and perimeter telemetry for source IP '40.80.148.42'
- **Tool mobilisé** : `query_logs`
- **Raisonnement** : Determine whether inbound/outbound connection volume, targeted ports, or IDS signatures indicate malicious probing
- **Requête / Entrées** : `src_ip=40.80.148.42, scenario_id=scenario_02_brute_force`
- **Résultat intermédiaire** : Identified 31 matching network/IDS telemetry events.

### Étape 3 : Query authentication and endpoint activity for user 'None' and host 'None'
- **Tool mobilisé** : `query_logs`
- **Raisonnement** : Assess whether user account suffered brute forcing, unauthorized privilege escalation, or executed suspicious processes
- **Requête / Entrées** : `user=None, host=None, scenario_id=scenario_02_brute_force`
- **Résultat intermédiaire** : Retrieved 33 authentication/endpoint events.

### Étape 4 : Cross-source temporal correlation and attack pattern reconstruction
- **Tool mobilisé** : `correlate_events`
- **Raisonnement** : Synthesize event timeline across perimeter, authentication, and endpoint telemetry to identify multi-stage attack patterns
- **Requête / Entrées** : `scenario_id=scenario_02_brute_force, target_ip=40.80.148.42`
- **Résultat intermédiaire** : Correlated 33 events. Detected 1 attack pattern(s): ['brute_force_followed_by_success'].

### Étape 5 : Query Threat Intelligence feeds for all extracted external IOCs
- **Tool mobilisé** : `lookup_threat_intel`
- **Raisonnement** : Validate external indicators against known C2 servers, vulnerability scanners, and malicious hash feeds
- **Requête / Entrées** : `IOCs: ['40.80.148.42', '192.168.250.50']`
- **Résultat intermédiaire** : Evaluated 2 indicators. Malicious tags found: [['apt', 'brute-force', 'po1s0n1vy']].

### Étape 6 : Compute combined severity score (rules + ML)
- **Tool mobilisé** : `score_severity`
- **Raisonnement** : Combine explicit rule-based scoring with ML binary classification to produce calibrated severity
- **Requête / Entrées** : `rules=4 triggered, ml_confidence=0.85`
- **Résultat intermédiaire** : Score: 79.2/100 | Severity: CRITICAL | Rules: ['ti_malicious_high_confidence', 'pattern_brute_force_success', 'after_hours_activity', 'all_internal_traffic']

### Étape 7 : Synthesize final investigation verdict and containment action
- **Tool mobilisé** : `investigation_synthesis`
- **Raisonnement** : Weigh threat intel confidence, correlation patterns, and administrative context to assign verdict
- **Requête / Entrées** : `Analytical evaluation`
- **Résultat intermédiaire** : Verdict: TRUE_POSITIVE | Recommended Action: CONTAIN

---

## 4. Évaluation & Alignement Final

| Métrique | Vérité Terrain | Verdict Agent | Statut |
|---|---|---|---|
| **Verdict** | `TRUE_POSITIVE` | `TRUE_POSITIVE` | ✅ Conforme |
| **Sévérité** | `CRITICAL` | `CRITICAL` | ✅ Conforme |
| **Action** | `CONTAIN` | `CONTAIN` | ✅ Conforme |
| **Score combiné** | — | `79.2/100` (Règles: `70.0`, ML: `0.85`) | Calibré |

### Explication du Score de Sévérité
```
Rule score: 70.0/100 (4 rules triggered)
ML confidence: 0.85 (trained model)
Combined: 40% × 70.0 + 60% × 85.2 = 79.2
Severity: CRITICAL
  [threat_intel] ti_malicious_high_confidence: +40 pts — 1 IOC(s) malicious ≥0.85: ['40.80.148.42']
  [correlation] pattern_brute_force_success: +35 pts — 15 failed authentications followed by successful login for user 'admin' from 40.80.148.42
  [temporal] after_hours_activity: +15 pts — 33/33 events occurred outside business hours
  [network] all_internal_traffic: -20 pts — No external IP destinations observed in correlated events
```
