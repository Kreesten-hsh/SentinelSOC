# Scénario ALT-2024-008 : Multiple Failed OWA Logins from Single External IP

**Scénario de référence** : `scenario_08_credential_stuffing`  
**Source SIEM** : `Windows Event Log`  
**Horodatage alerte** : `2024-08-17T07:00:30`

---

## 1. Alerte Brute (Ingestion SIEM)

```json
{
  "src_ip": "198.71.247.91",
  "dest_ip": "192.168.250.70",
  "dest_port": 443,
  "event_id": 4625,
  "unique_users_targeted": 12,
  "failure_count": 12,
  "success_count": 2,
  "time_window_seconds": 60,
  "service": "OWA",
  "timestamp": "2024-08-17T07:00:30"
}
```

---

## 2. Vérité Terrain (Ground Truth Baseline)

- **Verdict Attendu** : `TRUE_POSITIVE`
- **Sévérité Attendue** : `CRITICAL`
- **Action Recommandée** : `CONTAIN`
- **Chaîne d'attaque documentée** :
  - Distributed Account Testing (12 different usernames attempted in rapid succession from a single IP)
  - Failed Logons (10 failed authentications with bad passwords)
  - Account Compromise (2 successful authentications for lucius.fox and barbara.gordon)
  - Unauthorized Mailbox Access (Inbox access via OWA)
- **Justification experte** :
  > Credential stuffing campaign. A single external IP tested a list of corporate usernames with varied leaked credentials, successfully accessing mailboxes for two accounts. Immediate password resets and session terminations required.

---

## 3. Déroulement de l'Investigation Autonome (Agent SentinelSOC)

L'agent a exécuté sa chaîne de raisonnement en 7 étapes causales strictes :

### Étape 1 : Extract Indicators of Compromise (IOCs)
- **Tool mobilisé** : `extract_iocs`
- **Raisonnement** : Extract all atomic observables (IPs, domains, hashes, users, hosts) from raw alert payload
- **Requête / Entrées** : `content={"src_ip": "198.71.247.91", "dest_ip": "192.168.250.70", "dest_port": 443, "even...`
- **Résultat intermédiaire** : Extracted 2 IOCs: 2 IPs, 0 hashes, 0 users, 0 domains.

### Étape 2 : Query network and perimeter telemetry for source IP '198.71.247.91'
- **Tool mobilisé** : `query_logs`
- **Raisonnement** : Determine whether inbound/outbound connection volume, targeted ports, or IDS signatures indicate malicious probing
- **Requête / Entrées** : `src_ip=198.71.247.91, scenario_id=scenario_08_credential_stuffing`
- **Résultat intermédiaire** : Identified 29 matching network/IDS telemetry events.

### Étape 3 : Query authentication and endpoint activity for user 'None' and host 'None'
- **Tool mobilisé** : `query_logs`
- **Raisonnement** : Assess whether user account suffered brute forcing, unauthorized privilege escalation, or executed suspicious processes
- **Requête / Entrées** : `user=None, host=None, scenario_id=scenario_08_credential_stuffing`
- **Résultat intermédiaire** : Retrieved 29 authentication/endpoint events.

### Étape 4 : Cross-source temporal correlation and attack pattern reconstruction
- **Tool mobilisé** : `correlate_events`
- **Raisonnement** : Synthesize event timeline across perimeter, authentication, and endpoint telemetry to identify multi-stage attack patterns
- **Requête / Entrées** : `scenario_id=scenario_08_credential_stuffing, target_ip=198.71.247.91`
- **Résultat intermédiaire** : Correlated 29 events. Detected 1 attack pattern(s): ['brute_force_followed_by_success'].

### Étape 5 : Query Threat Intelligence feeds for all extracted external IOCs
- **Tool mobilisé** : `lookup_threat_intel`
- **Raisonnement** : Validate external indicators against known C2 servers, vulnerability scanners, and malicious hash feeds
- **Requête / Entrées** : `IOCs: ['198.71.247.91', '192.168.250.70']`
- **Résultat intermédiaire** : Evaluated 2 indicators. Malicious tags found: [['credential-stuffing', 'brute-force', 'webmail-attack']].

### Étape 6 : Compute combined severity score (rules + ML)
- **Tool mobilisé** : `score_severity`
- **Raisonnement** : Combine explicit rule-based scoring with ML binary classification to produce calibrated severity
- **Requête / Entrées** : `rules=3 triggered, ml_confidence=0.87`
- **Résultat intermédiaire** : Score: 74.3/100 | Severity: CRITICAL | Rules: ['ti_malicious_high_confidence', 'pattern_brute_force_success', 'all_internal_traffic']

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
| **Score combiné** | — | `74.3/100` (Règles: `55.0`, ML: `0.87`) | Calibré |

### Explication du Score de Sévérité
```
Rule score: 55.0/100 (3 rules triggered)
ML confidence: 0.87 (trained model)
Combined: 40% × 55.0 + 60% × 87.2 = 74.3
Severity: CRITICAL
  [threat_intel] ti_malicious_high_confidence: +40 pts — 1 IOC(s) malicious ≥0.85: ['198.71.247.91']
  [correlation] pattern_brute_force_success: +35 pts — 12 failed authentications followed by successful login for user 'WAYNE\lucius.fox' from 198.71.247.91
  [network] all_internal_traffic: -20 pts — No external IP destinations observed in correlated events
```
