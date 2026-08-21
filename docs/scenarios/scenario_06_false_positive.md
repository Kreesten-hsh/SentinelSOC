# Scénario ALT-2024-006 : Suspicious PowerShell Execution — srv-dc01

**Scénario de référence** : `scenario_06_false_positive`  
**Source SIEM** : `Sysmon`  
**Horodatage alerte** : `2024-08-15T10:02:00`

---

## 1. Alerte Brute (Ingestion SIEM)

```json
{
  "host": "srv-dc01",
  "user": "WAYNE\\sysadmin.jones",
  "process": "powershell.exe",
  "command_line": "powershell.exe -ExecutionPolicy Bypass -File C:\\Scripts\\Update-ADGroupPolicy.ps1",
  "parent_process": "services.exe",
  "event_id": 1,
  "timestamp": "2024-08-15T10:02:00"
}
```

---

## 2. Vérité Terrain (Ground Truth Baseline)

- **Verdict Attendu** : `FALSE_POSITIVE`
- **Sévérité Attendue** : `LOW`
- **Action Recommandée** : `IGNORE`
- **Chaîne d'attaque documentée** :
  - Legitimate Admin Logon (Event ID 4624 during working hours by sysadmin.jones)
  - Task Scheduler Execution (Weekly-AD-Maintenance scheduled task, Event ID 106)
  - PowerShell Execution (AD Group Policy update script)
  - Standard AD Replication Network Traffic (LDAP Port 389 to broadcast/domain controller)
- **Justification experte** :
  > False Positive. Although the alert flagged PowerShell ExecutionPolicy Bypass, log correlation reveals execution was initiated by a recurring Task Scheduler job ('Weekly-AD-Maintenance') during business hours by an authorized domain admin, accompanied exclusively by normal LDAP directory replication.

---

## 3. Déroulement de l'Investigation Autonome (Agent SentinelSOC)

L'agent a exécuté sa chaîne de raisonnement en 7 étapes causales strictes :

### Étape 1 : Extract Indicators of Compromise (IOCs)
- **Tool mobilisé** : `extract_iocs`
- **Raisonnement** : Extract all atomic observables (IPs, domains, hashes, users, hosts) from raw alert payload
- **Requête / Entrées** : `content={"host": "srv-dc01", "user": "WAYNE\\sysadmin.jones", "process": "powershell.exe...`
- **Résultat intermédiaire** : Extracted 2 IOCs: 0 IPs, 0 hashes, 1 users, 0 domains.

### Étape 2 : Query network and perimeter telemetry for source IP 'None'
- **Tool mobilisé** : `query_logs`
- **Raisonnement** : Determine whether inbound/outbound connection volume, targeted ports, or IDS signatures indicate malicious probing
- **Requête / Entrées** : `src_ip=None, scenario_id=scenario_06_false_positive`
- **Résultat intermédiaire** : Identified 4 matching network/IDS telemetry events.

### Étape 3 : Query authentication and endpoint activity for user 'WAYNE\sysadmin.jones' and host 'srv-dc01'
- **Tool mobilisé** : `query_logs`
- **Raisonnement** : Assess whether user account suffered brute forcing, unauthorized privilege escalation, or executed suspicious processes
- **Requête / Entrées** : `user=WAYNE\sysadmin.jones, host=srv-dc01, scenario_id=scenario_06_false_positive`
- **Résultat intermédiaire** : Retrieved 2 authentication/endpoint events.

### Étape 4 : Cross-source temporal correlation and attack pattern reconstruction
- **Tool mobilisé** : `correlate_events`
- **Raisonnement** : Synthesize event timeline across perimeter, authentication, and endpoint telemetry to identify multi-stage attack patterns
- **Requête / Entrées** : `scenario_id=scenario_06_false_positive, target_ip=None`
- **Résultat intermédiaire** : Correlated 4 events. Detected 1 attack pattern(s): ['scheduled_task_triggered_execution'].

### Étape 5 : Query Threat Intelligence feeds for all extracted external IOCs
- **Tool mobilisé** : `lookup_threat_intel`
- **Raisonnement** : Validate external indicators against known C2 servers, vulnerability scanners, and malicious hash feeds
- **Requête / Entrées** : `IOCs: []`
- **Résultat intermédiaire** : Evaluated 0 indicators. Malicious tags found: [].

### Étape 6 : Compute combined severity score (rules + ML)
- **Tool mobilisé** : `score_severity`
- **Raisonnement** : Combine explicit rule-based scoring with ML binary classification to produce calibrated severity
- **Requête / Entrées** : `rules=2 triggered, ml_confidence=0.18`
- **Résultat intermédiaire** : Score: 11.1/100 | Severity: LOW | Rules: ['pattern_scheduled_task', 'all_internal_traffic']

### Étape 7 : Synthesize final investigation verdict and containment action
- **Tool mobilisé** : `investigation_synthesis`
- **Raisonnement** : Weigh threat intel confidence, correlation patterns, and administrative context to assign verdict
- **Requête / Entrées** : `Analytical evaluation`
- **Résultat intermédiaire** : Verdict: FALSE_POSITIVE | Recommended Action: IGNORE

---

## 4. Évaluation & Alignement Final

| Métrique | Vérité Terrain | Verdict Agent | Statut |
|---|---|---|---|
| **Verdict** | `FALSE_POSITIVE` | `FALSE_POSITIVE` | ✅ Conforme |
| **Sévérité** | `LOW` | `LOW` | ✅ Conforme |
| **Action** | `IGNORE` | `IGNORE` | ✅ Conforme |
| **Score combiné** | — | `11.1/100` (Règles: `0.0`, ML: `0.18`) | Calibré |

### Explication du Score de Sévérité
```
Rule score: 0.0/100 (2 rules triggered)
ML confidence: 0.18 (trained model)
Combined: 40% × 0.0 + 60% × 18.5 = 11.1
Severity: LOW
  [correlation] pattern_scheduled_task: -15 pts — Endpoint process execution correlates with scheduled task trigger (['Weekly-AD-Maintenance'])
  [network] all_internal_traffic: -20 pts — No external IP destinations observed in correlated events
```
