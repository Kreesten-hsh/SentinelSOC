# Scénario ALT-2024-007 : PsExec Remote Execution Detected — ws-bobsmith → srv-dc01

**Scénario de référence** : `scenario_07_ambiguous_lateral`  
**Source SIEM** : `Sysmon`  
**Horodatage alerte** : `2024-08-16T15:35:00`

---

## 1. Alerte Brute (Ingestion SIEM)

```json
{
  "src_ip": "192.168.250.100",
  "dest_ip": "192.168.250.50",
  "host": "ws-bobsmith",
  "user": "WAYNE\\bob.smith",
  "process": "PsExec.exe",
  "command_line": "PsExec.exe \\\\srv-dc01 cmd.exe",
  "timestamp": "2024-08-16T15:35:00"
}
```

---

## 2. Vérité Terrain (Ground Truth Baseline)

- **Verdict Attendu** : `SUSPICIOUS`
- **Sévérité Attendue** : `MEDIUM`
- **Action Recommandée** : `ESCALATE`
- **Chaîne d'attaque documentée** :
  - Workstation Logon (bob.smith on ws-bobsmith)
  - Remote Admin Tool Invocation (PsExec to srv-dc01)
  - Domain Discovery (net user /domain)
  - File Share Access (43 files accessed on srv-fileserver)
- **Justification experte** :
  > Ambiguous event sequence. Dual-use administrative tools (PsExec) and domain enumeration commands executed by a standard user account across multiple core servers. Requires analyst confirmation with account owner to determine if it is sanctioned IT support activity or active lateral movement by an adversary using stolen credentials.

---

## 3. Déroulement de l'Investigation Autonome (Agent SentinelSOC)

L'agent a exécuté sa chaîne de raisonnement en 7 étapes causales strictes :

### Étape 1 : Extract Indicators of Compromise (IOCs)
- **Tool mobilisé** : `extract_iocs`
- **Raisonnement** : Extract all atomic observables (IPs, domains, hashes, users, hosts) from raw alert payload
- **Requête / Entrées** : `content={"src_ip": "192.168.250.100", "dest_ip": "192.168.250.50", "host": "ws-bobsmith"...`
- **Résultat intermédiaire** : Extracted 5 IOCs: 2 IPs, 0 hashes, 1 users, 0 domains.

### Étape 2 : Query network and perimeter telemetry for source IP '192.168.250.100'
- **Tool mobilisé** : `query_logs`
- **Raisonnement** : Determine whether inbound/outbound connection volume, targeted ports, or IDS signatures indicate malicious probing
- **Requête / Entrées** : `src_ip=192.168.250.100, scenario_id=scenario_07_ambiguous_lateral`
- **Résultat intermédiaire** : Identified 4 matching network/IDS telemetry events.

### Étape 3 : Query authentication and endpoint activity for user 'WAYNE\bob.smith' and host 'ws-bobsmith'
- **Tool mobilisé** : `query_logs`
- **Raisonnement** : Assess whether user account suffered brute forcing, unauthorized privilege escalation, or executed suspicious processes
- **Requête / Entrées** : `user=WAYNE\bob.smith, host=ws-bobsmith, scenario_id=scenario_07_ambiguous_lateral`
- **Résultat intermédiaire** : Retrieved 2 authentication/endpoint events.

### Étape 4 : Cross-source temporal correlation and attack pattern reconstruction
- **Tool mobilisé** : `correlate_events`
- **Raisonnement** : Synthesize event timeline across perimeter, authentication, and endpoint telemetry to identify multi-stage attack patterns
- **Requête / Entrées** : `scenario_id=scenario_07_ambiguous_lateral, target_ip=192.168.250.100`
- **Résultat intermédiaire** : Correlated 7 events. Detected 1 attack pattern(s): ['lateral_movement_dual_use_tool'].

### Étape 5 : Query Threat Intelligence feeds for all extracted external IOCs
- **Tool mobilisé** : `lookup_threat_intel`
- **Raisonnement** : Validate external indicators against known C2 servers, vulnerability scanners, and malicious hash feeds
- **Requête / Entrées** : `IOCs: ['192.168.250.100', '192.168.250.50']`
- **Résultat intermédiaire** : Evaluated 2 indicators. Malicious tags found: [].

### Étape 6 : Compute combined severity score (rules + ML)
- **Tool mobilisé** : `score_severity`
- **Raisonnement** : Combine explicit rule-based scoring with ML binary classification to produce calibrated severity
- **Requête / Entrées** : `rules=2 triggered, ml_confidence=0.70`
- **Résultat intermédiaire** : Score: 42.0/100 | Severity: MEDIUM | Rules: ['pattern_lateral_movement', 'all_internal_traffic']

### Étape 7 : Synthesize final investigation verdict and containment action
- **Tool mobilisé** : `investigation_synthesis`
- **Raisonnement** : Weigh threat intel confidence, correlation patterns, and administrative context to assign verdict
- **Requête / Entrées** : `Analytical evaluation`
- **Résultat intermédiaire** : Verdict: SUSPICIOUS | Recommended Action: ESCALATE

---

## 4. Évaluation & Alignement Final

| Métrique | Vérité Terrain | Verdict Agent | Statut |
|---|---|---|---|
| **Verdict** | `SUSPICIOUS` | `SUSPICIOUS` | ✅ Conforme |
| **Sévérité** | `MEDIUM` | `MEDIUM` | ✅ Conforme |
| **Action** | `ESCALATE` | `ESCALATE` | ✅ Conforme |
| **Score combiné** | — | `42.0/100` (Règles: `0.0`, ML: `0.70`) | Calibré |

### Explication du Score de Sévérité
```
Rule score: 0.0/100 (2 rules triggered)
ML confidence: 0.70 (trained model)
Combined: 40% × 0.0 + 60% × 70.0 = 42.0
Severity: MEDIUM
  [correlation] pattern_lateral_movement: +20 pts — Dual-use administrative tool execution detected (['PsExec.exe']) accompanied by network logons across 4 distinct target hosts (['srv-dc01', 'srv-fileserver', '192.168.250.60', '192.168.250.50'])
  [network] all_internal_traffic: -20 pts — No external IP destinations observed in correlated events
```
