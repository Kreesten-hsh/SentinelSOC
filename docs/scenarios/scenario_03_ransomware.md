# Scénario ALT-2024-003 : Cerber Ransomware C2 Communication Detected — ws-bobsmith

**Scénario de référence** : `scenario_03_ransomware`  
**Source SIEM** : `Suricata IDS`  
**Horodatage alerte** : `2024-08-12T09:46:20`

---

## 1. Alerte Brute (Ingestion SIEM)

```json
{
  "src_ip": "192.168.250.100",
  "dest_ip": "185.141.27.88",
  "dest_port": 443,
  "signature": "ET MALWARE Cerber Ransomware CnC Beacon",
  "severity": 1,
  "host": "ws-bobsmith",
  "user": "WAYNE\\bob.smith",
  "timestamp": "2024-08-12T09:46:20"
}
```

---

## 2. Vérité Terrain (Ground Truth Baseline)

- **Verdict Attendu** : `TRUE_POSITIVE`
- **Sévérité Attendue** : `CRITICAL`
- **Action Recommandée** : `CONTAIN`
- **Chaîne d'attaque documentée** :
  - Initial Access (Physical USB storage insertion, Event ID 6416)
  - Payload Execution (invoice_aug2024.exe)
  - Defense Evasion & Anti-Recovery (vssadmin delete shadows /all /quiet)
  - Command and Control (Cerber C2 beaconing to 185.141.27.88:443)
  - Impact (Mass file modification to .cerber, ransom note dropped)
- **Justification experte** :
  > Unambiguous ransomware infection lifecycle matching Cerber USB scenario in BOTS v1. Correlation of USB insertion, shadow copy deletion, IDS C2 alert, and rapid mass file renaming.

---

## 3. Déroulement de l'Investigation Autonome (Agent SentinelSOC)

L'agent a exécuté sa chaîne de raisonnement en 7 étapes causales strictes :

### Étape 1 : Extract Indicators of Compromise (IOCs)
- **Tool mobilisé** : `extract_iocs`
- **Raisonnement** : Extract all atomic observables (IPs, domains, hashes, users, hosts) from raw alert payload
- **Requête / Entrées** : `content={"src_ip": "192.168.250.100", "dest_ip": "185.141.27.88", "dest_port": 443, "sig...`
- **Résultat intermédiaire** : Extracted 4 IOCs: 2 IPs, 0 hashes, 1 users, 0 domains.

### Étape 2 : Query network and perimeter telemetry for source IP '192.168.250.100'
- **Tool mobilisé** : `query_logs`
- **Raisonnement** : Determine whether inbound/outbound connection volume, targeted ports, or IDS signatures indicate malicious probing
- **Requête / Entrées** : `src_ip=192.168.250.100, scenario_id=scenario_03_ransomware`
- **Résultat intermédiaire** : Identified 2 matching network/IDS telemetry events.

### Étape 3 : Query authentication and endpoint activity for user 'WAYNE\bob.smith' and host 'ws-bobsmith'
- **Tool mobilisé** : `query_logs`
- **Raisonnement** : Assess whether user account suffered brute forcing, unauthorized privilege escalation, or executed suspicious processes
- **Requête / Entrées** : `user=WAYNE\bob.smith, host=ws-bobsmith, scenario_id=scenario_03_ransomware`
- **Résultat intermédiaire** : Retrieved 6 authentication/endpoint events.

### Étape 4 : Cross-source temporal correlation and attack pattern reconstruction
- **Tool mobilisé** : `correlate_events`
- **Raisonnement** : Synthesize event timeline across perimeter, authentication, and endpoint telemetry to identify multi-stage attack patterns
- **Requête / Entrées** : `scenario_id=scenario_03_ransomware, target_ip=192.168.250.100`
- **Résultat intermédiaire** : Correlated 8 events. Detected 1 attack pattern(s): ['command_and_control_or_exfiltration'].

### Étape 5 : Query Threat Intelligence feeds for all extracted external IOCs
- **Tool mobilisé** : `lookup_threat_intel`
- **Raisonnement** : Validate external indicators against known C2 servers, vulnerability scanners, and malicious hash feeds
- **Requête / Entrées** : `IOCs: ['192.168.250.100', '185.141.27.88']`
- **Résultat intermédiaire** : Evaluated 2 indicators. Malicious tags found: [['c2', 'ransomware', 'cerber']].

### Étape 6 : Compute combined severity score (rules + ML)
- **Tool mobilisé** : `score_severity`
- **Raisonnement** : Combine explicit rule-based scoring with ML binary classification to produce calibrated severity
- **Requête / Entrées** : `rules=3 triggered, ml_confidence=0.97`
- **Résultat intermédiaire** : Score: 94.2/100 | Severity: CRITICAL | Rules: ['ti_malicious_high_confidence', 'pattern_c2_exfiltration', 'external_dest_ip']

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
| **Score combiné** | — | `94.2/100` (Règles: `90.0`, ML: `0.97`) | Calibré |

### Explication du Score de Sévérité
```
Rule score: 90.0/100 (3 rules triggered)
ML confidence: 0.97 (trained model)
Combined: 40% × 90.0 + 60% × 97.0 = 94.2
Severity: CRITICAL
  [threat_intel] ti_malicious_high_confidence: +40 pts — 1 IOC(s) malicious ≥0.85: ['185.141.27.88']
  [correlation] pattern_c2_exfiltration: +40 pts — Endpoint activity directly correlates with outbound external communication/IDS alert
  [network] external_dest_ip: +10 pts — External destinations: ['185.141.27.88']
```
