# Scénario ALT-2024-004 : Large Outbound Data Transfer — ws-jdoe to External IP

**Scénario de référence** : `scenario_04_data_exfiltration`  
**Source SIEM** : `Fortinet Firewall`  
**Horodatage alerte** : `2024-08-13T22:42:00`

---

## 1. Alerte Brute (Ingestion SIEM)

```json
{
  "src_ip": "192.168.250.120",
  "dest_ip": "91.234.99.42",
  "dest_port": 443,
  "bytes_sent": 48500000,
  "host": "ws-jdoe",
  "user": "WAYNE\\j.doe",
  "timestamp": "2024-08-13T22:42:00"
}
```

---

## 2. Vérité Terrain (Ground Truth Baseline)

- **Verdict Attendu** : `TRUE_POSITIVE`
- **Sévérité Attendue** : `CRITICAL`
- **Action Recommandée** : `CONTAIN`
- **Chaîne d'attaque documentée** :
  - Anomalous Access (After-hours logon at 22:30)
  - Collection (Access to confidential finance and restricted HR shares, Event ID 4663)
  - Archive Staging (7z compression into C:\Temp\backup.7z)
  - Exfiltration (Large outbound HTTPS stream ~48.5MB to external drop IP 91.234.99.42)
  - DNS Resolution (dropzone-files.xyz)
- **Justification experte** :
  > Insider threat / data exfiltration pattern. Temporal correlation of unauthorized sensitive file access, local archiving, and immediate large volume transfer to an external IP matching a known drop domain.

---

## 3. Déroulement de l'Investigation Autonome (Agent SentinelSOC)

L'agent a exécuté sa chaîne de raisonnement en 7 étapes causales strictes :

### Étape 1 : Extract Indicators of Compromise (IOCs)
- **Tool mobilisé** : `extract_iocs`
- **Raisonnement** : Extract all atomic observables (IPs, domains, hashes, users, hosts) from raw alert payload
- **Requête / Entrées** : `content={"src_ip": "192.168.250.120", "dest_ip": "91.234.99.42", "dest_port": 443, "byte...`
- **Résultat intermédiaire** : Extracted 4 IOCs: 2 IPs, 0 hashes, 1 users, 0 domains.

### Étape 2 : Query network and perimeter telemetry for source IP '192.168.250.120'
- **Tool mobilisé** : `query_logs`
- **Raisonnement** : Determine whether inbound/outbound connection volume, targeted ports, or IDS signatures indicate malicious probing
- **Requête / Entrées** : `src_ip=192.168.250.120, scenario_id=scenario_04_data_exfiltration`
- **Résultat intermédiaire** : Identified 4 matching network/IDS telemetry events.

### Étape 3 : Query authentication and endpoint activity for user 'WAYNE\j.doe' and host 'ws-jdoe'
- **Tool mobilisé** : `query_logs`
- **Raisonnement** : Assess whether user account suffered brute forcing, unauthorized privilege escalation, or executed suspicious processes
- **Requête / Entrées** : `user=WAYNE\j.doe, host=ws-jdoe, scenario_id=scenario_04_data_exfiltration`
- **Résultat intermédiaire** : Retrieved 4 authentication/endpoint events.

### Étape 4 : Cross-source temporal correlation and attack pattern reconstruction
- **Tool mobilisé** : `correlate_events`
- **Raisonnement** : Synthesize event timeline across perimeter, authentication, and endpoint telemetry to identify multi-stage attack patterns
- **Requête / Entrées** : `scenario_id=scenario_04_data_exfiltration, target_ip=192.168.250.120`
- **Résultat intermédiaire** : Correlated 7 events. Detected 1 attack pattern(s): ['command_and_control_or_exfiltration'].

### Étape 5 : Query Threat Intelligence feeds for all extracted external IOCs
- **Tool mobilisé** : `lookup_threat_intel`
- **Raisonnement** : Validate external indicators against known C2 servers, vulnerability scanners, and malicious hash feeds
- **Requête / Entrées** : `IOCs: ['192.168.250.120', '91.234.99.42']`
- **Résultat intermédiaire** : Evaluated 2 indicators. Malicious tags found: [['exfiltration', 'data-theft', 'drop-server']].

### Étape 6 : Compute combined severity score (rules + ML)
- **Tool mobilisé** : `score_severity`
- **Raisonnement** : Combine explicit rule-based scoring with ML binary classification to produce calibrated severity
- **Requête / Entrées** : `rules=5 triggered, ml_confidence=1.00`
- **Résultat intermédiaire** : Score: 100.0/100 | Severity: CRITICAL | Rules: ['ti_malicious_high_confidence', 'pattern_c2_exfiltration', 'after_hours_activity', 'external_dest_ip', 'high_volume_outbound']

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
| **Score combiné** | — | `100.0/100` (Règles: `100.0`, ML: `1.00`) | Calibré |

### Explication du Score de Sévérité
```
Rule score: 100.0/100 (5 rules triggered)
ML confidence: 1.00 (trained model)
Combined: 40% × 100.0 + 60% × 100.0 = 100.0
Severity: CRITICAL
  [threat_intel] ti_malicious_high_confidence: +40 pts — 1 IOC(s) malicious ≥0.85: ['91.234.99.42']
  [correlation] pattern_c2_exfiltration: +40 pts — Endpoint activity directly correlates with outbound external communication/IDS alert
  [temporal] after_hours_activity: +15 pts — 7/7 events occurred outside business hours
  [network] external_dest_ip: +10 pts — External destinations: ['91.234.99.42']
  [network] high_volume_outbound: +15 pts — Total outbound: 48.5 MB
```
