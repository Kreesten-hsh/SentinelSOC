# Scénario ALT-2024-005 : Internal Network Port Scan Detected — 10.0.0.88

**Scénario de référence** : `scenario_05_reconnaissance`  
**Source SIEM** : `Suricata IDS`  
**Horodatage alerte** : `2024-08-14T11:00:30`

---

## 1. Alerte Brute (Ingestion SIEM)

```json
{
  "src_ip": "10.0.0.88",
  "dest_network": "192.168.250.0/24",
  "signature": "ET SCAN Nmap Scripting Engine User-Agent Detected",
  "unique_destinations": 4,
  "unique_ports": 7,
  "timestamp": "2024-08-14T11:00:00"
}
```

---

## 2. Vérité Terrain (Ground Truth Baseline)

- **Verdict Attendu** : `SUSPICIOUS`
- **Sévérité Attendue** : `MEDIUM`
- **Action Recommandée** : `MONITOR`
- **Chaîne d'attaque documentée** :
  - Network Scanning (TCP SYN/Connect scanning across multiple internal hosts and ports)
  - IDS Detection (Nmap Scripting Engine signature)
- **Justification experte** :
  > Reconnaissance activity detected from an internal IP address without subsequent exploitation or lateral movement. Could represent rogue internal scanning, compromised host, or unannounced internal audit/vulnerability assessment.

---

## 3. Déroulement de l'Investigation Autonome (Agent SentinelSOC)

L'agent a exécuté sa chaîne de raisonnement en 7 étapes causales strictes :

### Étape 1 : Extract Indicators of Compromise (IOCs)
- **Tool mobilisé** : `extract_iocs`
- **Raisonnement** : Extract all atomic observables (IPs, domains, hashes, users, hosts) from raw alert payload
- **Requête / Entrées** : `content={"src_ip": "10.0.0.88", "dest_network": "192.168.250.0/24", "signature": "ET SCA...`
- **Résultat intermédiaire** : Extracted 2 IOCs: 2 IPs, 0 hashes, 0 users, 0 domains.

### Étape 2 : Query network and perimeter telemetry for source IP '10.0.0.88'
- **Tool mobilisé** : `query_logs`
- **Raisonnement** : Determine whether inbound/outbound connection volume, targeted ports, or IDS signatures indicate malicious probing
- **Requête / Entrées** : `src_ip=10.0.0.88, scenario_id=scenario_05_reconnaissance`
- **Résultat intermédiaire** : Identified 29 matching network/IDS telemetry events.

### Étape 3 : Query authentication and endpoint activity for all active identities and hosts
- **Tool mobilisé** : `query_logs`
- **Raisonnement** : Assess whether user account suffered brute forcing, unauthorized privilege escalation, or executed suspicious processes
- **Requête / Entrées** : `user=*, host=*, scenario_id=scenario_05_reconnaissance`
- **Résultat intermédiaire** : Retrieved 29 authentication/endpoint events.

### Étape 4 : Cross-source temporal correlation and attack pattern reconstruction
- **Tool mobilisé** : `correlate_events`
- **Raisonnement** : Synthesize event timeline across perimeter, authentication, and endpoint telemetry to identify multi-stage attack patterns
- **Requête / Entrées** : `scenario_id=scenario_05_reconnaissance, target_ip=10.0.0.88`
- **Résultat intermédiaire** : Correlated 29 events. Detected 1 attack pattern(s): ['reconnaissance_only'].

### Étape 5 : Query Threat Intelligence feeds for all extracted external IOCs
- **Tool mobilisé** : `lookup_threat_intel`
- **Raisonnement** : Validate external indicators against known C2 servers, vulnerability scanners, and malicious hash feeds
- **Requête / Entrées** : `IOCs: ['10.0.0.88', '192.168.250.0']`
- **Résultat intermédiaire** : Evaluated 2 indicators. Malicious tags found: [].

### Étape 6 : Compute combined severity score (rules + ML)
- **Tool mobilisé** : `score_severity`
- **Raisonnement** : Combine explicit rule-based scoring with ML binary classification to produce calibrated severity
- **Requête / Entrées** : `rules=2 triggered, ml_confidence=0.84`
- **Résultat intermédiaire** : Score: 50.3/100 | Severity: MEDIUM | Rules: ['pattern_recon_only', 'all_internal_traffic']

### Étape 7 : Synthesize final investigation verdict and containment action
- **Tool mobilisé** : `investigation_synthesis`
- **Raisonnement** : Weigh threat intel confidence, correlation patterns, and administrative context to assign verdict
- **Requête / Entrées** : `Analytical evaluation`
- **Résultat intermédiaire** : Verdict: SUSPICIOUS | Recommended Action: MONITOR

---

## 4. Évaluation & Alignement Final

| Métrique | Vérité Terrain | Verdict Agent | Statut |
|---|---|---|---|
| **Verdict** | `SUSPICIOUS` | `SUSPICIOUS` | ✅ Conforme |
| **Sévérité** | `MEDIUM` | `MEDIUM` | ✅ Conforme |
| **Action** | `MONITOR` | `MONITOR` | ✅ Conforme |
| **Score combiné** | — | `50.3/100` (Règles: `0.0`, ML: `0.84`) | Calibré |

### Explication du Score de Sévérité
```
Rule score: 0.0/100 (2 rules triggered)
ML confidence: 0.84 (trained model)
Combined: 40% × 0.0 + 60% × 83.9 = 50.3
Severity: MEDIUM
  [correlation] pattern_recon_only: +10 pts — Network/port scanning activity detected (1 scan events) without subsequent endpoint process execution
  [network] all_internal_traffic: -20 pts — No external IP destinations observed in correlated events
```
