# Scénario ALT-2024-001 : Web Vulnerability Scanner Detected — imreallynotbatman.com

**Scénario de référence** : `scenario_01_web_defacement`  
**Source SIEM** : `Suricata IDS`  
**Horodatage alerte** : `2024-08-10T14:20:01`

---

## 1. Alerte Brute (Ingestion SIEM)

```json
{
  "src_ip": "23.22.63.114",
  "dest_ip": "192.168.250.70",
  "dest_port": 80,
  "signature": "ET SCAN Acunetix Web Vulnerability Scanner",
  "severity": 2,
  "timestamp": "2024-08-10T14:20:00"
}
```

---

## 2. Vérité Terrain (Ground Truth Baseline)

- **Verdict Attendu** : `TRUE_POSITIVE`
- **Sévérité Attendue** : `CRITICAL`
- **Action Recommandée** : `CONTAIN`
- **Chaîne d'attaque documentée** :
  - Reconnaissance (Acunetix vulnerability scan)
  - Web Authentication Brute Force (/joomla/administrator/index.php)
  - Exploitation & Web Shell Injection (Joomla template editor abuse)
  - Post-Exploitation Execution (cmd.exe /c whoami via w3wp.exe)
  - Web Defacement (Replacement of site index)
- **Justification experte** :
  > Clear malicious progression matching the po1s0n1vy web attack campaign in Splunk BOTS v1. Multiple correlating log sources (Suricata IDS, Web Server, Sysmon Endpoint) confirm initial probe turned into administrative takeover and webshell execution.

---

## 3. Déroulement de l'Investigation Autonome (Agent SentinelSOC)

L'agent a exécuté sa chaîne de raisonnement en 7 étapes causales strictes :

### Étape 1 : Extract Indicators of Compromise (IOCs)
- **Tool mobilisé** : `extract_iocs`
- **Raisonnement** : Extract all atomic observables (IPs, domains, hashes, users, hosts) from raw alert payload
- **Requête / Entrées** : `content={"src_ip": "23.22.63.114", "dest_ip": "192.168.250.70", "dest_port": 80, "signat...`
- **Résultat intermédiaire** : Extracted 2 IOCs: 2 IPs, 0 hashes, 0 users, 0 domains.

### Étape 2 : Query network and perimeter telemetry for source IP '23.22.63.114'
- **Tool mobilisé** : `query_logs`
- **Raisonnement** : Determine whether inbound/outbound connection volume, targeted ports, or IDS signatures indicate malicious probing
- **Requête / Entrées** : `src_ip=23.22.63.114, scenario_id=scenario_01_web_defacement`
- **Résultat intermédiaire** : Identified 13 matching network/IDS telemetry events.

### Étape 3 : Query authentication and endpoint activity for user 'None' and host 'None'
- **Tool mobilisé** : `query_logs`
- **Raisonnement** : Assess whether user account suffered brute forcing, unauthorized privilege escalation, or executed suspicious processes
- **Requête / Entrées** : `user=None, host=None, scenario_id=scenario_01_web_defacement`
- **Résultat intermédiaire** : Retrieved 14 authentication/endpoint events.

### Étape 4 : Cross-source temporal correlation and attack pattern reconstruction
- **Tool mobilisé** : `correlate_events`
- **Raisonnement** : Synthesize event timeline across perimeter, authentication, and endpoint telemetry to identify multi-stage attack patterns
- **Requête / Entrées** : `scenario_id=scenario_01_web_defacement, target_ip=23.22.63.114`
- **Résultat intermédiaire** : Correlated 14 events. Detected 1 attack pattern(s): ['reconnaissance_followed_by_execution'].

### Étape 5 : Query Threat Intelligence feeds for all extracted external IOCs
- **Tool mobilisé** : `lookup_threat_intel`
- **Raisonnement** : Validate external indicators against known C2 servers, vulnerability scanners, and malicious hash feeds
- **Requête / Entrées** : `IOCs: ['23.22.63.114', '192.168.250.70']`
- **Résultat intermédiaire** : Evaluated 2 indicators. Malicious tags found: [['web-scanner', 'acunetix', 'vulnerability-assessment']].

### Étape 6 : Compute combined severity score (rules + ML)
- **Tool mobilisé** : `score_severity`
- **Raisonnement** : Combine explicit rule-based scoring with ML binary classification to produce calibrated severity
- **Requête / Entrées** : `rules=3 triggered, ml_confidence=0.91`
- **Résultat intermédiaire** : Score: 76.5/100 | Severity: CRITICAL | Rules: ['ti_malicious_high_confidence', 'pattern_recon_then_execution', 'all_internal_traffic']

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
| **Score combiné** | — | `76.5/100` (Règles: `55.0`, ML: `0.91`) | Calibré |

### Explication du Score de Sévérité
```
Rule score: 55.0/100 (3 rules triggered)
ML confidence: 0.91 (trained model)
Combined: 40% × 55.0 + 60% × 90.8 = 76.5
Severity: CRITICAL
  [threat_intel] ti_malicious_high_confidence: +40 pts — 1 IOC(s) malicious ≥0.85: ['23.22.63.114']
  [correlation] pattern_recon_then_execution: +35 pts — Vulnerability scanning detected followed by process execution (1 endpoint events observed)
  [network] all_internal_traffic: -20 pts — No external IP destinations observed in correlated events
```
