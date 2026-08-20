"""Tool for extracting Indicators of Compromise (IOCs) from alert payloads and raw logs."""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlparse

from smolagents import Tool

from src.models.alert import IOC, IOCCollection, IOCType

# Compiled regex patterns for high-precision extraction
IPV4_PATTERN = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
IPV6_PATTERN = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b")
SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")
SHA1_PATTERN = re.compile(r"\b[a-fA-F0-9]{40}\b")
MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")
DOMAIN_PATTERN = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|org|net|xyz|edu|gov|mil|io|fr|de|uk|ru|cn|info|biz)\b", re.IGNORECASE)
USER_DOMAIN_PATTERN = re.compile(r"\b([A-Z0-9_-]{2,15}\\[a-zA-Z0-9._-]{2,30})\b")
HOST_PATTERN = re.compile(r"\b(srv-[a-zA-Z0-9_-]+|ws-[a-zA-Z0-9_-]+|fw-[a-zA-Z0-9_-]+|ids-[a-zA-Z0-9_-]+)\b", re.IGNORECASE)


def extract_iocs_from_text(text: str, context: str = "raw_text") -> list[IOC]:
    """Extract typed IOCs from an arbitrary string using regex and heuristic validation."""
    found: list[IOC] = []
    seen: set[tuple[IOCType, str]] = set()

    def add_ioc(ioc_type: IOCType, value: str, ctx: str) -> None:
        key = (ioc_type, value.strip())
        if key not in seen and key[1]:
            seen.add(key)
            found.append(IOC(ioc_type=ioc_type, value=key[1], context=ctx))

    # 1. Hashes (order: sha256 -> sha1 -> md5 to avoid substrings)
    for match in SHA256_PATTERN.findall(text):
        add_ioc(IOCType.SHA256, match.lower(), context)

    # Filter out sha256 matches before checking sha1/md5 to prevent overlaps
    text_without_sha256 = SHA256_PATTERN.sub(" ", text)
    for match in SHA1_PATTERN.findall(text_without_sha256):
        add_ioc(IOCType.SHA1, match.lower(), context)

    text_without_hashes = SHA1_PATTERN.sub(" ", text_without_sha256)
    for match in MD5_PATTERN.findall(text_without_hashes):
        add_ioc(IOCType.MD5, match.lower(), context)

    # 2. IPv4 & IPv6
    for match in IPV4_PATTERN.findall(text):
        # Ignore common non-routable dummy/subnet masks
        if match not in {"255.255.255.0", "255.255.255.255", "0.0.0.0"}:
            add_ioc(IOCType.IPV4, match, context)

    for match in IPV6_PATTERN.findall(text):
        add_ioc(IOCType.IPV6, match, context)

    # 3. Users with DOMAIN\user format
    for match in USER_DOMAIN_PATTERN.findall(text):
        add_ioc(IOCType.USER, match, context)

    # 4. Standard Hosts
    for match in HOST_PATTERN.findall(text):
        add_ioc(IOCType.HOSTNAME, match.lower(), context)

    # 5. Domains (ignore file extensions like .exe, .ps1, .zip)
    for match in DOMAIN_PATTERN.findall(text):
        lower_match = match.lower()
        if not lower_match.endswith((".exe", ".dll", ".ps1", ".bat", ".sh", ".zip", ".tar", ".gz")):
            add_ioc(IOCType.DOMAIN, lower_match, context)

    return found


def extract_iocs_from_dict(data: dict[str, Any], alert_id: str = "") -> IOCCollection:
    """Extract all IOCs from a structured alert or log dictionary."""
    text_repr = json.dumps(data, default=str)
    iocs = extract_iocs_from_text(text_repr, context=f"alert_{alert_id}" if alert_id else "structured_data")

    # Explicit field checks
    if "src_ip" in data and data["src_ip"] and isinstance(data["src_ip"], str):
        if not any(i.ioc_type == IOCType.IPV4 and i.value == data["src_ip"] for i in iocs):
            iocs.append(IOC(ioc_type=IOCType.IPV4, value=data["src_ip"], context="src_ip"))
    if "dest_ip" in data and data["dest_ip"] and isinstance(data["dest_ip"], str):
        if not any(i.ioc_type == IOCType.IPV4 and i.value == data["dest_ip"] for i in iocs):
            iocs.append(IOC(ioc_type=IOCType.IPV4, value=data["dest_ip"], context="dest_ip"))
    if "user" in data and data["user"] and isinstance(data["user"], str):
        if not any(i.ioc_type == IOCType.USER and i.value == data["user"] for i in iocs):
            iocs.append(IOC(ioc_type=IOCType.USER, value=data["user"], context="user"))
    if "host" in data and data["host"] and isinstance(data["host"], str):
        if not any(i.ioc_type == IOCType.HOSTNAME and i.value == data["host"] for i in iocs):
            iocs.append(IOC(ioc_type=IOCType.HOSTNAME, value=data["host"], context="host"))

    return IOCCollection(alert_id=alert_id, iocs=iocs)


class IOCExtractorTool(Tool):
    """smolagents Tool to extract indicators of compromise (IP, domain, hash, user, host) from alerts."""

    name = "extract_iocs"
    description = (
        "Extracts all Indicators of Compromise (IOCs) such as IPv4, IPv6, domains, file hashes, "
        "usernames, and hostnames from an alert payload or text description."
    )
    inputs = {
        "content": {
            "type": "string",
            "description": "The raw alert string, JSON payload, or description from which to extract IOCs.",
        },
        "alert_id": {
            "type": "string",
            "description": "Optional alert identifier to associate with the extracted IOC collection.",
            "nullable": True,
        },
    }
    output_type = "string"

    def forward(self, content: str, alert_id: str | None = None) -> str:
        aid = alert_id or "UNKNOWN"
        try:
            # Check if content is JSON
            parsed = json.loads(content)
            if isinstance(parsed, dict):
                collection = extract_iocs_from_dict(parsed, alert_id=aid)
            else:
                iocs = extract_iocs_from_text(content, context=f"alert_{aid}")
                collection = IOCCollection(alert_id=aid, iocs=iocs)
        except Exception:
            iocs = extract_iocs_from_text(content, context=f"alert_{aid}")
            collection = IOCCollection(alert_id=aid, iocs=iocs)

        summary = {
            "alert_id": collection.alert_id,
            "total_iocs": len(collection.iocs),
            "ips": [i.value for i in collection.ips],
            "domains": [i.value for i in collection.domains],
            "hashes": [i.value for i in collection.hashes],
            "users": [i.value for i in collection.users],
            "all_iocs": [{"type": i.ioc_type.value, "value": i.value, "context": i.context} for i in collection.iocs],
        }
        return json.dumps(summary, indent=2)
