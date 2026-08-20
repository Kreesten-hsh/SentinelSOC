"""Tool for querying Threat Intelligence databases (Local Known IOCs + Optional Live API)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import httpx
from smolagents import Tool

from src.models.alert import IOCType, ThreatIntelResult


class ThreatIntelTool(Tool):
    """smolagents Tool to check the reputation of IPs, domains, and file hashes."""

    name = "lookup_threat_intel"
    description = (
        "Queries threat intelligence sources for a given IP address, domain, or file hash. "
        "Returns reputation score, known malicious tags, associated campaigns, and confidence."
    )
    inputs = {
        "ioc_value": {
            "type": "string",
            "description": "The IP address, domain name, or file hash (MD5, SHA1, SHA256) to query.",
        },
        "ioc_type": {
            "type": "string",
            "description": "Type of indicator: 'ipv4', 'ipv6', 'domain', 'sha256', 'md5', or 'sha1'. Optional (auto-detected if omitted).",
            "nullable": True,
        },
    }
    output_type = "string"

    def __init__(self, threat_intel_file: Path | str | None = None) -> None:
        super().__init__()
        if threat_intel_file is not None:
            self.ti_path = Path(threat_intel_file)
        else:
            self.ti_path = Path(__file__).resolve().parent.parent.parent / "data" / "threat_intel" / "known_iocs.json"

        self._local_db: dict[str, Any] = {}
        self._load_local_db()

    def _load_local_db(self) -> None:
        if self.ti_path.is_file():
            with self.ti_path.open("r", encoding="utf-8") as fh:
                self._local_db = json.load(fh)
        else:
            self._local_db = {"malicious_ips": {}, "malicious_hashes": {}, "malicious_domains": {}, "clean_ips": {}}

    def _query_local(self, ioc: str) -> ThreatIntelResult | None:
        val = ioc.strip()

        # Check malicious IPs
        mal_ips = self._local_db.get("malicious_ips", {})
        if val in mal_ips:
            data = mal_ips[val]
            return ThreatIntelResult(
                ioc_value=val,
                ioc_type=IOCType.IPV4,
                reputation=data.get("reputation", "malicious"),
                confidence=float(data.get("confidence", 0.9)),
                tags=data.get("tags", []),
                source="local_known_iocs",
                raw_response=data,
            )

        # Check clean IPs
        clean_ips = self._local_db.get("clean_ips", {})
        if val in clean_ips:
            data = clean_ips[val]
            return ThreatIntelResult(
                ioc_value=val,
                ioc_type=IOCType.IPV4,
                reputation="clean",
                confidence=float(data.get("confidence", 0.99)),
                tags=data.get("tags", ["internal"]),
                source="local_known_iocs",
                raw_response=data,
            )

        # Check malicious Hashes
        mal_hashes = self._local_db.get("malicious_hashes", {})
        if val.lower() in mal_hashes:
            data = mal_hashes[val.lower()]
            return ThreatIntelResult(
                ioc_value=val,
                ioc_type=IOCType.SHA256 if len(val) == 64 else IOCType.MD5,
                reputation=data.get("reputation", "malicious"),
                confidence=float(data.get("confidence", 0.95)),
                tags=data.get("tags", []),
                source="local_known_iocs",
                raw_response=data,
            )

        # Check malicious Domains
        mal_domains = self._local_db.get("malicious_domains", {})
        if val.lower() in mal_domains:
            data = mal_domains[val.lower()]
            return ThreatIntelResult(
                ioc_value=val,
                ioc_type=IOCType.DOMAIN,
                reputation=data.get("reputation", "malicious"),
                confidence=float(data.get("confidence", 0.88)),
                tags=data.get("tags", []),
                source="local_known_iocs",
                raw_response=data,
            )

        return None

    def _query_abuseipdb(self, ip_address: str, api_key: str) -> ThreatIntelResult | None:
        """Optional online check with AbuseIPDB."""
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            params = {"ipAddress": ip_address, "maxAgeInDays": "90"}
            headers = {"Accept": "application/json", "Key": api_key}
            resp = httpx.get(url, params=params, headers=headers, timeout=5.0)
            if resp.status_code == 200:
                body = resp.json().get("data", {})
                abuse_score = body.get("abuseConfidenceScore", 0) / 100.0
                rep = "malicious" if abuse_score > 0.5 else "suspicious" if abuse_score > 0.2 else "clean"
                return ThreatIntelResult(
                    ioc_value=ip_address,
                    ioc_type=IOCType.IPV4,
                    reputation=rep,
                    confidence=abuse_score,
                    tags=["abuseipdb_report"],
                    source="abuseipdb_api",
                    raw_response=body,
                )
        except Exception:
            return None
        return None

    def forward(self, ioc_value: str, ioc_type: str | None = None) -> str:
        ioc = ioc_value.strip()

        # 1. Local database lookup
        local_res = self._query_local(ioc)
        if local_res:
            return json.dumps({
                "ioc": local_res.ioc_value,
                "reputation": local_res.reputation,
                "confidence": local_res.confidence,
                "tags": local_res.tags,
                "source": local_res.source,
                "details": local_res.raw_response,
            }, indent=2)

        # 2. Live API lookup if API key configured and it looks like an IP
        api_key = os.getenv("ABUSEIPDB_API_KEY")
        if api_key and (ioc_type == "ipv4" or "." in ioc):
            online_res = self._query_abuseipdb(ioc, api_key)
            if online_res:
                return json.dumps({
                    "ioc": online_res.ioc_value,
                    "reputation": online_res.reputation,
                    "confidence": online_res.confidence,
                    "tags": online_res.tags,
                    "source": online_res.source,
                    "details": online_res.raw_response,
                }, indent=2)

        # 3. Default unknown response
        return json.dumps({
            "ioc": ioc,
            "reputation": "unknown",
            "confidence": 0.0,
            "tags": [],
            "source": "none",
            "message": "Indicator not present in local threat intelligence feeds or known blocklists.",
        }, indent=2)
