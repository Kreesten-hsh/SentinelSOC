"""Log Store — interface d'accès aux logs normalisés.

Charge les scénarios JSONL et expose des méthodes de requête
imitant ce qu'un analyste SOC ferait dans un SIEM :
- filtrer par IP source/destination
- filtrer par utilisateur
- filtrer par host
- filtrer par fenêtre temporelle
- filtrer par source_type (firewall, auth, endpoint, IDS)
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

from src.models.alert import LogEvent, LogSourceType


class LogStore:
    """In-memory store for normalized log events.

    Loads JSONL scenario files and provides SOC-style query methods.
    Designed for the MVP — production would use Elasticsearch/Splunk.
    """

    def __init__(self, scenarios_dir: Path | str | None = None) -> None:
        self._events: list[LogEvent] = []
        if scenarios_dir is not None:
            self.load_scenarios(Path(scenarios_dir))

    @property
    def event_count(self) -> int:
        return len(self._events)

    @property
    def scenarios_loaded(self) -> set[str]:
        return {e.scenario_id for e in self._events if e.scenario_id}

    def load_scenarios(self, scenarios_dir: Path) -> None:
        """Charge tous les fichiers .jsonl du répertoire de scénarios."""
        if not scenarios_dir.is_dir():
            raise FileNotFoundError(f"Scenarios directory not found: {scenarios_dir}")

        for jsonl_file in sorted(scenarios_dir.glob("*.jsonl")):
            self._load_jsonl(jsonl_file)

    def load_scenario_file(self, filepath: Path) -> None:
        """Charge un seul fichier .jsonl de scénario."""
        self._load_jsonl(filepath)

    def _load_jsonl(self, filepath: Path) -> None:
        with filepath.open("r", encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if not stripped:
                    continue
                data = json.loads(stripped)
                event = LogEvent(**data)
                self._events.append(event)

    def add_event(self, event: LogEvent) -> None:
        self._events.append(event)

    # ──────────────── Query methods (SOC analyst patterns) ────────────────

    def query_by_src_ip(
        self,
        src_ip: str,
        source_type: LogSourceType | None = None,
        time_start: datetime | None = None,
        time_end: datetime | None = None,
    ) -> list[LogEvent]:
        """Tous les événements provenant d'une IP source donnée."""
        return self._filter(
            src_ip=src_ip,
            source_type=source_type,
            time_start=time_start,
            time_end=time_end,
        )

    def query_by_dest_ip(
        self,
        dest_ip: str,
        source_type: LogSourceType | None = None,
        time_start: datetime | None = None,
        time_end: datetime | None = None,
    ) -> list[LogEvent]:
        """Tous les événements ciblant une IP destination donnée."""
        return self._filter(
            dest_ip=dest_ip,
            source_type=source_type,
            time_start=time_start,
            time_end=time_end,
        )

    def query_by_user(
        self,
        user: str,
        source_type: LogSourceType | None = None,
        time_start: datetime | None = None,
        time_end: datetime | None = None,
    ) -> list[LogEvent]:
        """Événements d'authentification/activité pour un utilisateur."""
        return self._filter(
            user=user,
            source_type=source_type,
            time_start=time_start,
            time_end=time_end,
        )

    def query_by_host(
        self,
        host: str,
        source_type: LogSourceType | None = None,
        time_start: datetime | None = None,
        time_end: datetime | None = None,
    ) -> list[LogEvent]:
        """Activité sur une machine donnée (endpoint logs)."""
        return self._filter(
            host=host,
            source_type=source_type,
            time_start=time_start,
            time_end=time_end,
        )

    def query_firewall_logs(
        self,
        src_ip: str = "",
        dest_ip: str = "",
        time_start: datetime | None = None,
        time_end: datetime | None = None,
    ) -> list[LogEvent]:
        """Logs pare-feu pour une paire IP source/destination."""
        return self._filter(
            src_ip=src_ip or None,
            dest_ip=dest_ip or None,
            source_type=LogSourceType.FIREWALL,
            time_start=time_start,
            time_end=time_end,
        )

    def query_auth_logs(
        self,
        user: str = "",
        host: str = "",
        time_start: datetime | None = None,
        time_end: datetime | None = None,
    ) -> list[LogEvent]:
        """Logs d'authentification pour un utilisateur/host."""
        return self._filter(
            user=user or None,
            host=host or None,
            source_type=LogSourceType.AUTH,
            time_start=time_start,
            time_end=time_end,
        )

    def query_endpoint_logs(
        self,
        host: str = "",
        time_start: datetime | None = None,
        time_end: datetime | None = None,
    ) -> list[LogEvent]:
        """Logs endpoint (Sysmon, process creation) pour une machine."""
        return self._filter(
            host=host or None,
            source_type=LogSourceType.ENDPOINT,
            time_start=time_start,
            time_end=time_end,
        )

    def query_ids_logs(
        self,
        src_ip: str = "",
        dest_ip: str = "",
        time_start: datetime | None = None,
        time_end: datetime | None = None,
    ) -> list[LogEvent]:
        """Alertes IDS/IPS (Suricata) pour une paire IP."""
        return self._filter(
            src_ip=src_ip or None,
            dest_ip=dest_ip or None,
            source_type=LogSourceType.IDS,
            time_start=time_start,
            time_end=time_end,
        )

    def query_around_timestamp(
        self,
        timestamp: datetime,
        window_minutes: int = 5,
        source_type: LogSourceType | None = None,
    ) -> list[LogEvent]:
        """Événements dans une fenêtre temporelle autour d'un timestamp."""
        delta = timedelta(minutes=window_minutes)
        return self._filter(
            source_type=source_type,
            time_start=timestamp - delta,
            time_end=timestamp + delta,
        )

    def query_by_scenario(self, scenario_id: str) -> list[LogEvent]:
        """Tous les événements d'un scénario spécifique."""
        return sorted(
            [e for e in self._events if e.scenario_id == scenario_id],
            key=lambda e: e.timestamp,
        )

    # ──────────────── Internal filter engine ────────────────

    def _filter(
        self,
        src_ip: str | None = None,
        dest_ip: str | None = None,
        user: str | None = None,
        host: str | None = None,
        source_type: LogSourceType | None = None,
        time_start: datetime | None = None,
        time_end: datetime | None = None,
    ) -> list[LogEvent]:
        results: list[LogEvent] = []
        for event in self._events:
            if src_ip and event.src_ip != src_ip:
                continue
            if dest_ip and event.dest_ip != dest_ip:
                continue
            if user and event.user.lower() != user.lower():
                continue
            if host and event.host.lower() != host.lower():
                continue
            if source_type and event.source_type != source_type:
                continue
            if time_start and event.timestamp < time_start:
                continue
            if time_end and event.timestamp > time_end:
                continue
            results.append(event)
        return sorted(results, key=lambda e: e.timestamp)
