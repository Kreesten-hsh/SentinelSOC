"""Investigation report generator.

Transforms an InvestigationResult into a structured InvestigationReport
with executive summary, timeline, correlation narrative, scoring breakdown,
and full agent reasoning trace. Renders as Markdown via Jinja2.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

from src.models.alert import (
    Alert,
    InvestigationReport,
    InvestigationResult,
    RecommendedAction,
    Severity,
    Verdict,
)

# Report template location
TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
TEMPLATE_NAME = "investigation_report.md.j2"

# Icon mappings
VERDICT_ICONS: dict[str, str] = {
    "true_positive": "🔴",
    "false_positive": "🟢",
    "suspicious": "🟡",
}

SEVERITY_ICONS: dict[str, str] = {
    "critical": "🔴",
    "medium": "🟠",
    "low": "🟢",
}

ACTION_ICONS: dict[str, str] = {
    "contain": "🛑",
    "escalate": "⬆️",
    "monitor": "👁️",
    "ignore": "✅",
}

REPUTATION_ICONS: dict[str, str] = {
    "malicious": "🔴",
    "suspicious": "🟡",
    "clean": "🟢",
    "unknown": "⚪",
}

# Action recommendations per verdict/action combination
ACTION_RECOMMENDATIONS: dict[str, list[str]] = {
    "contain": [
        "Isoler immédiatement le(s) hôte(s) compromis du réseau",
        "Bloquer les adresses IP malveillantes identifiées au pare-feu périmétrique",
        "Réinitialiser les identifiants des comptes compromis",
        "Lancer une analyse forensique complète des systèmes affectés",
        "Notifier l'équipe de réponse aux incidents (CSIRT)",
    ],
    "escalate": [
        "Transmettre à un analyste SOC niveau 3 pour investigation approfondie",
        "Contacter le propriétaire du compte pour vérifier la légitimité de l'activité",
        "Renforcer la surveillance sur les hôtes impliqués pendant 72h",
        "Documenter les observations pour le rapport d'incident",
    ],
    "monitor": [
        "Ajouter les IOCs identifiés aux watchlists de surveillance",
        "Programmer une revue dans 24h si l'activité persiste",
        "Vérifier les logs des 7 derniers jours pour un historique similaire",
    ],
    "ignore": [
        "Clôturer l'alerte comme faux positif documenté",
        "Envisager un tuning de la règle de détection pour réduire le bruit",
    ],
}


class ReportGenerator:
    """Generates structured investigation reports from InvestigationResult."""

    def __init__(self) -> None:
        self._env = Environment(
            loader=FileSystemLoader(str(TEMPLATE_DIR)),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def generate(self, alert: Alert, result: InvestigationResult) -> InvestigationReport:
        """Build a complete InvestigationReport from alert and investigation result."""
        now = datetime.now(UTC)

        # Extract verdict/severity values
        verdict_val = result.verdict.value if result.verdict else "unknown"
        action_val = result.recommended_action.value if result.recommended_action else "monitor"
        severity_val = result.severity_score.severity.value if result.severity_score else "medium"
        severity_score = result.severity_score.final_score if result.severity_score else 0.0

        # Build executive summary
        executive_summary = self._build_executive_summary(
            alert=alert,
            verdict=verdict_val,
            action=action_val,
            severity=severity_val,
            score=severity_score,
            patterns=[c.pattern for c in result.correlations],
            malicious_iocs=[t.ioc_value for t in result.threat_intel if t.reputation == "malicious"],
        )

        # Build IOC list
        iocs_extracted = [
            {"type": ioc.ioc_type.value, "value": ioc.value, "context": ioc.context}
            for ioc in result.iocs.iocs
        ]

        # Build timeline
        timeline = [
            {
                "timestamp": e.timestamp.strftime("%H:%M:%S"),
                "source": e.source_type.value,
                "action": e.action,
                "entity": f"{e.src_ip}→{e.dest_ip}" if e.src_ip and e.dest_ip else e.user or e.host,
            }
            for e in sorted(result.log_events, key=lambda e: e.timestamp)[:30]  # Cap at 30 events for readability
        ]

        # Correlation narrative
        correlation_narrative = self._build_correlation_narrative(result)

        # Threat intel formatted
        ti_results = [
            {
                "ioc": t.ioc_value,
                "reputation": t.reputation,
                "reputation_icon": REPUTATION_ICONS.get(t.reputation, "⚪"),
                "confidence": f"{t.confidence:.0%}",
                "tags": ", ".join(t.tags) if t.tags else "—",
                "source": t.source,
            }
            for t in result.threat_intel
        ]

        # Scoring details
        rules_triggered_formatted: list[dict[str, str]] = []
        if result.severity_score:
            from src.scoring.rule_engine import RULES_BY_NAME

            for rule_name in result.severity_score.rules_triggered:
                rule_def = RULES_BY_NAME.get(rule_name)
                weight_val = rule_def.weight if rule_def else 0.0
                desc_val = rule_def.description if rule_def else rule_name
                weight_str = f"+{weight_val:.0f}" if weight_val > 0 else f"{weight_val:.0f}"
                rules_triggered_formatted.append({
                    "name": rule_name,
                    "weight": weight_str,
                    "evidence": desc_val,
                    "icon": "✅" if weight_val > 0 else "🔽",
                })

        # Patterns detected
        patterns_detected = [
            {"pattern": c.pattern, "severity": "high", "description": c.description}
            for c in result.correlations
        ]

        # Agent reasoning
        agent_reasoning = [
            {
                "number": s.step_number,
                "action": s.action,
                "tool": s.tool_used,
                "reasoning": s.reasoning,
                "result": s.result_summary,
            }
            for s in result.steps
        ]

        # Action items
        action_items = ACTION_RECOMMENDATIONS.get(action_val, ["Aucune action requise"])

        # Severity assessment dict
        severity_assessment: dict[str, Any] = {
            "severity": severity_val,
            "score": round(severity_score, 1),
        }
        if result.severity_score:
            severity_assessment["rule_score"] = round(result.severity_score.rule_score, 1)
            severity_assessment["ml_confidence"] = round(result.severity_score.ml_confidence, 4)
            severity_assessment["explanation"] = result.severity_score.explanation

        # Render markdown
        template = self._env.get_template(TEMPLATE_NAME)
        markdown = template.render(
            alert_id=alert.id,
            alert_timestamp=alert.timestamp.isoformat(),
            alert_source=alert.source,
            alert_title=alert.title,
            generated_at=now.strftime("%Y-%m-%d %H:%M:%S UTC"),
            executive_summary=executive_summary,
            verdict=verdict_val.upper().replace("_", " "),
            verdict_icon=VERDICT_ICONS.get(verdict_val, "⚪"),
            severity=severity_val.upper(),
            severity_icon=SEVERITY_ICONS.get(severity_val, "⚪"),
            severity_score=round(severity_score, 1),
            recommended_action=action_val.upper(),
            action_icon=ACTION_ICONS.get(action_val, "❓"),
            iocs_extracted=iocs_extracted,
            timeline=timeline,
            correlation_narrative=correlation_narrative,
            patterns_detected=patterns_detected,
            threat_intel_results=ti_results,
            rule_score=round(result.severity_score.rule_score, 1) if result.severity_score else 0,
            ml_confidence=f"{result.severity_score.ml_confidence:.2%}" if result.severity_score else "N/A",
            rules_triggered=rules_triggered_formatted,
            ml_top_features=result.severity_score.ml_features_importance if result.severity_score else {},
            action_items=action_items,
            agent_reasoning=agent_reasoning,
        )

        return InvestigationReport(
            alert_id=alert.id,
            title=f"Investigation Report — {alert.title}",
            executive_summary=executive_summary,
            alert_info={
                "id": alert.id,
                "timestamp": alert.timestamp.isoformat(),
                "source": alert.source,
                "title": alert.title,
            },
            iocs_extracted=iocs_extracted,
            timeline=[
                {"timestamp": t["timestamp"], "source": t["source"], "action": t["action"]}
                for t in timeline
            ],
            correlation_narrative=correlation_narrative,
            threat_intel_results=[
                {"ioc": t["ioc"], "reputation": t["reputation"], "confidence": t["confidence"]}
                for t in ti_results
            ],
            severity_assessment=severity_assessment,
            verdict=verdict_val,
            recommended_action=action_val,
            action_items=action_items,
            agent_reasoning=[
                {"step": str(s["number"]), "action": s["action"], "result": s["result"]}
                for s in agent_reasoning
            ],
            generated_at=now,
            markdown=markdown,
        )

    @staticmethod
    def _build_executive_summary(
        alert: Alert,
        verdict: str,
        action: str,
        severity: str,
        score: float,
        patterns: list[str],
        malicious_iocs: list[str],
    ) -> str:
        """Generate a concise executive summary paragraph."""
        parts: list[str] = []

        if verdict == "true_positive":
            parts.append(
                f"L'investigation de l'alerte **{alert.title}** a confirmé une menace réelle "
                f"(sévérité **{severity.upper()}**, score {score:.0f}/100)."
            )
            if patterns:
                parts.append(
                    f"Les patterns d'attaque identifiés incluent : {', '.join(patterns)}."
                )
            if malicious_iocs:
                parts.append(
                    f"Les indicateurs malveillants confirmés : {', '.join(f'`{i}`' for i in malicious_iocs)}."
                )
            parts.append(f"**Action immédiate requise : {action.upper()}.**")

        elif verdict == "suspicious":
            parts.append(
                f"L'alerte **{alert.title}** présente une activité ambiguë "
                f"(sévérité **{severity.upper()}**, score {score:.0f}/100) "
                f"nécessitant une investigation complémentaire."
            )
            if patterns:
                parts.append(f"Patterns détectés : {', '.join(patterns)}.")
            parts.append(f"**Action recommandée : {action.upper()}.**")

        else:  # false_positive
            parts.append(
                f"L'investigation de l'alerte **{alert.title}** conclut à un **faux positif** "
                f"(sévérité **{severity.upper()}**, score {score:.0f}/100)."
            )
            parts.append(
                "L'activité observée correspond à un comportement légitime sans indicateur de compromission."
            )
            parts.append(f"**Aucune action corrective nécessaire.** L'alerte peut être clôturée.")

        return " ".join(parts)

    @staticmethod
    def _build_correlation_narrative(result: InvestigationResult) -> str:
        """Build a human-readable narrative of event correlations."""
        if not result.correlations:
            return "Aucune corrélation cross-source significative identifiée."

        parts = [
            f"L'analyse croisée des {len(result.log_events)} événements télémétriques "
            f"a identifié **{len(result.correlations)} pattern(s)** de corrélation :"
        ]
        for c in result.correlations:
            parts.append(f"\n- **{c.pattern}** (confiance {c.confidence:.0%}) : {c.description}")

        return "\n".join(parts)
