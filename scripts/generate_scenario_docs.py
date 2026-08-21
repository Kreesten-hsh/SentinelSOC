"""Export formatted scenario walkthroughs to docs/scenarios/."""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.agent.sentinel_agent import SentinelInvestigationAgent
from src.data.log_store import LogStore
from src.models.alert import Alert


def main() -> None:
    log_store = LogStore(PROJECT_ROOT / "data" / "scenarios")
    agent = SentinelInvestigationAgent(
        log_store=log_store,
        threat_intel_path=PROJECT_ROOT / "data" / "threat_intel" / "known_iocs.json",
        use_llm=False,
    )

    with (PROJECT_ROOT / "data" / "scenarios" / "ground_truth.json").open("r") as fh:
        gt_data = json.load(fh)["scenarios"]

    with (PROJECT_ROOT / "data" / "alerts" / "sample_alerts.json").open("r") as fh:
        alerts = [Alert.model_validate(a) for a in json.load(fh)]

    docs_dir = PROJECT_ROOT / "docs" / "scenarios"
    docs_dir.mkdir(parents=True, exist_ok=True)

    for alert in alerts:
        res = agent.investigate(alert)
        gt = gt_data.get(alert.scenario_id, {})

        content = f"""# Scénario {alert.id} : {alert.title}

**Scénario de référence** : `{alert.scenario_id}`  
**Source SIEM** : `{alert.source}`  
**Horodatage alerte** : `{alert.timestamp.isoformat()}`

---

## 1. Alerte Brute (Ingestion SIEM)

```json
{json.dumps(alert.raw_data, indent=2)}
```

---

## 2. Vérité Terrain (Ground Truth Baseline)

- **Verdict Attendu** : `{gt.get('expected_verdict', '').upper()}`
- **Sévérité Attendue** : `{gt.get('expected_severity', '').upper()}`
- **Action Recommandée** : `{gt.get('recommended_action', '').upper()}`
- **Chaîne d'attaque documentée** :
{chr(10).join(f"  - {step}" for step in gt.get('attack_chain', []))}
- **Justification experte** :
  > {gt.get('justification', '')}

---

## 3. Déroulement de l'Investigation Autonome (Agent SentinelSOC)

L'agent a exécuté sa chaîne de raisonnement en 7 étapes causales strictes :

"""
        for step in res.steps:
            content += f"""### Étape {step.step_number} : {step.action}
- **Tool mobilisé** : `{step.tool_used}`
- **Raisonnement** : {step.reasoning}
- **Requête / Entrées** : `{step.query}`
- **Résultat intermédiaire** : {step.result_summary}

"""

        content += f"""---

## 4. Évaluation & Alignement Final

| Métrique | Vérité Terrain | Verdict Agent | Statut |
|---|---|---|---|
| **Verdict** | `{gt.get('expected_verdict', '').upper()}` | `{res.verdict.value.upper() if res.verdict else 'N/A'}` | {'✅ Conforme' if res.verdict and res.verdict.value == gt.get('expected_verdict') else '❌ Non conforme'} |
| **Sévérité** | `{gt.get('expected_severity', '').upper()}` | `{res.severity_score.severity.value.upper() if res.severity_score else 'N/A'}` | {'✅ Conforme' if res.severity_score and res.severity_score.severity.value == gt.get('expected_severity') else '❌ Non conforme'} |
| **Action** | `{gt.get('recommended_action', '').upper()}` | `{res.recommended_action.value.upper() if res.recommended_action else 'N/A'}` | {'✅ Conforme' if res.recommended_action and res.recommended_action.value == gt.get('recommended_action') else '❌ Non conforme'} |
| **Score combiné** | — | `{res.severity_score.final_score:.1f}/100` (Règles: `{res.severity_score.rule_score:.1f}`, ML: `{res.severity_score.ml_confidence:.2f}`) | Calibré |

### Explication du Score de Sévérité
```
{res.severity_score.explanation if res.severity_score else 'N/A'}
```
"""
        filename = f"{alert.scenario_id}.md"
        (docs_dir / filename).write_text(content, encoding="utf-8")
        print(f"Generated doc for {alert.id} -> {filename}")


if __name__ == "__main__":
    main()
