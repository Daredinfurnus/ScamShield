
from typing import Any


class DeterministicFallback:
    """Evidence-based responses when the AI provider is unavailable."""

    def explain(
        self,
        findings: list[dict[str, Any]],
        risk_score: float,
        risk_band: str,
    ) -> dict[str, Any]:
        observations = []

        for finding in findings:
            title = finding.get("title") or finding.get("finding_type")
            description = finding.get("description")

            if title or description:
                observations.append({
                    "finding_id": finding.get("id"),
                    "title": title or "Detected finding",
                    "description": description or "",
                    "evidence_snippet": finding.get("evidence_snippet", ""),
                    "evidence_source": finding.get("evidence_source", ""),
                })

        if observations:
            summary = (
                f"The investigation contains {len(observations)} "
                "detected finding(s). Review the evidence below."
            )
            limitation = (
                "These findings are indicators, not proof of criminal activity."
            )
        else:
            summary = (
                "No findings were supplied for this investigation. "
                "This does not establish that the submitted content is safe."
            )
            limitation = "Insufficient findings are available for further interpretation."

        return {
            "summary": summary,
            "observations": observations,
            "recommendations": [
                "Review the original evidence before taking action.",
                "Verify suspicious requests through an independent channel.",
            ] if observations else [
                "Do not treat the absence of findings as proof of safety."
            ],
            "limitations": [limitation],
            "risk_score": risk_score,
            "risk_band": risk_band,
            "provider": "deterministic",
            "fallback_used": True,
        }

    def draft_report(
        self,
        investigation_data: dict[str, Any],
    ) -> dict[str, Any]:
        findings = investigation_data.get("findings", [])
        risk_score = investigation_data.get("risk_score")
        risk_band = investigation_data.get("risk_band")

        explanation = self.explain(
            findings=findings,
            risk_score=risk_score,
            risk_band=risk_band,
        )

        return {
            "investigation_id": investigation_data.get("id"),
            "risk_score": risk_score,
            "risk_band": risk_band,
            "findings": explanation["observations"],
            "summary": explanation["summary"],
            "recommendations": explanation["recommendations"],
            "limitations": explanation["limitations"],
            "provider": "deterministic",
            "fallback_used": True,
        }
