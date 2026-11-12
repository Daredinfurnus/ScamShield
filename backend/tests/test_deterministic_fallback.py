
from app.services.ai.deterministic_fallback import DeterministicFallback


def test_explanation_preserves_risk_score():
    fallback = DeterministicFallback()

    result = fallback.explain(
        findings=[],
        risk_score=82.5,
        risk_band="critical",
    )

    assert result["risk_score"] == 82.5
    assert result["risk_band"] == "critical"
    assert result["provider"] == "deterministic"


def test_empty_findings_not_declared_safe():
    fallback = DeterministicFallback()

    result = fallback.explain([], 0, "low")

    assert "does not establish" in result["summary"]
    assert result["observations"] == []


def test_findings_are_preserved():
    fallback = DeterministicFallback()

    findings = [{
        "id": 12,
        "title": "Urgency indicator",
        "description": "Urgent payment request",
        "evidence_snippet": "Pay immediately",
        "evidence_source": "message_body",
    }]

    result = fallback.explain(findings, 75, "critical")

    assert result["observations"][0]["finding_id"] == 12
    assert result["observations"][0]["evidence_snippet"] == "Pay immediately"


def test_report_preserves_authoritative_score():
    fallback = DeterministicFallback()

    report = fallback.draft_report({
        "id": 7,
        "risk_score": 65,
        "risk_band": "high",
        "findings": [],
    })

    assert report["investigation_id"] == 7
    assert report["risk_score"] == 65
    assert report["risk_band"] == "high"
    assert report["fallback_used"] is True
