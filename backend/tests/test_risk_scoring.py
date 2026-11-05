from app.services.risk_scoring import RiskScorer


def test_risk_bands():
    scorer = RiskScorer()
    assert scorer.score([{"score": 90}])["risk_band"] == "critical"
    assert scorer.score([{"score": 60}])["risk_band"] == "high"
    assert scorer.score([{"score": 30}])["risk_band"] == "medium"
    assert scorer.score([{"score": 10}])["risk_band"] == "low"


def test_risk_score_clamped_to_100():
    scorer = RiskScorer()
    result = scorer.score([{"score": 200}])
    assert result["risk_score"] == 100.0


def test_risk_score_clamps_at_zero():
    scorer = RiskScorer()
    result = scorer.score([{"score": -50}])
    assert result["risk_score"] == 0.0


def test_empty_signals_yields_low():
    scorer = RiskScorer()
    result = scorer.score([])
    assert result["risk_score"] == 0.0
    assert result["risk_band"] == "low"