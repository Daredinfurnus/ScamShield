from app.services.text_analysis import TextAnalyzer


def test_text_analyzer_returns_baseline():
    analyzer = TextAnalyzer()
    result = analyzer.analyze("hello world")
    assert "score" in result
    assert "label" in result
    assert "evidence" in result
    assert "source" in result
    assert result["score"] == 0.0
    assert "not yet trained" in result.get("note", "")


def test_text_analyzer_empty_input():
    analyzer = TextAnalyzer()
    result = analyzer.analyze("")
    assert result["score"] == 0.0