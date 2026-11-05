
import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import httpx
import openai
import pytest

from app.config import settings
from app.services.ai.openai_provider import OpenAIProvider


def mock_response(data):
    return SimpleNamespace(
        choices=[
            SimpleNamespace(
                message=SimpleNamespace(
                    content=json.dumps(data)
                )
            )
        ]
    )


def mock_client(data):
    client = MagicMock()
    client.chat.completions.create.return_value = mock_response(data)
    return client


def test_provider_name():
    provider = OpenAIProvider()
    assert provider.name == "openai"


def test_missing_api_key(monkeypatch):
    monkeypatch.setattr(settings, "OPENAI_API_KEY", None)

    provider = OpenAIProvider()

    assert provider.is_available is False


def test_provider_available(monkeypatch):
    monkeypatch.setattr(settings, "OPENAI_API_KEY", "test-key")

    provider = OpenAIProvider()

    assert provider.is_available is True


def test_successful_explanation(monkeypatch):
    monkeypatch.setattr(settings, "OPENAI_API_KEY", "test-key")

    provider = OpenAIProvider()
    client = mock_client({
        "summary": "Suspicious activity detected.",
        "observations": ["Urgent payment request"],
        "recommendations": ["Verify the sender"],
        "limitations": [],
    })

    monkeypatch.setattr(provider, "_get_client", lambda: client)

    result = provider.explain(
        investigation_id=1,
        findings=[{"type": "urgency", "description": "Urgent payment"}],
        risk_score=85,
    )

    assert result["success"] is True
    assert result["provider"] == "openai"
    assert result["data"]["summary"] == "Suspicious activity detected."

    sent_data = client.chat.completions.create.call_args.kwargs["messages"][1]["content"]
    assert '"risk_score": 85' in sent_data


def test_successful_report(monkeypatch):
    monkeypatch.setattr(settings, "OPENAI_API_KEY", "test-key")

    provider = OpenAIProvider()
    client = mock_client({
        "title": "Investigation Report",
        "executive_summary": "Suspicious message identified.",
        "findings_summary": ["Urgent payment request"],
        "recommendations": ["Verify sender identity"],
        "limitations": [],
    })

    monkeypatch.setattr(provider, "_get_client", lambda: client)

    result = provider.draft_report(
        1,
        {"message": "Send money immediately"},
    )

    assert result["success"] is True
    assert result["data"]["title"] == "Investigation Report"


def test_chat_requires_evidence():
    provider = OpenAIProvider()

    result = provider.chat(1, "Why is this suspicious?")

    assert result["success"] is False
    assert result["error"] == "investigation_evidence_required"


def test_empty_response(monkeypatch):
    monkeypatch.setattr(settings, "OPENAI_API_KEY", "test-key")

    provider = OpenAIProvider()
    client = MagicMock()
    client.chat.completions.create.return_value = SimpleNamespace(
        choices=[
            SimpleNamespace(
                message=SimpleNamespace(content=None)
            )
        ]
    )

    monkeypatch.setattr(provider, "_get_client", lambda: client)

    result = provider.explain(1, [], 20)

    assert result["success"] is False
    assert result["error"] == "empty_response"


def test_malformed_json(monkeypatch):
    monkeypatch.setattr(settings, "OPENAI_API_KEY", "test-key")

    provider = OpenAIProvider()
    client = MagicMock()
    client.chat.completions.create.return_value = SimpleNamespace(
        choices=[
            SimpleNamespace(
                message=SimpleNamespace(content="not valid json")
            )
        ]
    )

    monkeypatch.setattr(provider, "_get_client", lambda: client)

    result = provider.explain(1, [], 20)

    assert result["success"] is False
    assert result["error"] == "invalid_response"


def test_timeout_handling(monkeypatch):
    monkeypatch.setattr(settings, "OPENAI_API_KEY", "test-key")

    provider = OpenAIProvider()

    def timeout():
        raise openai.APITimeoutError(
            request=httpx.Request("POST", "https://api.openai.com/v1/chat/completions")
        )

    monkeypatch.setattr(provider, "_get_client", timeout)

    result = provider.explain(1, [], 20)

    assert result["success"] is False
    assert result["error"] == "timeout"


def test_authentication_failure(monkeypatch):
    monkeypatch.setattr(settings, "OPENAI_API_KEY", "test-key")

    provider = OpenAIProvider()

    def auth_error():
        request = httpx.Request("POST", "https://api.openai.com/v1/chat/completions")
        response = httpx.Response(401, request=request)
        raise openai.AuthenticationError(
            message="Authentication failed",
            response=response,
            body=None,
        )

    monkeypatch.setattr(provider, "_get_client", auth_error)

    result = provider.explain(1, [], 20)

    assert result["success"] is False
    assert result["error"] == "authentication_failed"


def test_rate_limit_handling(monkeypatch):
    monkeypatch.setattr(settings, "OPENAI_API_KEY", "test-key")

    provider = OpenAIProvider()

    def rate_limit():
        request = httpx.Request("POST", "https://api.openai.com/v1/chat/completions")
        response = httpx.Response(429, request=request)
        raise openai.RateLimitError(
            message="Rate limit reached",
            response=response,
            body=None,
        )

    monkeypatch.setattr(provider, "_get_client", rate_limit)

    result = provider.explain(1, [], 20)

    assert result["success"] is False
    assert result["error"] == "rate_limited"


def test_risk_score_is_not_returned_as_modified(monkeypatch):
    monkeypatch.setattr(settings, "OPENAI_API_KEY", "test-key")

    provider = OpenAIProvider()
    client = mock_client({
        "summary": "Evidence indicates possible fraud.",
        "observations": [],
        "recommendations": [],
        "limitations": [],
    })

    monkeypatch.setattr(provider, "_get_client", lambda: client)

    original_score = 92

    result = provider.explain(1, [], original_score)

    assert result["success"] is True
    assert "risk_score" not in result["data"]

    sent_data = client.chat.completions.create.call_args.kwargs["messages"][1]["content"]
    assert '"risk_score": 92' in sent_data
