from app.redaction import redact_text


def test_redact_bearer_token() -> None:
    result = redact_text("Authorization: Bearer secret123")
    assert "secret123" not in result

