from app.redaction import redact_text


def test_redact_bearer_token() -> None:
    result = redact_text("Authorization: Bearer secret123")
    assert "secret123" not in result


def test_redact_key_value_secrets() -> None:
    result = redact_text("password=supersecret token: abc123 api_key=xyz789 session=foo")
    assert "supersecret" not in result
    assert "abc123" not in result
    assert "xyz789" not in result
    assert "foo" not in result
