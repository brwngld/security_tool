from app.web.security import hash_password, sign_session, verify_password, verify_session


def test_password_hash_round_trip_does_not_store_plaintext() -> None:
    password_hash = hash_password("correct horse battery staple")

    assert "correct horse" not in password_hash
    assert verify_password("correct horse battery staple", password_hash) is True
    assert verify_password("wrong password", password_hash) is False


def test_signed_session_round_trip_and_wrong_secret_rejection() -> None:
    token = sign_session(42, "secret-one")

    assert verify_session(token, "secret-one") == 42
    assert verify_session(token, "secret-two") is None
