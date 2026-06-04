from app.probes.waf import detect_waf_signals


def test_detect_waf_signals_finds_known_markers() -> None:
    headers = {"CF-Ray": "abc123", "X-Other": "value"}

    assert detect_waf_signals(headers) == ["cf-ray"]
