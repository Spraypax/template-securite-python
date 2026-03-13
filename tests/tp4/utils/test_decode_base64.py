import tp4.main as main


def test_decode_base64_sos():
    assert main.decode_base64("c29z") == "sos"
