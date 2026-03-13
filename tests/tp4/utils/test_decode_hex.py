import tp4.main as main


def test_decode_hex_sos():
    assert main.decode_hex("736f73") == "sos"
