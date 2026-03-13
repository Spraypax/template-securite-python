import tp4.main as main


def test_smart_decode_morse():
    assert main.smart_decode("... --- ...") == "sos"


def test_smart_decode_hex():
    assert main.smart_decode("736f73") == "sos"


def test_smart_decode_base64():
    assert main.smart_decode("aGVsbG8h") == "hello!"
