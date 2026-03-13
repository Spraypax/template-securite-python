import tp4.main as main


def test_decode_morse_sos():
    assert main.decode_morse("... --- ...") == "sos"
