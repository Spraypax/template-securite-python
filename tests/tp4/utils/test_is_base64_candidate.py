import tp4.main as main


def test_is_base64_candidate_true_for_sos():
    assert main.is_base64_candidate("c29zYWFh") is True
