"""
Tests unitaires pour Session (TP3).
Toutes les interactions réseau sont mockées.
"""

import os
from unittest.mock import MagicMock, patch

from src.tp3.utils.session import (
    Session,
    _CAPTCHA_ERROR_PATTERNS,
    _ERROR_PATTERNS,
    _FLAG_PATTERNS,
    _WRONG_FLAG_PATTERNS,
    _extract_visible_message,
    _is_help_text,
    _looks_like_captcha3_wrong_flag,
    _looks_like_trackflaw_wrong_flag,
    _magic_word_header_value,
    _needs_magic_word_header,
    _needs_code_alias,
    _needs_trackflaw_user_agent,
    _normalize_flag_match,
    _uses_empty_captcha_bypass,
    _uses_no_captcha_bypass,
)


_SAMPLE_HTML = """
<form action="http://31.220.95.27:9002/captcha1/check" method="POST">
    <input type="hidden" name="flag" value="secret_token_xyz">
    <input type="text" name="captcha" value="">
    <img src="/captcha_img.png" alt="captcha">
</form>
"""

_SAMPLE_HTML_ANSWER_FIELD = """
<form action="http://31.220.95.27:9002/captcha1/check" method="POST">
    <input type="hidden" name="flag" value="secret_token_xyz">
    <input type="text" name="answer" value="">
    <img src="/captcha_img.png" alt="captcha">
</form>
"""

_SUCCESS_HTML = """
<html><body>
<p>Bravo ! Voici votre flag : FLAG{tp3_success_42}</p>
</body></html>
"""

_FAILURE_HTML = """
<html><body>
<p>Captcha incorrect, veuillez réessayer.</p>
</body></html>
"""

_WRONG_FLAG_HTML = """
<html><body>
<p class="alert-danger col-md-2">Incorrect flag.</p>
</body></html>
"""

_CAPTCHA3_WRONG_FLAG_HTML = """
<html><body>
<form></form>
<!-- Ok --></div>
</body></html>
"""

_INVALID_CAPTCHA_HTML = """
<html><body>
<p class="alert-danger col-md-2">Invalid captcha</p>
</body></html>
"""

_AMBIGUOUS_SUCCESS_HTML = """
<html><body>
<p class="alert-info col-md-2">Well done, challenge solved</p>
</body></html>
"""

_HELP_ONLY_HTML = """
<html><body>
<p class="lead">Flag is an integer between 2000 and 3000.</p>
</body></html>
"""

_SAMPLE_HTML_NO_CAPTCHA = """
<form action="http://31.220.95.27:9002/captcha4/" method="POST">
    <input type="text" name="flag" value="">
    <input type="submit" name="submit">
</form>
"""

_SPACED_FLAG_HTML = """
<html><body>
<p>Wonderful ! F L A G - 2 {4_l1ttl3_h4rder} </p>
</body></html>
"""

_CAPTCHA3_SUCCESS_HTML = """
<html><body>
<div>Congratz ! FL A  G -3 { N0_t1m3_to_Sl33p}</div>
</body></html>
"""

_CAPTCHA5_SUCCESS_HTML = """
<html><body>
<p class="alert-danger col-md-2">Incorrect flag (huh 0_o?). F L AG - 5 {Th3_l4st_0n3}</p>
</body></html>
"""


# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------

def test_session_init():
    url = "http://example.com/captcha"
    session = Session(url)
    assert session.url == url
    assert session.captcha_value == ""
    assert session.flag_value == ""
    assert session.valid_flag == ""


# ---------------------------------------------------------------------------
# prepare_request()
# ---------------------------------------------------------------------------

def _make_mock_http(html: str = _SAMPLE_HTML) -> MagicMock:
    mock = MagicMock()
    mock.get.return_value.status_code = 200
    mock.get.return_value.text = html
    mock.get.return_value.headers = {"Content-Type": "image/png"}
    mock.get.return_value.content = b"\x89PNG\r\n\x1a\nfake"
    mock.get.return_value.raise_for_status = MagicMock()
    mock.cookies = {}
    return mock


@patch.dict(os.environ, {"CAPTCHA_MODE": "mock", "MOCK_CAPTCHA_VALUE": "mock_answer"})
def test_prepare_request_sets_fields():
    """prepare_request() remplit captcha_value, flag_value et form_fields."""
    session = Session("http://example.com/captcha1/")
    session._http = _make_mock_http()
    session.prepare_request()
    assert session.captcha_value == "mock_answer"
    assert session.flag_value == "secret_token_xyz"
    assert session._form_fields.get("flag") == "secret_token_xyz"
    assert "captcha" not in session._form_fields


@patch.dict(os.environ, {"CAPTCHA_MODE": "mock", "MOCK_CAPTCHA_VALUE": "mock_answer"})
def test_prepare_request_detects_captcha_field_name():
    """prepare_request() détecte le nom réel du champ captcha."""
    session = Session("http://example.com/captcha1/")
    session._http = _make_mock_http(_SAMPLE_HTML_ANSWER_FIELD)
    session.prepare_request()
    # FIX: le champ s'appelle "answer" dans ce formulaire
    assert session._captcha_field_name == "answer"


@patch.dict(os.environ, {"CAPTCHA_MODE": "mock", "MOCK_CAPTCHA_VALUE": "mock_answer"})
def test_prepare_request_reuses_form_and_refreshes_only_captcha():
    session = Session("http://example.com/captcha1/")
    session._http = _make_mock_http()

    session.prepare_request()
    session.prepare_request()

    called_urls = [call.args[0] for call in session._http.get.call_args_list]
    assert called_urls.count("http://example.com/captcha1/") == 1
    assert called_urls.count("http://example.com/captcha_img.png") == 2


@patch.dict(os.environ, {"CAPTCHA_MODE": "mock", "MOCK_CAPTCHA_VALUE": "mock_answer"})
def test_prepare_request_no_http(monkeypatch):
    """Sans réseau réel, la session se prépare sans planter."""
    session = Session("http://example.com/captcha")
    with patch("requests.Session.get", side_effect=Exception("no network")):
        try:
            session.prepare_request()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# submit_request()
# ---------------------------------------------------------------------------

@patch.dict(os.environ, {"CAPTCHA_MODE": "mock", "MOCK_CAPTCHA_VALUE": "mock_answer"})
def test_submit_request_posts_correct_data():
    """submit_request() envoie bien le captcha et le token caché."""
    session = Session("http://example.com/captcha1/", flag_value="1337")
    session._http = _make_mock_http()
    session.prepare_request()

    post_mock = MagicMock()
    post_mock.status_code = 200
    post_mock.text = _FAILURE_HTML
    session._http.post.return_value = post_mock

    session.submit_request()

    session._http.post.assert_called_once()
    call_kwargs = session._http.post.call_args
    sent_data = call_kwargs[1].get("data") or call_kwargs[0][1]
    assert sent_data.get("captcha") == "mock_answer"
    assert sent_data.get("flag") == "1337"
    assert "submit" in sent_data


@patch.dict(os.environ, {"CAPTCHA_MODE": "mock", "MOCK_CAPTCHA_VALUE": "mock_answer"})
def test_submit_uses_dynamic_captcha_field_name():
    """FIX: submit_request() utilise le nom de champ captcha détecté, pas 'captcha' hardcodé."""
    session = Session("http://example.com/captcha1/", flag_value="1500")
    session._http = _make_mock_http(_SAMPLE_HTML_ANSWER_FIELD)
    session.prepare_request()

    post_mock = MagicMock()
    post_mock.status_code = 200
    post_mock.text = _FAILURE_HTML
    session._http.post.return_value = post_mock

    session.submit_request()

    call_kwargs = session._http.post.call_args
    sent_data = call_kwargs[1].get("data") or call_kwargs[0][1]
    # FIX: le champ doit être "answer", pas "captcha"
    assert "answer" in sent_data, f"Champ 'answer' manquant, reçu: {sent_data}"
    assert sent_data["answer"] == "mock_answer"
    assert "captcha" not in sent_data
    assert sent_data["flag"] == "1500"


@patch.dict(os.environ, {"CAPTCHA_MODE": "mock", "MOCK_CAPTCHA_VALUE": "mock_answer"})
def test_submit_adds_code_alias_for_captcha2():
    """Challenge 2 attend aussi un champ code non annoncé dans le HTML."""
    session = Session("http://example.com/captcha2/", flag_value="2500")
    session._http = _make_mock_http(_SAMPLE_HTML)
    session.prepare_request()

    post_mock = MagicMock()
    post_mock.status_code = 200
    post_mock.text = _FAILURE_HTML
    session._http.post.return_value = post_mock

    session.submit_request()

    sent_data = session._http.post.call_args[1]["data"]
    assert sent_data["captcha"] == "mock_answer"
    assert sent_data["code"] == "mock_answer"
    assert sent_data["flag"] == "2500"


@patch.dict(os.environ, {"CAPTCHA_MODE": "mock", "MOCK_CAPTCHA_VALUE": "should_not_be_used"})
def test_prepare_uses_empty_captcha_bypass_for_captcha2():
    """Challenge 2 se contourne avec captcha vide après initialisation de l'image."""
    session = Session("http://example.com/captcha2/")
    session._http = _make_mock_http(_SAMPLE_HTML)
    session.prepare_request()
    assert session.captcha_value == ""


@patch.dict(os.environ, {"CAPTCHA_MODE": "mock", "MOCK_CAPTCHA_VALUE": "should_not_be_used"})
def test_prepare_uses_no_captcha_bypass_for_captcha4():
    """Challenge 4 demande un header mais pas de champ captcha."""
    session = Session("http://example.com/captcha4/")
    session._http = _make_mock_http(_SAMPLE_HTML_NO_CAPTCHA)
    session.prepare_request()
    assert session.captcha_value == ""


def test_session_adds_magic_word_header_for_captcha4():
    session = Session("http://example.com/captcha4/")
    assert session._http.headers["Magic-Word"] == "N0_t1m3_to_Sl33p"


def test_session_adds_headers_for_captcha5():
    session = Session("http://example.com/captcha5/")
    assert session._http.headers["Magic-Word"] == "N0_t1m3_to_Sl33p"
    assert session._http.headers["User-Agent"] == "Trackflaw"


def test_submit_request_no_crash_on_network_error():
    """submit_request() ne plante pas sur erreur réseau."""
    import requests as req
    session = Session("http://unreachable.invalid/captcha")
    session.captcha_value = "test"
    session._form_action = "http://unreachable.invalid/captcha"
    with patch.object(session._http, "post", side_effect=req.exceptions.ConnectionError("unreachable")):
        session.submit_request()
    assert session._response is None


# ---------------------------------------------------------------------------
# process_response()
# ---------------------------------------------------------------------------

def test_process_response_no_response():
    session = Session("http://example.com/captcha")
    result = session.process_response()
    assert result is False


def test_process_response_flag_found():
    session = Session("http://example.com/captcha")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = _SUCCESS_HTML
    session._response = mock_resp
    result = session.process_response()
    assert result is True
    assert session.valid_flag == "tp3_success_42"


def test_process_response_captcha_error():
    session = Session("http://example.com/captcha")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = _FAILURE_HTML
    session._response = mock_resp
    result = session.process_response()
    assert result is False
    assert session.valid_flag == ""
    assert session.last_result == "wrong_captcha"


def test_process_response_wrong_flag():
    session = Session("http://example.com/captcha")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = _WRONG_FLAG_HTML
    session._response = mock_resp
    result = session.process_response()
    assert result is False
    assert session.last_result == "wrong_flag"


def test_process_response_captcha3_ok_comment_is_wrong_flag():
    session = Session("http://example.com/captcha3/")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = _CAPTCHA3_WRONG_FLAG_HTML
    session._response = mock_resp
    result = session.process_response()
    assert result is False
    assert session.last_result == "wrong_flag"


def test_process_response_invalid_captcha():
    session = Session("http://example.com/captcha")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = _INVALID_CAPTCHA_HTML
    session._response = mock_resp
    result = session.process_response()
    assert result is False
    assert session.last_result == "wrong_captcha"


def test_process_response_ambiguous():
    session = Session("http://example.com/captcha")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = _AMBIGUOUS_SUCCESS_HTML
    session._response = mock_resp
    result = session.process_response()
    assert result is True
    assert session.last_result == "success"
    assert session.valid_flag == "Well done, challenge solved"


def test_process_response_help_text_is_not_success():
    session = Session("http://example.com/captcha")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = _HELP_ONLY_HTML
    session._response = mock_resp
    result = session.process_response()
    assert result is False
    assert session.last_result == "unknown"


def test_process_response_spaced_flag_found():
    session = Session("http://example.com/captcha2/")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = _SPACED_FLAG_HTML
    session._response = mock_resp
    result = session.process_response()
    assert result is True
    assert session.valid_flag == "FLAG-2{4_l1ttl3_h4rder}"


def test_process_response_captcha3_spaced_flag_found():
    session = Session("http://example.com/captcha3/")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = _CAPTCHA3_SUCCESS_HTML
    session._response = mock_resp
    result = session.process_response()
    assert result is True
    assert session.valid_flag == "FLAG-3{N0_t1m3_to_Sl33p}"


def test_process_response_captcha5_flag_wins_over_wrong_flag_text():
    session = Session("http://example.com/captcha5/")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = _CAPTCHA5_SUCCESS_HTML
    session._response = mock_resp
    result = session.process_response()
    assert result is True
    assert session.valid_flag == "FLAG-5{Th3_l4st_0n3}"


def test_extract_visible_message_skips_error_text():
    assert _extract_visible_message(_INVALID_CAPTCHA_HTML) == ""
    assert _extract_visible_message(_AMBIGUOUS_SUCCESS_HTML) == "Well done, challenge solved"


def test_is_help_text():
    assert _is_help_text("Flag is an integer between 2000 and 3000.")


# ---------------------------------------------------------------------------
# Patterns de détection
# ---------------------------------------------------------------------------

def test_flag_patterns_match_variants():
    cases = [
        ("FLAG{hello_world}", "hello_world"),
        ("Correct ! FLAG-2{two_done}", "FLAG-2{two_done}"),
        ("Wonderful ! F L A G - 2 {4_l1ttl3_h4rder}", "FLAG-2{4_l1ttl3_h4rder}"),
        ("Congratz ! FL A  G -3 { N0_t1m3_to_Sl33p}", "FLAG-3{N0_t1m3_to_Sl33p}"),
        ("F L AG - 5 {Th3_l4st_0n3}", "FLAG-5{Th3_l4st_0n3}"),
        ("ESGI{my_flag_42}", "my_flag_42"),
        ("CTF{secret}", "secret"),
    ]
    for text, expected in cases:
        matched = any(p.search(text) for p in _FLAG_PATTERNS)
        assert matched, f"Pattern non reconnu pour: {text}"


def test_error_patterns_match():
    cases = ["Captcha incorrect", "Invalid captcha", "Erreur"]
    for text in cases:
        matched = any(p.search(text) for p in _ERROR_PATTERNS)
        assert matched, f"Pattern d'erreur non reconnu pour: {text}"


def test_wrong_flag_patterns_match():
    assert any(p.search("Incorrect flag.") for p in _WRONG_FLAG_PATTERNS)


def test_captcha_error_patterns_match():
    assert any(p.search("Invalid captcha") for p in _CAPTCHA_ERROR_PATTERNS)
    assert any(
        p.search('Warning: Undefined array key "code"')
        for p in _CAPTCHA_ERROR_PATTERNS
    )


def test_needs_code_alias_only_for_captcha2():
    assert _needs_code_alias("http://example.com/captcha2/")
    assert not _needs_code_alias("http://example.com/captcha1/")


def test_empty_captcha_bypass_only_for_captcha2():
    assert _uses_empty_captcha_bypass("http://example.com/captcha2/")
    assert not _uses_empty_captcha_bypass("http://example.com/captcha1/")


def test_no_captcha_bypass_for_captcha4_and_captcha5():
    assert _uses_no_captcha_bypass("http://example.com/captcha4/")
    assert _uses_no_captcha_bypass("http://example.com/captcha5/")
    assert not _uses_no_captcha_bypass("http://example.com/captcha3/")


def test_magic_word_header_for_captcha4_and_captcha5():
    assert _needs_magic_word_header("http://example.com/captcha4/")
    assert _needs_magic_word_header("http://example.com/captcha5/")
    assert not _needs_magic_word_header("http://example.com/captcha3/")
    assert _magic_word_header_value() == "N0_t1m3_to_Sl33p"


def test_trackflaw_user_agent_only_for_captcha5():
    assert _needs_trackflaw_user_agent("http://example.com/captcha5/")
    assert not _needs_trackflaw_user_agent("http://example.com/captcha4/")


def test_normalize_spaced_flag():
    assert _normalize_flag_match("F L A G - 2 {4_l1ttl3_h4rder} ") == "FLAG-2{4_l1ttl3_h4rder}"
    assert _normalize_flag_match("FL A  G -3 { N0_t1m3_to_Sl33p}") == "FLAG-3{N0_t1m3_to_Sl33p}"
    assert _normalize_flag_match("F L AG - 5 {Th3_l4st_0n3}") == "FLAG-5{Th3_l4st_0n3}"


def test_trackflaw_marker_is_wrong_flag():
    html = """
    <html><body>
    <form></form>
    1b5683</div>
    </body></html>
    """
    assert _looks_like_trackflaw_wrong_flag(html)


def test_captcha3_ok_comment_is_wrong_flag():
    assert _looks_like_captcha3_wrong_flag(_CAPTCHA3_WRONG_FLAG_HTML)


# ---------------------------------------------------------------------------
# get_flag()
# ---------------------------------------------------------------------------

def test_get_flag():
    session = Session("http://example.com/captcha")
    session.valid_flag = "FLAG123"
    assert session.get_flag() == "FLAG123"


def test_get_flag_empty_before_success():
    session = Session("http://example.com/captcha")
    assert session.get_flag() == ""
