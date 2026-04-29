"""
Tests unitaires pour Captcha (TP3).

Variables d'environnement utilisées :
  CAPTCHA_MODE=mock          — désactive l'input() et le réseau
  MOCK_CAPTCHA_VALUE=FIXME   — valeur retournée par solve() en mode mock
"""

import os
from unittest.mock import MagicMock, patch

from src.tp3.utils.captcha import Captcha, _FormParser, CAPTCHA_FIELD_NAMES, clean_ocr_result


# ---------------------------------------------------------------------------
# _FormParser
# ---------------------------------------------------------------------------

def test_form_parser_basic():
    """Parse un formulaire HTML minimal."""
    html = """
    <form action="/submit" method="POST">
        <input type="hidden" name="flag" value="abc123">
        <input type="text" name="captcha" value="">
        <img src="/captcha.png" alt="captcha">
    </form>
    """
    p = _FormParser()
    p.feed(html)
    assert p.form_action == "/submit"
    assert p.form_method == "post"
    assert p.inputs.get("flag") == "abc123"
    assert p.captcha_img_src == "/captcha.png"
    assert p.captcha_field_name == "captcha"


def test_form_parser_no_captcha_img():
    """Sans image captcha, captcha_img_src reste vide."""
    html = '<form><input type="hidden" name="token" value="xyz"></form>'
    p = _FormParser()
    p.feed(html)
    assert p.captcha_img_src == ""
    assert p.inputs.get("token") == "xyz"


def test_form_parser_detects_answer_field():
    """Détecte 'answer' comme nom de champ captcha."""
    html = """
    <form action="/check" method="post">
        <input type="text" name="answer" value="">
        <img src="/cap.png" alt="captcha">
    </form>
    """
    p = _FormParser()
    p.feed(html)
    assert p.captcha_field_name == "answer"


# ---------------------------------------------------------------------------
# Captcha — initialisation
# ---------------------------------------------------------------------------

def test_captcha_init():
    url = "http://example.com/captcha"
    captcha = Captcha(url)
    assert captcha.url == url
    assert captcha.image == ""
    assert captcha.value == ""
    assert captcha.form_fields == {}
    assert captcha.captcha_field_name == "captcha"
    assert captcha.captcha_img_src == ""


# ---------------------------------------------------------------------------
# Captcha — capture() sans session HTTP (mode passif)
# ---------------------------------------------------------------------------

def test_capture_no_http_session():
    """Sans session HTTP, capture() ne fait rien (mode test)."""
    captcha = Captcha("http://example.com/captcha")
    captcha.capture()
    assert captcha.image == ""
    assert captcha.form_fields == {}


# ---------------------------------------------------------------------------
# Captcha — capture() avec session HTTP mockée
# ---------------------------------------------------------------------------

def test_capture_with_mock_http():
    """Avec une session HTTP mockée, capture() parse correctement le HTML."""
    html = """
    <form action="/captcha1/check" method="POST">
        <input type="hidden" name="flag" value="token_abc">
        <input type="text" name="captcha" value="">
        <img src="/captcha_image.png" alt="captcha" class="captcha">
    </form>
    """
    mock_session = MagicMock()
    mock_session.get.return_value.status_code = 200
    mock_session.get.return_value.text = html
    # Simule Content-Type PNG correct
    mock_session.get.return_value.headers = {"Content-Type": "image/png"}
    mock_session.get.return_value.content = b"\x89PNG\r\n\x1a\n" + b"fake"
    mock_session.get.return_value.raise_for_status = MagicMock()
    mock_session.cookies = {}

    captcha = Captcha("http://example.com/captcha1/", http_session=mock_session)
    captcha.capture()

    assert captcha.form_action == "http://example.com/captcha1/check"
    assert captcha.form_method == "post"
    assert captcha.form_fields.get("flag") == "token_abc"
    assert "captcha" not in captcha.form_fields
    assert captcha.captcha_field_name == "captcha"
    assert captcha.captcha_img_src == "/captcha_image.png"
    assert captcha.image != ""
    assert os.path.exists(captcha.image)
    # FIX vérifié : l'extension doit être .png (depuis Content-Type), pas .php
    assert captcha.image.endswith(".png"), f"Extension incorrecte: {captcha.image}"


def test_capture_extension_from_content_type():
    """L'extension vient du Content-Type, pas de l'URL (évite le bug .php)."""
    html = """
    <form action="/check" method="post">
        <img src="/get_captcha.php?token=abc" alt="captcha">
    </form>
    """
    mock_session = MagicMock()
    mock_session.get.return_value.status_code = 200
    mock_session.get.return_value.text = html
    mock_session.get.return_value.headers = {"Content-Type": "image/png"}
    mock_session.get.return_value.content = b"\x89PNG\r\n\x1a\n" + b"fake"
    mock_session.get.return_value.raise_for_status = MagicMock()
    mock_session.cookies = {}

    captcha = Captcha("http://example.com/", http_session=mock_session)
    captcha.capture()

    # Sans ce fix, l'extension serait .php — maintenant ça doit être .png
    assert captcha.image.endswith(".png"), f"Bug .php non corrigé: {captcha.image}"


def test_capture_extension_from_magic_bytes():
    """Fallback magic bytes quand Content-Type est absent."""
    html = '<form><img src="/captcha" alt="captcha"></form>'
    mock_session = MagicMock()
    mock_session.get.return_value.status_code = 200
    mock_session.get.return_value.text = html
    mock_session.get.return_value.headers = {}  # Pas de Content-Type
    mock_session.get.return_value.content = b"\x89PNG\r\n\x1a\n" + b"fake"
    mock_session.get.return_value.raise_for_status = MagicMock()
    mock_session.cookies = {}

    captcha = Captcha("http://example.com/", http_session=mock_session)
    captcha.capture()
    assert captcha.image.endswith(".png")


# ---------------------------------------------------------------------------
# Captcha — _guess_ext_from_magic
# ---------------------------------------------------------------------------

def test_magic_bytes_png():
    assert Captcha._guess_ext_from_magic(b"\x89PNG\r\n\x1a\nXXX") == ".png"

def test_magic_bytes_jpg():
    assert Captcha._guess_ext_from_magic(b"\xff\xd8\xffXXX") == ".jpg"

def test_magic_bytes_gif():
    assert Captcha._guess_ext_from_magic(b"GIF89aXXX") == ".gif"

def test_magic_bytes_unknown():
    assert Captcha._guess_ext_from_magic(b"UNKNOWN") is None


def test_clean_ocr_result():
    assert clean_ocr_result(" O1l-9!\n") == "0119"


# ---------------------------------------------------------------------------
# Captcha — solve() en mode mock
# ---------------------------------------------------------------------------

def test_solve_mock_default():
    """Mode mock avec valeur par défaut FIXME."""
    with patch.dict(os.environ, {"CAPTCHA_MODE": "mock", "MOCK_CAPTCHA_VALUE": "FIXME"}):
        captcha = Captcha("http://example.com/captcha")
        captcha.solve()
        assert captcha.value == "FIXME"


def test_solve_mock_custom_value():
    """Mode mock avec valeur personnalisée."""
    with patch.dict(os.environ, {"CAPTCHA_MODE": "mock", "MOCK_CAPTCHA_VALUE": "ABC123"}):
        captcha = Captcha("http://example.com/captcha")
        captcha.solve()
        assert captcha.value == "ABC123"


def test_solve_manual_no_image(monkeypatch):
    """Mode manuel sans image : demande input() et stocke la valeur."""
    monkeypatch.setenv("CAPTCHA_MODE", "manual")
    monkeypatch.delenv("MOCK_CAPTCHA_VALUE", raising=False)
    monkeypatch.setattr("builtins.input", lambda _: "test_response")
    captcha = Captcha("http://example.com/captcha")
    captcha.solve()
    assert captcha.value == "test_response"


# ---------------------------------------------------------------------------
# Captcha — get_value()
# ---------------------------------------------------------------------------

def test_get_value():
    captcha = Captcha("http://example.com/captcha")
    captcha.value = "TEST123"
    assert captcha.get_value() == "TEST123"


def test_get_value_after_mock_solve():
    with patch.dict(os.environ, {"CAPTCHA_MODE": "mock", "MOCK_CAPTCHA_VALUE": "FLAG42"}):
        captcha = Captcha("http://example.com/captcha")
        captcha.solve()
        assert captcha.get_value() == "FLAG42"
