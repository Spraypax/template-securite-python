"""
HTTP workflow for TP3 captcha challenges.

Public call order:
    prepare_request()
    submit_request()
    process_response()
    get_flag()
"""

import logging
import os
import re
from html import unescape

import requests

from src.tp3.utils.captcha import Captcha

logger = logging.getLogger("TP3")

_FLAG_PATTERNS = [
    re.compile(r"FLAG\{([^}]+)\}", re.IGNORECASE),
    re.compile(r"(FLAG-[A-Za-z0-9_-]+\{[^}]+\})", re.IGNORECASE),
    re.compile(r"(F\s*L\s*A\s*G\s*-\s*[A-Za-z0-9_-]+\s*\{\s*[^}]+?\s*\})", re.IGNORECASE),
    re.compile(r"ESGI\{([^}]+)\}", re.IGNORECASE),
    re.compile(r"CTF\{([^}]+)\}", re.IGNORECASE),
    re.compile(r'class=["\']flag["\'][^>]*>\s*([^<]+)\s*<', re.IGNORECASE),
    re.compile(r'class=["\']alert-success[^"\']*["\'][^>]*>\s*([^<]+)\s*<', re.IGNORECASE),
    re.compile(r"class=[\"'][^\"']*(?:success|valid)[^\"']*[\"'][^>]*>\s*([^<]+)\s*<", re.IGNORECASE),
    re.compile(r"flag\s*[=:]\s*([A-Za-z0-9_\-]{6,})", re.IGNORECASE),
]

_WRONG_FLAG_PATTERNS = [
    re.compile(r"incorrect\s+flag", re.IGNORECASE),
    re.compile(r"wrong\s+flag", re.IGNORECASE),
    re.compile(r"invalid\s+flag", re.IGNORECASE),
]

_CAPTCHA_ERROR_PATTERNS = [
    re.compile(r"incorrect\s+captcha", re.IGNORECASE),
    re.compile(r"captcha\s+incorrect", re.IGNORECASE),
    re.compile(r"invalid\s+captcha", re.IGNORECASE),
    re.compile(r"wrong\s+captcha", re.IGNORECASE),
    re.compile(r"captcha.*(?:fail|error|ko)", re.IGNORECASE),
    re.compile(r"undefined\s+array\s+key\s+[\"']code[\"']", re.IGNORECASE),
]

_ERROR_PATTERNS = [
    *_WRONG_FLAG_PATTERNS,
    *_CAPTCHA_ERROR_PATTERNS,
    re.compile(r"erreur", re.IGNORECASE),
    re.compile(r"mauvais", re.IGNORECASE),
    re.compile(r"try again", re.IGNORECASE),
]

_HELP_TEXT_PATTERNS = [
    re.compile(r"flag\s+is\s+an\s+integer\s+between", re.IGNORECASE),
]


class Session:
    """Manage one challenge session from page capture to response parsing."""

    def __init__(self, url: str, flag_value: str = ""):
        self.url: str = url
        self.captcha_value: str = ""
        self.flag_value: str = flag_value
        self.valid_flag: str = ""
        self.last_result: str = ""
        self.response_text: str = ""
        self._initial_body: str = ""

        self._http = requests.Session()
        self._response: requests.Response | None = None
        self._form_fields: dict = {}
        self._form_action: str = url
        self._form_method: str = "post"
        self._captcha_field_name: str = "captcha"
        self._captcha_img_src: str = ""
        self._form_initialized: bool = False

        self._configure_session_headers()

    def prepare_request(self) -> None:
        """Capture the captcha and compute every value needed for submission."""
        captcha = Captcha(self.url, http_session=self._http)
        self._load_or_refresh_form(captcha)
        self._fill_captcha_value(captcha)
        self._fill_missing_flag_value()
        self._log_request_state()

    def submit_request(self) -> None:
        """Submit the form with the current flag and captcha values."""
        self._warn_when_captcha_was_not_solved()

        payload = self._build_payload()
        headers = self._build_headers()
        logger.debug("[submit] %s %s", self._form_method.upper(), self._form_action)
        logger.debug("[submit] payload=%s", payload)

        self._response = self._send_form(payload, headers)
        if self._response is None:
            return

        logger.debug(
            "[submit] status=%s body_size=%s cookies=%s",
            self._response.status_code,
            len(self._response.text),
            dict(self._http.cookies),
        )
        if os.getenv("DEBUG", "0") == "1":
            logger.debug("[submit] body preview=%s", self._response.text[:500])

    def process_response(self) -> bool:
        """Analyse the last HTTP response and report whether it is successful."""
        if self._response is None:
            logger.warning("[process] response is missing")
            self.last_result = "no_response"
            return False

        body = self._response.text
        logger.debug("[process] status=%s body_size=%s", self._response.status_code, len(body))

        return self._classify_response_body(body)

    def get_flag(self) -> str:
        """Return the successful flag or message recorded by process_response()."""
        return self.valid_flag

    def _configure_session_headers(self) -> None:
        headers = _challenge_headers(self.url)
        if headers:
            self._http.headers.update(headers)

    def _load_or_refresh_form(self, captcha: Captcha) -> None:
        if self._form_initialized:
            captcha.download_captcha_image(self._captcha_img_src)
            return

        captcha.capture()
        self._initial_body = captcha.page_body
        self._form_fields = dict(captcha.form_fields)
        self._form_action = captcha.form_action or self.url
        self._form_method = captcha.form_method
        self._captcha_field_name = captcha.captcha_field_name
        self._captcha_img_src = captcha.captcha_img_src
        self._form_initialized = True

    def _fill_captcha_value(self, captcha: Captcha) -> None:
        bypass_message = _captcha_bypass_message(self.url)
        if bypass_message:
            self.captcha_value = ""
            logger.info("[solve] %s", bypass_message)
            return

        captcha.solve()
        self.captcha_value = captcha.get_value()

    def _fill_missing_flag_value(self) -> None:
        if self.flag_value:
            return

        self.flag_value = (
            self._form_fields.get("flag")
            or self._form_fields.get("token")
            or self._form_fields.get("csrf_token")
            or next(iter(self._form_fields.values()), "")
        )

    def _log_request_state(self) -> None:
        logger.debug(
            "[prepare] captcha=%r field=%r flag=%r",
            self.captcha_value,
            self._captcha_field_name,
            self.flag_value,
        )
        logger.debug("[prepare] fields=%s", self._form_fields)
        logger.debug("[prepare] target=%r method=%r", self._form_action, self._form_method)

    def _warn_when_captcha_was_not_solved(self) -> None:
        if self.captcha_value:
            return
        if _uses_empty_captcha_bypass(self.url) or _uses_no_captcha_bypass(self.url):
            return
        logger.warning("[submit] captcha value is empty; call prepare_request() first")

    def _build_payload(self) -> dict:
        payload = dict(self._form_fields)
        if "flag" in payload or self.flag_value:
            payload["flag"] = self.flag_value

        captcha_value = self._submission_captcha_value()
        payload[self._captcha_field_name] = captcha_value

        if _needs_code_alias(self.url):
            payload["code"] = captcha_value

        payload["submit"] = ""
        return payload

    def _submission_captcha_value(self) -> str:
        if self.captcha_value:
            return self.captcha_value

        if _needs_code_alias(self.url) and os.getenv("CAPTCHA_MODE", "").lower() == "mock":
            return os.getenv("MOCK_CAPTCHA_VALUE", "FIXME")

        return ""

    def _build_headers(self) -> dict[str, str]:
        headers = {
            "Referer": self.url,
            "Content-Type": "application/x-www-form-urlencoded",
        }
        headers.update(_challenge_headers(self.url))
        return headers

    def _send_form(self, payload: dict, headers: dict):
        try:
            if self._form_method == "post":
                return self._http.post(
                    self._form_action,
                    data=payload,
                    headers=headers,
                    timeout=15,
                )

            return self._http.get(
                self._form_action,
                params=payload,
                headers=headers,
                timeout=15,
            )
        except requests.exceptions.RequestException as exc:
            logger.error("[submit] network error: %s", exc)
            return None

    def _classify_response_body(self, body: str) -> bool:
        flag_match = _first_match(_FLAG_PATTERNS, body)
        if flag_match is not None:
            self.valid_flag = _normalize_flag_match(_match_text(flag_match))
            self.last_result = "success"
            logger.info("[process] flag accepted: %s", self.valid_flag)
            return True

        failure_kind = _response_failure_kind(body)
        if failure_kind:
            self.last_result = failure_kind
            _log_failure_kind(failure_kind)
            return False

        visible_message = _extract_visible_message(body)
        if visible_message and not _is_help_text(visible_message):
            self.valid_flag = visible_message
            self.response_text = body
            self.last_result = "success"
            logger.info("[process] accepted visible message: %s", self.valid_flag)
            return True

        self.response_text = body
        self.last_result = "unknown"
        logger.warning("[process] response could not be classified")
        logger.debug("[process] body preview=%s", body[:500])
        return False


def _extract_visible_message(body: str) -> str:
    """Extract the first visible paragraph that does not look like an error."""
    candidates = re.findall(
        r"<p[^>]*class=[\"'][^\"']*(?:success|valid|info|alert)[^\"']*[\"'][^>]*>(.*?)</p>",
        body,
        flags=re.IGNORECASE | re.DOTALL,
    )
    if not candidates:
        candidates = re.findall(r"<p[^>]*>(.*?)</p>", body, flags=re.IGNORECASE | re.DOTALL)

    for html_fragment in candidates:
        plain_text = re.sub(r"<[^>]+>", " ", html_fragment)
        plain_text = " ".join(unescape(plain_text).split())
        if plain_text and not _matches_any(_ERROR_PATTERNS, plain_text):
            return plain_text

    return ""


def _is_help_text(text: str) -> bool:
    return _matches_any(_HELP_TEXT_PATTERNS, text)


def _needs_code_alias(url: str) -> bool:
    return "/captcha2/" in url


def _needs_magic_word_header(url: str) -> bool:
    return "/captcha4/" in url or "/captcha5/" in url


def _magic_word_header_value() -> str:
    return os.getenv("TP3_MAGIC_WORD", "N0_t1m3_to_Sl33p")


def _needs_trackflaw_user_agent(url: str) -> bool:
    return "/captcha5/" in url


def _uses_empty_captcha_bypass(url: str) -> bool:
    return "/captcha2/" in url


def _uses_no_captcha_bypass(url: str) -> bool:
    return "/captcha4/" in url or "/captcha5/" in url


def _looks_like_captcha3_wrong_flag(body: str) -> bool:
    return "<!-- Ok -->" in body


def _normalize_flag_match(value: str) -> str:
    compact_flag = " ".join(value.split())
    spaced_flag = re.search(
        r"F\s*L\s*A\s*G\s*-\s*([A-Za-z0-9_-]+)\s*\{\s*([^}]+?)\s*\}",
        compact_flag,
        flags=re.IGNORECASE,
    )
    if spaced_flag:
        return f"FLAG-{spaced_flag.group(1)}{{{spaced_flag.group(2).strip()}}}"
    return compact_flag


def _looks_like_trackflaw_wrong_flag(body: str) -> bool:
    return bool(
        re.search(
            r">\s*[0-9a-f]{6}\s*</div>\s*</body>",
            body,
            flags=re.IGNORECASE,
        )
    )


def _first_match(patterns: list[re.Pattern], text: str):
    for pattern in patterns:
        match = pattern.search(text)
        if match is not None:
            return match
    return None


def _matches_any(patterns: list[re.Pattern], text: str) -> bool:
    return _first_match(patterns, text) is not None


def _match_text(match: re.Match) -> str:
    if match.lastindex:
        return match.group(1)
    return match.group(0)


def _challenge_headers(url: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    if _needs_magic_word_header(url):
        headers["Magic-Word"] = _magic_word_header_value()
    if _needs_trackflaw_user_agent(url):
        headers["User-Agent"] = "Trackflaw"
    return headers


def _captcha_bypass_message(url: str) -> str:
    if _uses_no_captcha_bypass(url):
        return "no captcha required for this challenge"
    if _uses_empty_captcha_bypass(url):
        return "empty captcha bypass selected"
    return ""


def _response_failure_kind(body: str) -> str:
    if _matches_any(_WRONG_FLAG_PATTERNS, body) or _looks_like_captcha3_wrong_flag(body):
        return "wrong_flag"
    if _matches_any(_CAPTCHA_ERROR_PATTERNS, body):
        return "wrong_captcha"
    if _looks_like_trackflaw_wrong_flag(body):
        return "wrong_flag"
    if _matches_any(_ERROR_PATTERNS, body):
        return "error"
    return ""


def _log_failure_kind(kind: str) -> None:
    messages = {
        "wrong_flag": "[process] flag rejected, moving on",
        "wrong_captcha": "[process] captcha rejected, retrying flag",
        "error": "[process] error response, retrying",
    }
    logger.info(messages.get(kind, "[process] response rejected"))
