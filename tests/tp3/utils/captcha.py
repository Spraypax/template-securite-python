"""
Captcha helper for TP3.

CAPTCHA_MODE controls how the answer is produced:
  - ocr: read the downloaded image with pytesseract
  - manual: open the image and ask on stdin
  - mock: use MOCK_CAPTCHA_VALUE, useful for tests
"""

import logging
import mimetypes
import os
import re
import subprocess
import tempfile
from html.parser import HTMLParser
from urllib.parse import urljoin

logger = logging.getLogger("TP3")

CAPTCHA_FIELD_NAMES = {"captcha", "captcha_value", "answer", "code"}
_KNOWN_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"}


class _FormParser(HTMLParser):
    """Collect the form metadata and locate the captcha image."""

    def __init__(self):
        super().__init__()
        self.inputs: dict[str, str] = {}
        self.form_action: str = ""
        self.form_method: str = "post"
        self.captcha_img_src: str = ""
        self.captcha_field_name: str = "captcha"

    def handle_starttag(self, tag: str, attrs: list) -> None:
        attributes = dict(attrs)

        if tag == "form":
            self._read_form_attributes(attributes)
            return

        if tag == "input":
            self._register_input(attributes)
            return

        if tag == "img" and _looks_like_captcha_image(attributes):
            self.captcha_img_src = attributes.get("src", "")

    def _read_form_attributes(self, attributes: dict) -> None:
        self.form_action = attributes.get("action", "")
        self.form_method = attributes.get("method", "post").lower()

    def _register_input(self, attributes: dict) -> None:
        name = attributes.get("name", "")
        if not name:
            return

        self.inputs[name] = attributes.get("value", "")
        if name.lower() in CAPTCHA_FIELD_NAMES:
            self.captcha_field_name = name


class Captcha:
    """Represent the captcha form and the answer sent back to it."""

    def __init__(self, url: str, http_session=None):
        self.url: str = url
        self.image: str = ""
        self.value: str = ""
        self.form_fields: dict = {}
        self.form_action: str = ""
        self.form_method: str = "post"
        self.captcha_field_name: str = "captcha"
        self.captcha_img_src: str = ""
        self.page_body: str = ""
        self._http = http_session

    def capture(self) -> None:
        """Fetch the page, parse the form and download the captcha image."""
        if self._http is None:
            logger.debug("[capture] no HTTP session, leaving captcha untouched")
            return

        response = self._http.get(self.url, timeout=10)
        response.raise_for_status()
        self.page_body = response.text
        logger.debug(
            "[capture] GET %s -> %s | cookies=%s",
            self.url,
            response.status_code,
            dict(self._http.cookies),
        )

        parser = _FormParser()
        parser.feed(self.page_body)
        self._apply_parser_result(parser)

        if self.captcha_img_src:
            self.download_captcha_image(self.captcha_img_src)
            return

        logger.warning("[capture] no captcha image detected in page HTML")

    def _apply_parser_result(self, parser: _FormParser) -> None:
        self.form_fields = {
            name: value
            for name, value in parser.inputs.items()
            if name.lower() not in CAPTCHA_FIELD_NAMES
        }
        self.form_action = urljoin(self.url, parser.form_action or self.url)
        self.form_method = parser.form_method
        self.captcha_field_name = parser.captcha_field_name
        self.captcha_img_src = parser.captcha_img_src

        logger.debug("[capture] action=%r method=%r", self.form_action, self.form_method)
        logger.debug("[capture] hidden fields=%s", self.form_fields)
        logger.debug("[capture] captcha field=%r", self.captcha_field_name)
        logger.debug("[capture] captcha image=%r", self.captcha_img_src)

    def download_captcha_image(self, src: str) -> None:
        """Download the captcha image and keep the best extension available."""
        image_url = urljoin(self.url, src)
        logger.debug("[capture] downloading captcha image: %s", image_url)

        response = self._http.get(image_url, timeout=10, stream=True)
        response.raise_for_status()

        image_bytes = response.content
        extension = _extension_from_content_type(response.headers.get("Content-Type", ""))
        extension = extension or _extension_from_url(src)
        extension = extension or self._guess_ext_from_magic(image_bytes)

        if not extension:
            extension = ".bin"
            logger.warning("[capture] unknown captcha image type, using .bin")

        self.image = _write_temp_image(image_bytes, extension)
        logger.info("[capture] captcha image saved to %s", self.image)

    @staticmethod
    def _guess_ext_from_magic(content: bytes) -> str | None:
        """Guess an image extension from magic bytes."""
        signatures = (
            (content[:8] == b"\x89PNG\r\n\x1a\n", ".png"),
            (content[:3] == b"\xff\xd8\xff", ".jpg"),
            (content[:6] in (b"GIF87a", b"GIF89a"), ".gif"),
            (content[:4] == b"RIFF" and content[8:12] == b"WEBP", ".webp"),
        )
        for matched, extension in signatures:
            if matched:
                return extension
        return None

    def solve(self) -> None:
        """Resolve the captcha with the mode requested in the environment."""
        mode = os.getenv("CAPTCHA_MODE", "ocr").lower()

        if mode == "mock":
            self.value = os.getenv("MOCK_CAPTCHA_VALUE", "FIXME")
            logger.debug("[solve] mock captcha value=%r", self.value)
            return

        if mode == "ocr":
            self.value = self._solve_with_ocr()
            logger.info("[solve] OCR value=%r", self.value)
            return

        self._show_image_for_manual_mode()
        self.value = input(">>> Saisir la valeur du captcha : ").strip()
        logger.debug("[solve] manual captcha value=%r", self.value)

    def _solve_with_ocr(self) -> str:
        """Read the captcha image with pytesseract and normalize its output."""
        if not self.image or not os.path.exists(self.image):
            logger.warning("[solve] OCR skipped: no local image")
            return ""

        try:
            from PIL import Image
            import pytesseract
        except ImportError as exc:
            logger.error("[solve] Pillow and pytesseract are required for OCR mode")
            raise RuntimeError("Pillow et pytesseract sont requis pour le TP3") from exc

        tesseract_cmd = os.getenv("TESSERACT_CMD", "")
        if tesseract_cmd:
            pytesseract.pytesseract.tesseract_cmd = tesseract_cmd

        with Image.open(self.image) as image:
            prepared_image = self._prepare_image_for_ocr(image)
            raw_text = pytesseract.image_to_string(
                prepared_image,
                config=(
                    "--psm 7 "
                    "-c tessedit_char_whitelist=0123456789"
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                ),
            )

        cleaned = clean_ocr_result(raw_text)
        if not cleaned:
            logger.warning("[solve] OCR returned no usable text from %r", raw_text)
        return cleaned

    @staticmethod
    def _prepare_image_for_ocr(image):
        """Convert to high contrast and enlarge before OCR."""
        from PIL import ImageOps

        gray_image = ImageOps.grayscale(image)
        bigger_image = gray_image.resize((gray_image.width * 2, gray_image.height * 2))
        return bigger_image.point(lambda px: 255 if px > 150 else 0)

    def _show_image_for_manual_mode(self) -> None:
        if self.image and os.path.exists(self.image):
            self._open_image(self.image)
            logger.info("[solve] captcha image: %s", self.image)
            return

        logger.warning("[solve] no local image available")

    def _open_image(self, path: str) -> None:
        """Open the image with the system viewer when possible."""
        try:
            if os.name == "nt":
                os.startfile(path)  # type: ignore[attr-defined]
                return

            opener = "open" if os.uname().sysname == "Darwin" else "xdg-open"
            subprocess.Popen(
                [opener, path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            logger.debug("[solve] image opened with %s", opener)
        except Exception as exc:
            logger.debug("[solve] could not open image: %s", exc)

    def get_value(self) -> str:
        """Return the value produced by solve()."""
        return self.value


def clean_ocr_result(value: str) -> str:
    """Normalize a short alphanumeric OCR result."""
    substitutions = str.maketrans({"O": "0", "o": "0", "I": "1", "l": "1"})
    normalized = value.strip().translate(substitutions)
    return "".join(re.findall(r"[A-Za-z0-9]+", normalized))


def _looks_like_captcha_image(attributes: dict) -> bool:
    src = attributes.get("src", "").lower()
    alt = attributes.get("alt", "").lower()
    class_name = attributes.get("class", "").lower()
    return "captcha" in src or "captcha" in alt or "captcha" in class_name


def _extension_from_content_type(content_type: str) -> str | None:
    mime_type = content_type.split(";", 1)[0].strip()
    logger.debug("[capture] content type=%r", mime_type)

    if not mime_type.startswith("image/"):
        return None

    extension = mimetypes.guess_extension(mime_type)
    if extension in (".jpe", ".jpeg"):
        return ".jpg"
    return extension


def _extension_from_url(src: str) -> str | None:
    url_path = src.split("?", 1)[0]
    extension = os.path.splitext(url_path)[1].lower()
    if extension in _KNOWN_IMAGE_EXTENSIONS:
        logger.debug("[capture] extension from URL=%s", extension)
        return extension
    return None


def _write_temp_image(content: bytes, extension: str) -> str:
    temp_file = tempfile.NamedTemporaryFile(
        suffix=extension,
        delete=False,
        prefix="captcha_tp3_",
    )
    try:
        temp_file.write(content)
        return temp_file.name
    finally:
        temp_file.close()
