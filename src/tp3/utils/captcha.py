"""
Captcha handling for TP3.

CAPTCHA_MODE controls the solver:
  - ocr: read the downloaded image with pytesseract
  - manual: open the image and ask for terminal input
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
_SUPPORTED_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"}


class _FormParser(HTMLParser):
    """Collect form metadata, inputs and the captcha image reference."""

    def __init__(self):
        super().__init__()
        self.inputs: dict[str, str] = {}
        self.form_action: str = ""
        self.form_method: str = "post"
        self.captcha_img_src: str = ""
        self.captcha_field_name: str = "captcha"

    def handle_starttag(self, tag: str, attrs: list) -> None:
        attributes = dict(attrs)
        handlers = {
            "form": self._read_form_tag,
            "input": self._read_input_tag,
            "img": self._read_image_tag,
        }
        handler = handlers.get(tag)
        if handler is not None:
            handler(attributes)

    def _read_form_tag(self, attributes: dict) -> None:
        self.form_action = attributes.get("action", "")
        self.form_method = attributes.get("method", "post").lower()

    def _read_input_tag(self, attributes: dict) -> None:
        input_name = attributes.get("name", "")
        if not input_name:
            return

        self.inputs[input_name] = attributes.get("value", "")
        if input_name.lower() in CAPTCHA_FIELD_NAMES:
            self.captcha_field_name = input_name

    def _read_image_tag(self, attributes: dict) -> None:
        src = attributes.get("src", "")
        searchable_bits = (
            src.lower(),
            attributes.get("alt", "").lower(),
            attributes.get("class", "").lower(),
        )
        if any("captcha" in value for value in searchable_bits):
            self.captcha_img_src = src


class Captcha:
    """Represent one captcha and the form data needed to submit it."""

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
        """Load the page, parse the form, then download the captcha image."""
        if self._http is None:
            logger.debug("capture() skipped: no HTTP session available")
            return

        response = self._fetch_page()
        parser = self._parse_page(response.text)
        self._apply_parser_result(parser)

        if self.captcha_img_src:
            self.download_captcha_image(self.captcha_img_src)
            return

        logger.warning("[capture] No captcha image found in the HTML page.")

    def download_captcha_image(self, src: str) -> None:
        """Download the captcha image into a temporary local file."""
        image_url = urljoin(self.url, src)
        logger.debug("[capture] downloading captcha image: %s", image_url)

        image_response = self._http.get(image_url, timeout=10, stream=True)
        image_response.raise_for_status()

        content = image_response.content
        extension = _extension_from_response(image_response, src, content)
        self.image = _write_temp_image(content, extension)
        logger.info("[capture] captcha image saved: %s", self.image)

    @staticmethod
    def _guess_ext_from_magic(content: bytes) -> str | None:
        """Identify common image formats from their magic bytes."""
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
        """Resolve the captcha according to CAPTCHA_MODE."""
        mode = os.getenv("CAPTCHA_MODE", "ocr").lower()
        solvers = {
            "mock": self._solve_from_mock,
            "ocr": self._solve_from_ocr,
        }
        solver = solvers.get(mode, self._solve_manually)
        solver()

    def get_value(self) -> str:
        """Return the current captcha value."""
        return self.value

    def _fetch_page(self):
        logger.debug("[capture] GET %s", self.url)
        response = self._http.get(self.url, timeout=10)
        response.raise_for_status()
        self.page_body = response.text
        logger.debug(
            "[capture] status=%s | cookies=%s",
            response.status_code,
            dict(self._http.cookies),
        )
        return response

    def _parse_page(self, body: str) -> _FormParser:
        parser = _FormParser()
        parser.feed(body)
        return parser

    def _apply_parser_result(self, parser: _FormParser) -> None:
        self.form_fields = _hidden_fields_without_captcha(parser.inputs)
        self.form_action = urljoin(self.url, parser.form_action or self.url)
        self.form_method = parser.form_method
        self.captcha_field_name = parser.captcha_field_name
        self.captcha_img_src = parser.captcha_img_src

        logger.debug("[capture] form_action=%r method=%r", self.form_action, self.form_method)
        logger.debug("[capture] hidden fields=%s", self.form_fields)
        logger.debug("[capture] captcha field name=%r", self.captcha_field_name)
        logger.debug("[capture] captcha img src=%r", self.captcha_img_src)

    def _solve_from_mock(self) -> None:
        self.value = os.getenv("MOCK_CAPTCHA_VALUE", "FIXME")
        logger.debug("[solve] mock captcha value: %r", self.value)

    def _solve_from_ocr(self) -> None:
        self.value = self._solve_with_ocr()
        logger.info("[solve] OCR captcha: %r", self.value)

    def _solve_manually(self) -> None:
        if self.image and os.path.exists(self.image):
            self._open_image(self.image)
            logger.info("[solve] captcha image: %s", self.image)
        else:
            logger.warning("[solve] No local captcha image available.")

        self.value = input(">>> Saisir la valeur du captcha : ").strip()
        logger.debug("[solve] manual captcha value: %r", self.value)

    def _solve_with_ocr(self) -> str:
        """Read the captcha image with pytesseract and normalize the result."""
        if not self.image or not os.path.exists(self.image):
            logger.warning("[solve] OCR skipped: no local image.")
            return ""

        try:
            from PIL import Image
            import pytesseract
        except ImportError as exc:
            logger.error("[solve] Pillow and pytesseract are required for OCR mode.")
            raise RuntimeError("Pillow et pytesseract sont requis pour le TP3") from exc

        tesseract_cmd = os.getenv("TESSERACT_CMD", "")
        if tesseract_cmd:
            pytesseract.pytesseract.tesseract_cmd = tesseract_cmd

        with Image.open(self.image) as image:
            prepared_image = self._prepare_image_for_ocr(image)
            raw_value = pytesseract.image_to_string(
                prepared_image,
                config=(
                    "--psm 7 "
                    "-c tessedit_char_whitelist=0123456789"
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                ),
            )

        cleaned_value = clean_ocr_result(raw_value)
        if not cleaned_value:
            logger.warning("[solve] OCR returned no usable value from: %r", raw_value)
        return cleaned_value

    @staticmethod
    def _prepare_image_for_ocr(image):
        """Make a simple high-contrast image for Tesseract."""
        from PIL import ImageOps

        grayscale = ImageOps.grayscale(image)
        enlarged = grayscale.resize((grayscale.width * 2, grayscale.height * 2))
        return enlarged.point(lambda px: 255 if px > 150 else 0)

    def _open_image(self, path: str) -> None:
        """Open the image with the system viewer without blocking the script."""
        try:
            if os.name == "nt":
                os.startfile(path)  # type: ignore[attr-defined]
                return

            viewer = "open" if os.uname().sysname == "Darwin" else "xdg-open"
            subprocess.Popen(
                [viewer, path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            logger.debug("[solve] opened image with %r", viewer)
        except Exception as exc:
            logger.debug("[solve] could not open image: %s", exc)


def clean_ocr_result(value: str) -> str:
    """Clean a short alphanumeric OCR answer."""
    translation = str.maketrans({"O": "0", "o": "0", "I": "1", "l": "1"})
    normalized = value.strip().translate(translation)
    return "".join(re.findall(r"[A-Za-z0-9]+", normalized))


def _hidden_fields_without_captcha(inputs: dict[str, str]) -> dict[str, str]:
    return {
        name: value
        for name, value in inputs.items()
        if name.lower() not in CAPTCHA_FIELD_NAMES
    }


def _extension_from_response(response, src: str, content: bytes) -> str:
    extension = _extension_from_content_type(response.headers.get("Content-Type", ""))
    if extension:
        return extension

    extension = _extension_from_url(src)
    if extension:
        logger.debug("[capture] extension from URL: %s", extension)
        return extension

    extension = Captcha._guess_ext_from_magic(content)
    if extension:
        logger.debug("[capture] extension from magic bytes: %s", extension)
        return extension

    logger.warning("[capture] Unknown image type, using .bin")
    return ".bin"


def _extension_from_content_type(content_type_header: str) -> str | None:
    content_type = content_type_header.split(";")[0].strip()
    logger.debug("[capture] received Content-Type: %r", content_type)
    if not content_type or not content_type.startswith("image/"):
        return None

    extension = mimetypes.guess_extension(content_type)
    if extension in (".jpe", ".jpeg"):
        return ".jpg"
    return extension


def _extension_from_url(src: str) -> str | None:
    url_path = src.split("?")[0]
    extension = os.path.splitext(url_path)[1].lower()
    if extension in _SUPPORTED_IMAGE_EXTENSIONS:
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
