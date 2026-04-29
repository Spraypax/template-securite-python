import logging

LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"


def _build_handlers() -> list[logging.Handler]:
    return [
        logging.FileHandler("app.log", mode="a"),
        logging.StreamHandler(),
    ]


logging.basicConfig(
    level=logging.INFO,
    format=LOG_FORMAT,
    handlers=_build_handlers(),
)

logger = logging.getLogger("TP3")
