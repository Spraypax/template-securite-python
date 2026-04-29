import logging


LOG_LEVEL = logging.INFO
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_FILE = "app.log"
LOGGER_NAME = "TP3"


def _build_handlers() -> list[logging.Handler]:
    return [
        logging.FileHandler(LOG_FILE, mode="a"),
        logging.StreamHandler(),
    ]


def _configure_logging() -> None:
    logging.basicConfig(
        level=LOG_LEVEL,
        format=LOG_FORMAT,
        handlers=_build_handlers(),
    )


_configure_logging()
logger = logging.getLogger(LOGGER_NAME)
