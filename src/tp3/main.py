import os
import re
import time
from dataclasses import dataclass

from src.tp3.utils.config import logger
from src.tp3.utils.session import Session


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


@dataclass(frozen=True)
class RuntimeOptions:
    base_url: str
    challenge_ids: str
    flag_start_env: str | None
    flag_end_env: str | None
    retries_per_flag: int
    delay_seconds: float
    magic_word: str


@dataclass(frozen=True)
class FlagWindow:
    start: int
    end: int

    def as_tuple(self) -> tuple[int, int]:
        return self.start, self.end


def build_challenge_urls(
    base_url: str = DEFAULT_BASE_URL,
    challenge_ids: str = DEFAULT_CHALLENGES,
) -> dict[str, str]:
    cleaned_base = base_url.rstrip("/")
    ids = (part for part in challenge_ids.replace(" ", "").split(",") if part)
    return {challenge_id: f"{cleaned_base}/captcha{challenge_id}/" for challenge_id in ids}


def solve_challenge(
    url: str,
    *,
    flag_start: int,
    flag_end: int,
    retries_per_flag: int,
    delay_seconds: float,
) -> str:
    total_attempts = (flag_end - flag_start + 1) * retries_per_flag
    current_attempt = 0
    session = Session(url)

    for flag_candidate in range(flag_start, flag_end + 1):
        session.flag_value = str(flag_candidate)

        for retry_index in range(1, retries_per_flag + 1):
            current_attempt += 1
            _log_attempt(
                url=url,
                attempt=current_attempt,
                total_attempts=total_attempts,
                flag_candidate=flag_candidate,
                retry_index=retry_index,
                retries_per_flag=retries_per_flag,
            )

            session.prepare_request()
            session.submit_request()

            if session.process_response():
                return session.get_flag()

            if session.last_result == "wrong_flag":
                break

            _pause_between_attempts(delay_seconds)

    raise RuntimeError(
        f"Aucun flag trouve pour {url} entre {flag_start} et {flag_end}"
    )


def get_flag_range(
    challenge_id: str,
    start_env: str | None,
    end_env: str | None,
) -> tuple[int, int]:
    if start_env is not None and end_env is not None:
        return int(start_env), int(end_env)

    fixed_value = CHALLENGE_FIXED_FLAGS.get(challenge_id)
    if fixed_value is not None:
        return fixed_value, fixed_value

    return CHALLENGE_FLAG_RANGES.get(
        challenge_id,
        (DEFAULT_FLAG_START, DEFAULT_FLAG_END),
    )


def is_fixed_flag_challenge(challenge_id: str) -> bool:
    return challenge_id in CHALLENGE_FIXED_FLAGS


def extract_flag_payload(flag_value: str) -> str:
    """Return the text found inside flag braces, when present."""
    match = re.search(r"\{\s*([^}]+?)\s*\}", flag_value)
    if match is None:
        return ""
    return match.group(1).strip()


def magic_word_for_challenge(
    challenge_id: str,
    flags: dict[str, str],
    current_magic_word: str,
) -> str:
    """Reuse the previous flag payload as Magic-Word for the next steps."""
    previous_flag_by_challenge = {
        "4": "3",
        "5": "4",
    }
    source_challenge = previous_flag_by_challenge.get(challenge_id)
    if source_challenge is None:
        return current_magic_word

    return extract_flag_payload(flags.get(source_challenge, "")) or current_magic_word


def main() -> int:
    logger.info("TP3 run started")
    options = _load_runtime_options()
    found_flags = _run_challenges(options)
    logger.info("TP3 run completed: %s", found_flags)
    return 0


def _load_runtime_options() -> RuntimeOptions:
    return RuntimeOptions(
        base_url=os.getenv("TP3_BASE_URL", DEFAULT_BASE_URL),
        challenge_ids=os.getenv("TP3_CHALLENGES", DEFAULT_CHALLENGES),
        flag_start_env=os.getenv("TP3_FLAG_START"),
        flag_end_env=os.getenv("TP3_FLAG_END"),
        retries_per_flag=int(
            os.getenv("TP3_RETRIES_PER_FLAG", str(DEFAULT_RETRIES_PER_FLAG))
        ),
        delay_seconds=float(os.getenv("TP3_DELAY_SECONDS", "0.2")),
        magic_word=os.getenv("TP3_MAGIC_WORD", ""),
    )


def _run_challenges(options: RuntimeOptions) -> dict[str, str]:
    flags: dict[str, str] = {}
    magic_word = options.magic_word

    for challenge_id, url in build_challenge_urls(
        options.base_url,
        options.challenge_ids,
    ).items():
        magic_word = magic_word_for_challenge(challenge_id, flags, magic_word)
        _configure_magic_word(challenge_id, magic_word)

        flag_window = _flag_window_for(challenge_id, options)
        _log_challenge_start(challenge_id, url, flag_window)

        flags[challenge_id] = solve_challenge(
            url,
            flag_start=flag_window.start,
            flag_end=flag_window.end,
            retries_per_flag=options.retries_per_flag,
            delay_seconds=options.delay_seconds,
        )
        logger.info("Challenge %s flag: %s", challenge_id, flags[challenge_id])

    return flags


def _flag_window_for(challenge_id: str, options: RuntimeOptions) -> FlagWindow:
    start, end = get_flag_range(
        challenge_id,
        options.flag_start_env,
        options.flag_end_env,
    )
    return FlagWindow(start=start, end=end)


def _configure_magic_word(challenge_id: str, magic_word: str) -> None:
    if challenge_id not in {"4", "5"} or not magic_word:
        return

    os.environ["TP3_MAGIC_WORD"] = magic_word
    logger.info("Magic-Word ready for challenge %s", challenge_id)


def _log_challenge_start(challenge_id: str, url: str, flag_window: FlagWindow) -> None:
    logger.info("Solving challenge %s at %s", challenge_id, url)
    if is_fixed_flag_challenge(challenge_id) and flag_window.start == flag_window.end:
        logger.info("Challenge %s uses flag value %s", challenge_id, flag_window.start)
        return

    logger.info("Challenge %s flag range: %s..%s", challenge_id, flag_window.start, flag_window.end)


def _log_attempt(
    *,
    url: str,
    attempt: int,
    total_attempts: int,
    flag_candidate: int,
    retry_index: int,
    retries_per_flag: int,
) -> None:
    logger.info(
        "Attempt %s/%s on %s | flag=%s | retry=%s/%s",
        attempt,
        total_attempts,
        url,
        flag_candidate,
        retry_index,
        retries_per_flag,
    )


def _pause_between_attempts(delay_seconds: float) -> None:
    if delay_seconds > 0:
        time.sleep(delay_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
