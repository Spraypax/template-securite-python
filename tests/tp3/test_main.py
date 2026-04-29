import importlib
import os

import src.tp3.main as tp3_main
from src.tp3.main import (
    DEFAULT_CHALLENGES,
    build_challenge_urls,
    extract_flag_payload,
    get_flag_range,
    is_fixed_flag_challenge,
    magic_word_for_challenge,
)


def test_default_challenges_run_all_tp3_in_order():
    assert DEFAULT_CHALLENGES == "1,2,3,4,5"
    assert list(build_challenge_urls("http://example.test").keys()) == [
        "1",
        "2",
        "3",
        "4",
        "5",
    ]


def test_build_challenge_urls():
    assert build_challenge_urls("http://example.test", "1,2") == {
        "1": "http://example.test/captcha1/",
        "2": "http://example.test/captcha2/",
    }


def test_get_flag_range_uses_challenge_defaults():
    assert get_flag_range("1", None, None) == (1000, 2000)
    assert get_flag_range("2", None, None) == (2000, 3000)
    assert get_flag_range("3", None, None) == (3000, 4000)
    assert get_flag_range("4", None, None) == (7629, 7629)
    assert get_flag_range("5", None, None) == (8632, 8632)


def test_fixed_flag_challenges_are_header_steps():
    assert not is_fixed_flag_challenge("3")
    assert is_fixed_flag_challenge("4")
    assert is_fixed_flag_challenge("5")


def test_get_flag_range_env_overrides_defaults():
    assert get_flag_range("2", "2100", "2200") == (2100, 2200)


def test_extract_flag_payload():
    assert extract_flag_payload("FLAG-3{N0_t1m3_to_Sl33p}") == "N0_t1m3_to_Sl33p"
    assert extract_flag_payload("Correct:)") == ""


def test_magic_word_for_challenge_uses_previous_flags_with_fallback():
    flags = {
        "3": "FLAG-3{N0_t1m3_to_Sl33p}",
        "4": "Correct:)",
    }
    assert magic_word_for_challenge("4", flags, "") == "N0_t1m3_to_Sl33p"
    assert magic_word_for_challenge("5", flags, "N0_t1m3_to_Sl33p") == "N0_t1m3_to_Sl33p"


def test_main_orchestrates_default_challenges(monkeypatch):
    calls = []

    def fake_solve_challenge(url, *, flag_start, flag_end, retries_per_flag, delay_seconds):
        challenge_id = url.rstrip("/").rsplit("captcha", 1)[1]
        calls.append(
            (
                challenge_id,
                flag_start,
                flag_end,
                os.environ.get("TP3_MAGIC_WORD", ""),
            )
        )
        return {
            "1": "FLAG-1{one}",
            "2": "FLAG-2{two}",
            "3": "FLAG-3{N0_t1m3_to_Sl33p}",
            "4": "Correct:)",
            "5": "FLAG-5{five}",
        }[challenge_id]

    monkeypatch.delenv("TP3_CHALLENGES", raising=False)
    monkeypatch.delenv("TP3_FLAG_START", raising=False)
    monkeypatch.delenv("TP3_FLAG_END", raising=False)
    monkeypatch.delenv("TP3_MAGIC_WORD", raising=False)
    monkeypatch.setattr(tp3_main, "solve_challenge", fake_solve_challenge)

    assert tp3_main.main() == 0
    assert [call[0] for call in calls] == ["1", "2", "3", "4", "5"]
    assert calls[0][1:3] == (1000, 2000)
    assert calls[1][1:3] == (2000, 3000)
    assert calls[2][1:3] == (3000, 4000)
    assert calls[3][1:3] == (7629, 7629)
    assert calls[4][1:3] == (8632, 8632)
    assert calls[3][3] == "N0_t1m3_to_Sl33p"
    assert calls[4][3] == "N0_t1m3_to_Sl33p"


def test_source_module_alias_imports_tp3_main():
    module = importlib.import_module("source.tp3.main")
    assert module.main is tp3_main.main
