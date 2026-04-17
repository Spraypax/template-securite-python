import argparse
from pathlib import Path

from tp2.utils.config import logger
from tp2.utils.analyzer import (
    parse_shellcode_from_text,
    get_shellcode_strings,
    get_pylibemu_analysis,
    get_capstone_analysis,
    get_llm_analysis,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", required=True, help="Fichier shellcode à analyser")
    args = parser.parse_args()

    # lecture du fichier
    raw = Path(args.file).read_text(encoding="utf-8", errors="ignore")
    shellcode = parse_shellcode_from_text(raw)

    logger.info(f"Testing shellcode of size {len(shellcode)}B")

    # analyses
    strings  = get_shellcode_strings(shellcode)
    pyl      = get_pylibemu_analysis(shellcode)
    cap      = get_capstone_analysis(shellcode)
    llm      = get_llm_analysis(shellcode, strings, pyl, cap)

    logger.info("Shellcode analysed !")

    # affichage des résultats
    print("\n=== STRINGS ===")
    print("\n".join(strings) if strings else "(none)")

    print("\n=== PYLIBEMU ===")
    print(pyl)

    print("\n=== CAPSTONE ===")
    print(cap)

    print("\n=== LLM ===")
    print(llm)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
