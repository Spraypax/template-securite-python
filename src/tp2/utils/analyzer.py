from __future__ import annotations

import os
import re
import textwrap
from typing import List

from .config import STRINGS_MIN_LEN, CAPSTONE_BASE_ADDR, OPENAI_API_KEY, OPENAI_MODEL


def parse_shellcode_from_text(text: str) -> bytes:
    """Lit le contenu d'un fichier texte et extrait les octets du shellcode."""
    t = text.strip()

    # format \xNN le plus courant
    if "\\x" in t:
        found = re.findall(r"\\x([0-9a-fA-F]{2})", t)
        if not found:
            raise ValueError("Aucun octet \\xHH trouvé.")
        return bytes(int(b, 16) for b in found)

    # sinon on essaie de lire du hex brut
    cleaned = re.sub(r"[^0-9a-fA-F]", "", t)
    if len(cleaned) < 2 or len(cleaned) % 2 != 0:
        raise ValueError("Hex brut invalide (longueur impaire ou vide).")
    return bytes.fromhex(cleaned)


def get_shellcode_strings(shellcode: bytes, min_len: int = STRINGS_MIN_LEN) -> List[str]:
    """Extrait les chaînes ASCII lisibles du shellcode (comme la commande strings)."""
    pat = rb"[ -~]{" + str(min_len).encode() + rb",}"
    results = []
    for m in re.finditer(pat, shellcode):
        results.append(m.group(0).decode("ascii", errors="ignore"))
    return results


def get_pylibemu_analysis(shellcode: bytes) -> str:
    """Émule le shellcode avec pylibemu et retourne le profil d'appels API."""
    try:
        import pylibemu  # type: ignore
    except Exception as e:
        return f"[pylibemu] indisponible: {e}"

    emu = pylibemu.Emulator()
    try:
        offset = emu.shellcode_getpc_test(shellcode)
        # getpc_test peut retourner -1, on force à 0 dans ce cas
        if offset < 0:
            offset = 0
        emu.prepare(shellcode, offset)
        emu.test()
        profile = getattr(emu, "emu_profile_output", "")
        if not profile:
            return "[pylibemu] aucun profil API détecté"
        return str(profile)
    except Exception as e:
        return f"[pylibemu] erreur: {e}"


def get_capstone_analysis(shellcode: bytes, base_addr: int = CAPSTONE_BASE_ADDR) -> str:
    """Désassemble le shellcode en x86 32 bits avec capstone."""
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32  # type: ignore
    except Exception as e:
        return f"[capstone] indisponible: {e}"

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    instrs = []
    try:
        for ins in md.disasm(shellcode, base_addr):
            instrs.append(f"0x{ins.address:08x}:\t{ins.mnemonic}\t{ins.op_str}")
    except Exception as e:
        return f"[capstone] erreur: {e}"

    if not instrs:
        return "[capstone] aucune instruction décodée"
    return "\n".join(instrs)


def get_llm_analysis(
    shellcode: bytes,
    strings: List[str],
    pylibemu_out: str,
    capstone_out: str
) -> str:
    """Envoie le contexte d'analyse à un LLM pour obtenir une explication."""

    # si pas de clé API, on fait une analyse rapide à la main
    if not OPENAI_API_KEY:
        guesses = []
        if any("cmd.exe" in s.lower() for s in strings):
            guesses.append("Probable exécution de commandes via cmd.exe.")
        if any("ws2_32" in s.lower() for s in strings):
            guesses.append("Indice réseau (ws2_32).")

        if guesses:
            return "[LLM fallback]\n" + "\n".join(f"- {g}" for g in guesses)
        return "[LLM fallback]\n- Manques d'indices"

    try:
        from openai import OpenAI  # type: ignore
        client = OpenAI()

        prompt = f"""
Explique ce que fait ce shellcode.

Format:
- Objectif
- Étapes
- IOCs (strings, ip/port si visible)
- Risque
- Incertitudes si besoin

strings: {strings}
pylibemu: {pylibemu_out[:2000]}
capstone: {capstone_out[:2000]}
"""
        resp = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[{"role": "user", "content": textwrap.dedent(prompt).strip()}],
        )
        return resp.choices[0].message.content.strip()

    except Exception as e:
        return f"[LLM] erreur: {e}"
