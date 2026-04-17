import os
import logging

logger = logging.getLogger("TP2")

# TP2 settings
STRINGS_MIN_LEN = 4
CAPSTONE_BASE_ADDR = 0x1000

# OpenAI (optionnel)
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
