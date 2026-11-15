"""Shared ELM endpoint and local credential handling for LLMDroid tests."""

import os
import stat
from pathlib import Path
from urllib.parse import urlsplit


ELM_URL = "https://elm.edina.ac.uk/api/v1/"
ELM_MODEL = "mistralai/Mistral-Small-4-119B-2603"
DEFAULT_KEY_FILE = Path(__file__).resolve().parents[1] / "results/llmdroid-credentials/elm.key"


def validate_base_url(url):
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or
            parsed.password or parsed.query or parsed.fragment):
        raise ValueError("ELM base URL must be an HTTPS URL without credentials or query parameters")
    return url.rstrip("/") + "/"


def read_local_key(path):
    path = Path(path)
    meta = path.lstat()
    if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.getuid() or
            stat.S_IMODE(meta.st_mode) & 0o077 or meta.st_size > 512):
        raise ValueError("ELM key file must be owner-only regular file under 512 bytes")
    key = path.read_text(encoding="utf-8").strip()
    if not key:
        raise ValueError("ELM key file is empty")
    return key
