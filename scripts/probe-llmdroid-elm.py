#!/usr/bin/env python3
"""Check ELM key, model access, and LLMDroid's chat API before emulator work."""

import argparse
import sys
from pathlib import Path

from llmdroid_elm import DEFAULT_KEY_FILE, ELM_MODEL, ELM_URL, read_local_key, validate_base_url


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--key-file", type=Path, default=DEFAULT_KEY_FILE)
    parser.add_argument("--base-url", default=ELM_URL)
    parser.add_argument("--model", default=ELM_MODEL)
    args = parser.parse_args()
    try:
        base_url = validate_base_url(args.base_url)
        key = read_local_key(args.key_file)
        from openai import OpenAI

        client = OpenAI(api_key=key, base_url=base_url, timeout=30, max_retries=0)
        available = {item.id for item in client.models.list().data}
        if args.model not in available:
            print(f"ELM model is unavailable to this key: {args.model}", file=sys.stderr)
            return 2
        response = client.chat.completions.create(
            model=args.model,
            messages=[{"role": "user", "content": "Reply with OK."}],
            temperature=0,
            max_tokens=16,
        )
        if not response.choices or not response.choices[0].message.content:
            print("ELM returned no text response for the selected model.", file=sys.stderr)
            return 2
        print(f"ELM connection and chat model ready: {args.model}")
        return 0
    except (OSError, ValueError) as exc:
        print(f"ELM setup error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        # Avoid printing raw provider responses or request headers around a key.
        status = getattr(exc, "status_code", None)
        detail = f"HTTP {status}" if status else type(exc).__name__
        print(f"ELM API check failed: {detail}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
