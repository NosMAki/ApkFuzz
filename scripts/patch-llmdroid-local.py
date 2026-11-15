#!/usr/bin/env python3
"""Apply the minimal local credential guard to the pinned LLMDroid checkout.

The upstream checkout stays outside this repository. This script deliberately
refuses unknown revisions or source layouts instead of editing arbitrary code.
"""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


COMMIT = "5b5485cf195583370d49e353601985850210277e"
SOURCE_SHA256 = "5ca5033780576808a3aed8d1b0188ad95fe4be1c23d659a3f3f283aad84464bf"
SOURCE = Path("LLMDroid-Droidbot/droidbot/policy/llm_agent.py")
CONFIG = Path("LLMDroid-Droidbot/config.json")
ADB_SOURCE = Path("LLMDroid-Droidbot/droidbot/adapter/adb.py")
ADB_SHA256 = "b47b9af0eea181aa0890e32acaea7f19e0a87db00fa81b89e47302ad7becb000"
OLD_ACCESSIBILITY = "        return r.strip().split(\":\") if r.strip() != '' else []"
NEW_ACCESSIBILITY = "        return r.strip().split(\":\") if r.strip() not in ('', 'null') else []"
OLD_LOG = '            self.logger.info(f"config.json:\\n{json.dumps(config, indent=4)}\\n")'
NEW_LOG = ('            self.logger.info("config.json: %s", '
           'json.dumps({**config, "ApiKey": "<redacted>"}, indent=4))')
OLD_KEY = "            self.__api_key = config['ApiKey']"
NEW_KEY = ('            self.__api_key = os.environ.get("APKVULFUZZ_LLM_API_KEY")\n'
           '            if not self.__api_key:\n'
           '                raise ValueError("APKVULFUZZ_LLM_API_KEY is required for LLMDroid exploration")')
OLD_USAGE = "        response = chat_completion.choices[0].message.content"
NEW_USAGE = (OLD_USAGE + '\n'
             '        usage = getattr(chat_completion, "usage", None)\n'
             '        with open(os.path.join(self.__app.output_dir, "LLM-Usage.jsonl"), "a") as usage_file:\n'
             '            usage_file.write(json.dumps({\n'
             '                "model": LLMAgent.MODEL_STR,\n'
             '                "attempts": try_times + 1,\n'
             '                "prompt_tokens": getattr(usage, "prompt_tokens", None),\n'
             '                "completion_tokens": getattr(usage, "completion_tokens", None),\n'
             '                "total_tokens": getattr(usage, "total_tokens", None),\n'
             '                "elapsed_seconds": round(time.time() - begin_stamp, 5),\n'
             '            }) + "\\n")')


def patch_source(content):
    if NEW_LOG in content and NEW_KEY in content:
        if NEW_USAGE in content:
            return content
        if content.count(OLD_USAGE) != 1:
            raise ValueError("expected LLM response code not found exactly once")
        return content.replace(OLD_USAGE, NEW_USAGE)
    if hashlib.sha256(content.encode()).hexdigest() != SOURCE_SHA256:
        raise ValueError("LLMDroid source differs from the pinned unpatched version")
    if (content.count(OLD_LOG) != 1 or content.count(OLD_KEY) != 1 or
            content.count(OLD_USAGE) != 1):
        raise ValueError("expected credential code not found exactly once")
    return (content.replace(OLD_LOG, NEW_LOG).replace(OLD_KEY, NEW_KEY)
            .replace(OLD_USAGE, NEW_USAGE))


def patch_adb(content):
    if NEW_ACCESSIBILITY in content:
        return content
    if hashlib.sha256(content.encode()).hexdigest() != ADB_SHA256:
        raise ValueError("LLMDroid ADB adapter differs from the pinned unpatched version")
    if content.count(OLD_ACCESSIBILITY) != 1:
        raise ValueError("expected accessibility setting parser not found exactly once")
    return content.replace(OLD_ACCESSIBILITY, NEW_ACCESSIBILITY)


def patch_checkout(checkout):
    checkout = Path(checkout)
    commit = subprocess.run(["git", "-C", str(checkout), "rev-parse", "HEAD"],
                            capture_output=True, text=True, check=True).stdout.strip()
    if commit != COMMIT:
        raise ValueError(f"unsupported LLMDroid commit: {commit}")
    source = checkout / SOURCE
    source.write_text(patch_source(source.read_text(encoding="utf-8")), encoding="utf-8")
    adb_source = checkout / ADB_SOURCE
    adb_source.write_text(patch_adb(adb_source.read_text(encoding="utf-8")),
                          encoding="utf-8")
    config_path = checkout / CONFIG
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["ApiKey"] = ""
    config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    return source


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checkout", type=Path)
    args = parser.parse_args()
    try:
        source = patch_checkout(args.checkout)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        parser.error(str(exc))
    print(f"local credential guard ready: {source}")


if __name__ == "__main__":
    main()
