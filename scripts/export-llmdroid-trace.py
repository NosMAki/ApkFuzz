#!/usr/bin/env python3
"""Export LLMDroid-Droidbot EventLog files as one ordered, replayable trace."""

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


LLMDROID_COMMIT = "5b5485cf195583370d49e353601985850210277e"


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def export(output_dir, apk):
    output_dir, apk = Path(output_dir).resolve(), Path(apk).resolve()
    events_dir = output_dir / "events"
    if not apk.is_file():
        raise ValueError(f"APK missing: {apk}")
    if not events_dir.is_dir():
        raise ValueError(f"LLMDroid events directory missing: {events_dir}")
    files = sorted(events_dir.glob("event_*.json"))
    if not files:
        raise ValueError("no LLMDroid action events found")
    events = []
    for index, path in enumerate(files):
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"invalid event JSON: {path.name}: {exc}") from exc
        if not isinstance(record, dict) or not isinstance(record.get("event"), dict):
            raise ValueError(f"event payload missing: {path.name}")
        action = record["event"]
        if not isinstance(action.get("event_type"), str) or not action["event_type"]:
            raise ValueError(f"event type missing: {path.name}")
        for state in ("start_state", "stop_state"):
            if not isinstance(record.get(state), str) or not record[state]:
                raise ValueError(f"{state} missing: {path.name}")
        events.append({
            "index": index,
            "source_file": path.name,
            "source_sha256": digest(path),
            "tag": record.get("tag"),
            "event_type": action["event_type"],
            "event": action,
            "start_state": record["start_state"],
            "stop_state": record["stop_state"],
            "event_str": record.get("event_str"),
        })
    return {
        "schema_version": 1,
        "framework": "LLMDroid-Droidbot",
        "llmdroid_commit": LLMDROID_COMMIT,
        "exported_utc": datetime.now(timezone.utc).isoformat(),
        "source_output": str(output_dir),
        "source_apk": str(apk),
        "source_apk_sha256": digest(apk),
        "action_count": len(events),
        "actions": events,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--llmdroid-output", required=True, type=Path)
    parser.add_argument("--apk", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error(f"output already exists: {args.output}")
    try:
        trace = export(args.llmdroid_output, args.apk)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8") as stream:
            json.dump(trace, stream, indent=2)
            stream.write("\n")
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(f"exported {trace['action_count']} actions: {args.output}")


if __name__ == "__main__":
    main()
