# SECURITY_REVIEW.md — Focused Security Engineering Checklist

> Use for a targeted review, not an automatic full audit of every change.

## Threat modeling and scope
- Identify assets, actors, trust boundaries, entry points, permissions, and affected data.
- Note authorized testing boundary and whether the code is a controlled research tool or a deployed service.

## Code review checklist
- Input validation: sizes, nesting, types, canonicalization, path traversal, archive bombs, malformed encodings.
- Injection: shell/SQL/template/path/log; avoid constructing commands with attacker-controlled strings.
- Authentication and authorization: object-level access, privilege boundaries, session lifecycle.
- Secrets and privacy: no hardcoded credentials, unsafe logs, or unintended upload/exfiltration.
- Supply chain: pinned/verified dependencies as project permits; review new packages and scripts.
- Memory/concurrency: buffer bounds, lifetime/ownership, races, error handling, resource cleanup.
- Network: trust decisions, TLS validation, DNS, timeouts, retries, protocol parsing.
- Android/APK: package provenance, exported components, intents, permissions, WebView, IPC, file URI and storage access where applicable.
- Fuzz harness: confirm harness rejects invalid setup, has deterministic input handling, no unsafe external side effects, and correctly distinguishes target failures from harness failures.

## Findings (one per issue)
- File:line and data/control flow
- Evidence and minimum reproduction
- Reachability / preconditions / trust boundary
- Impact (observed versus plausible) and confidence
- Root cause and smallest practical fix
- Test demonstrating the fix

## Exit criteria
- No unexplained high-risk change in the touched area.
- Appropriate negative tests added or a specific reason documented.
- Re-run relevant tests and check changed files for secrets.

References: OWASP Cheat Sheet Series; OWASP Web Security Testing Guide; CWE.
