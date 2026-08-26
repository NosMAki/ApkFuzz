# Next Meeting Status

## 2026-08-26 — Campaign readiness pass

Before the 12h/72h runs we hardened the whole pipeline. Everything below is
implemented, compiled clean (`-Wall -Wextra`), and verified with a fast test
suite (`scripts/run-tests.sh`) and short rehearsals of the real campaign scripts.

### Two findings that changed the plan

1. **Disk burn (new, was not on the radar).** Every exec wrote a full APK, i.e.
   ~1.12 GB/s (90 exec/s × 12.4 MB). A 144h campaign is ~580 TB of writes; a
   consumer NVMe is rated 300–600 TB *total*. The campaign as designed would
   have consumed the drive's whole write endurance in one go, and the cache-
   masked "90 exec/s" was not a real sustained rate. **Fixed:** transient mutants
   go to tmpfs and are reaped continuously; only a ~200-byte patch is kept per
   mutant. Measured physical writes in a 20s run: ~flat.
2. **The seed was dead.** The mutator overwrote AFL's seed with
   `srand(time ^ addr)`, so `afl-fuzz -s` did nothing and (ASLR off) different
   seeds could collide into the *same* sequence — a parallel 6×12h would have
   silently been one run six times. **Fixed:** per-instance xoshiro256++ seeded
   from AFL's seed. Proven: same seed → identical sequence; different → different;
   holds under `setarch -R`.

### What is now done

- **Reproducibility (RNG):** deterministic, libc-independent, per-instance.
- **I/O:** tmpfs scratch + `reap-scratch.py` + patch saves + `apply-patch.py`
  (reconstructs and byte-verifies any mutant for triage).
- **Logging:** seed, iter, gen, compiled/effective/requested mode, locked, status
  enum, requested-vs-actual flips, multi-region spans; optional JSONL.
- **Field strategies:** crc/size gain 7 patterns × 4 targets. `both-different`
  desynchronizes local header vs central directory (the Janus / Master-Key case).
  Locked variants exist for the interesting cells.
- **Generation chaining:** mutants carry origin+gen; an unparsable descendant
  falls back to its origin (logged) instead of dead-ending; generation cap.
- **De-duplicated flips:** `flips=N` now means N distinct bit changes.
- **Corpus cleanup:** 6 files were really 2 apps (3 identical + 2 saved mutants);
  duplicates/mutant-seeds quarantined; `validate-corpus.py` rejects both; and
  `corpus.csv` records sha256/size/entry_count/manifest offset+size.
- **Tests:** 17 locked variants each verified to only touch the structure their
  name promises, plus the reproducibility checks. Runs in seconds, gates a build.
- **Campaign scripts split** into the two real questions, both with pinned seeds,
  explicit output dirs, machine-state capture, and a normalized CSV. Rehearsed.

### Decisions still needed at the meeting

| # | Decision | Our recommendation |
|---|---|---|
| A | Generation chaining vs always-from-origin | **chaining + fallback** (implemented as default; flip via env if desired) |
| B | Follow-up question: union-of-coverage vs mean±variance | **union** unless there is budget for 3×72h vs 18×12h |
| C | Corpus size + source, and the **small-APK** fetch | **10–14 APKs, mostly <1 MB, all from F-Droid** — needs a download + sign-off (see below) |
| D | Is DroidBot part of the evaluation, or is the harness enough | ask Aidan; it defines what "crash" means |
| E | CRC repair after mutation | **do not repair**; the field strategies make it an empirical question |

### The one open build item

The corpus is clean but still **2 large APKs (12 MB, 20 MB)**. The plan wants
small (<1 MB) APKs, which also makes the tmpfs approach comfortable at any exec
rate. Fetching them needs network access + a call on *which* apps, so it is left
for you: drop APKs into `Evaluation-SSBSE-2026/apk/`, then

```
python3 scripts/validate-corpus.py           # must pass (no dups, all usable)
python3 scripts/build-corpus-csv.py           # refresh corpus.csv
bash scripts/run-tests.sh                      # must stay green
```

### Go / no-go for the long runs

1. `bash scripts/run-tests.sh` → ALL TESTS PASSED
2. rehearse: `SECONDS_PER=60 REPEATS=2 scripts/run-mutator-comparison.sh` and
   `LONG_SECONDS=600 SHORT_SECONDS=100 scripts/run-duration-comparison.sh`
3. confirm the CSVs and `machine-state.txt` look right, and disk I/O stays low
4. only then raise the durations to 12h/72h

See `README_FUZZING.md` §"Reproducible campaigns" for the exact commands.

---

_Earlier status (pre-readiness pass) preserved in_ `docs/NEXT_MEETING_STATUS.prev.md`.
