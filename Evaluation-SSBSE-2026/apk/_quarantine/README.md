# Quarantined corpus files (moved out of the fuzzing corpus)

These were removed from the active corpus during Phase 4 (corpus cleanup) because
they are not distinct apps. They are kept here (not deleted) so the change is
reversible. validate-corpus.py ignores this subdirectory.

- happymod.apk, weather-shalltry-group.apk
    byte-identical (same md5) to flashlight.apk -- the same file under three
    names. Only flashlight.apk stays in the corpus.
- F-Droid_00a40fa8.apk, F-Droid_00b48d62.apk
    saved *mutants* of F-Droid.apk that were accidentally kept as seeds. The
    fuzzer must start from clean originals, not from its own output.

To restore one, move it back up into ../ and re-run validate-corpus.py.
