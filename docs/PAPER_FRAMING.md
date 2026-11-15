# Paper framing and evidence boundary — 2026-11-15

This is draft paper language, not a new experiment. Use the linked protocols
and raw tables for denominators. No result here establishes an F-Droid defect,
app code coverage, or a signature bypass.

## Proposed claim

We evaluate **structure-preserving mutation of compressed Android binary XML**
as a way to construct installable APK test inputs and expose differences in
how manifest readers resolve raw and typed values. For one pinned F-Droid APK,
the first-generation one-bit space is small enough to enumerate completely;
AFL is an optional way to sample or extend that space, not the vulnerability
oracle. The current parser result is a *candidate class* and a small sampled
comparison. A full `aapt`/Androguard/Android reader-disagreement result awaits
direct measurement.

## Evidence table for a draft

| Claim | Evidence | Scope and limit |
| --- | --- | --- |
| 71,368 possible compressed-manifest one-bit flips; 16,024 accepted by the structural mutator | [enumeration.tsv](../results/gen1-enumeration-2026-11-15/enumeration.tsv), [protocol and review](../results/gen1-enumeration-2026-11-15/REVIEW.md) | Exhaustive only for this APK, fixed origin, first generation, and this acceptance rule. |
| 93/120 sampled accepted flips passed the recorded launch gate; 37/37 repeated classes agreed | [device review](../results/gen1-enumeration-2026-11-15/REVIEW.md) | One Android 10 emulator; gate v2; launch is not UI behavior, and repeat classes were re-derived after the earlier probe fix. |
| 3,339 inert flips and 1,123 raw-value-only flips by the static model | [classification.tsv](../results/gen1-flip-semantics-2026-11-15/classification.tsv), [refinement.tsv](../results/gen1-flip-semantics-2026-11-15/cosmetic-refinement.tsv), [semantic review](../results/gen1-flip-semantics-2026-11-15/REVIEW.md) | The 1,123 carry distinct raw and typed values; they are not 1,123 demonstrated three-reader divergences. |
| Androguard read the raw value rather than the model's typed value in 10 sampled raw-only cases; one `<category>` change blocked Android launcher resolution | [semantic review](../results/gen1-flip-semantics-2026-11-15/REVIEW.md) | Android's resolved values for the remaining attributes were not observed. No security impact established. |
| Three independent 120-second AFL seeds each preserved one provenance-verified exact mutant | [three-seed review](../results/paper-afl-seeds-2026-11-15/REVIEW.md) | Input-generation engineering check only; all three exact APK signatures failed, and no Android app behavior was measured. |
| Gate-v3 baseline/inert/crasher/baseline controls passed | [control review](../results/oracle-controls-2026-11-15/REVIEW.md) | One clean emulator session; the crasher produced one fingerprint in 15 log records during one install, not three independent reproductions. |

The old 72-hour random-range VM results, supplied separately by the user,
describe Python-harness executions and invalid selected APKs. They do not
support a claim that AFL executed or crashed F-Droid. The earlier 120-second
single-seed `manifest-axml-onebit` arm is an engineering feasibility check.
A subsequent [three-seed short check](../results/paper-afl-seeds-2026-11-15/REVIEW.md)
used identical arm settings and reports each seed separately; it still does
not estimate installable mutant or application-defect yield. Any AFL
performance or yield result presented as a scientific comparison needs at
least **three independent seeds**, per-seed results, and identical arm
settings. Do not pool historical runs with changed mutators, parents, gates,
or crash settings.

## Draft abstract paragraph

> We study one-bit mutation of a compressed Android binary XML manifest in a
> pinned F-Droid APK. We exhaustively classified 71,368 first-generation bit
> positions and found 16,024 outputs accepted by a structural manifest check.
> In a uniform sample of 120 accepted outputs, 93 passed an Android 10
> install-and-launch gate; 37 repeated probe classifications agreed after
> applying the same crash rule. Static semantic analysis identified 3,339
> inert flips and 1,123 flips that change only an attribute's raw value while
> leaving its typed value unchanged. Ten sampled raw-value cases were read
> differently by Androguard than by a typed-value model, and one changed
> Android launcher resolution. These results motivate a direct comparison of
> `aapt`, Androguard, and Android package-manager interpretation. We report
> parser observations and input admission separately from application
> defects; no F-Droid vulnerability is claimed.

## Controls and methodology requirements

Every future Android batch should name and hash an original/original or
matched signed-baseline control, sampled inert flips from the 3,339-member
negative class, and the existing known start-up crasher as a **gate positive
control**. Its expected crash is an invalid-input check, not an F-Droid
finding. Record each control's class and the emulator fingerprint before
interpreting mutants. Use the [oracle](ORACLE.md) for package-owned fatal
exceptions, three clean fingerprint reproductions, manifest-rejection
exclusions, ANRs, and infrastructure timeouts. A reader-disagreement batch
should record the exact attribute and observed value from each of `aapt`,
Androguard, and Android's package manager, with parse failures as separate
outcomes. The 1,123 total is the sampling frame, not the disagreement count.

A previously probed inert negative control is enumerated flip `9157`
(compressed offset `7402534`, bit `4`): exact SHA-256
`6c3a57168f7fbffaafb7deeb55812aec753bf08cfd075209252883f9636e5f03`,
prepared SHA-256
`6b64e48acd7de3f8efc6b32f5e467d70a2619d58cc4e638338041160fe0c6cce`.
The existing start-up-crash positive control is
`gen1_offline_ready:10433:iter15`: exact SHA-256
`a880e6f6d7dfc6efc39317a81c181e2a64dc0040ac8706976131ab555fb09306`,
prepared SHA-256
`506406a45c167f034d0f3bd0f17bed2149c78944b3a0fe9adf1c2ba63505d29b`.
These are **historical gate-v2 observations**; repeat them under gate v3
before using them to validate a new device batch.

For context, the original [Janus research](https://www.guardsquare.com/blog/new-android-vulnerability-allows-attackers-to-modify-apps-without-affecting-their-signatures-guardsquare)
and [Master Key analysis](https://www.saurik.com/masterkey1.html) show why
different interpretations of APK bytes can matter. Their mechanisms involve
APK/DEX or ZIP/signature interpretation, respectively; this work concerns
binary-XML attribute interpretation and does **not** demonstrate either
historical vulnerability mechanism.

## Material limitations

One APK and one Android 10 emulator, signed derivatives for device testing,
mostly start-up rather than UI behavior, and no application code coverage.
The historical launch data used gate v2; future gate v3 records richer crash
and ANR classes and should not be silently merged with the older labels.
