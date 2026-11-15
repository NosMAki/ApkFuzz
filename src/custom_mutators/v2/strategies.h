/*
 * strategies.h - Selectable mutation strategies for the multi-strategy mutator.
 *
 * Strategy can be chosen at runtime via APKFUZZ_MUTATOR_MODE, or fixed at
 * compile time with APKFUZZ_COMPILED_MODE + APKFUZZ_LOCK_COMPILED_MODE. Region
 * and intensity are tunable via APKFUZZ_SEGMENT_OFFSET / APKFUZZ_SEGMENT_SIZE /
 * APKFUZZ_MAX_FLIPS, with compile-time defaults for locked variants.
 *
 * Randomness comes from a per-instance xoshiro256++ RNG seeded from AFL's seed
 * (apkfuzz_rng_t). There is no global rand()/srand() state, so two runs with the
 * same AFL seed produce the same mutation sequence on any libc, and parallel
 * instances never collide.
 *
 * Every mutation records its byte edits into an apkfuzz_edits_t. That edit list
 * is the single source of truth used for (a) the actual-flip count, (b) the
 * per-region log, and (c) the saved patch. Nothing recomputes the diff.
 *
 * Opt-in per-fuzz logging via APKFUZZ_LOG=1 (+ optional APKFUZZ_LOG_FILE,
 * APKFUZZ_LOG_FORMAT=jsonl).
 */
#ifndef APKFUZZ_STRATEGIES_H
#define APKFUZZ_STRATEGIES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "zip2.h"

/* ------------------------------------------------------------------ */
/* Strategy modes                                                      */
/* ------------------------------------------------------------------ */
typedef enum {
    MODE_MANIFEST_BITFLIP = 0, /* flip bits across whole compressed manifest (== baseline) */
    MODE_MANIFEST_SEGMENT,     /* flip within [off, off+size) inside the manifest region   */
    MODE_MANIFEST_START,       /* flip within first third of the manifest region           */
    MODE_MANIFEST_MIDDLE,      /* flip within middle third of the manifest region          */
    MODE_MANIFEST_END,         /* flip within last third of the manifest region            */
    MODE_ZIP_LOCAL_HEADER,     /* flip within the manifest local file header               */
    MODE_ZIP_CENTRAL_DIR,      /* flip within the whole central directory                  */
    MODE_CRC_FIELDS,           /* perturb manifest CRC-32 fields (local + central)         */
    MODE_SIZE_FIELDS,          /* perturb manifest comp/uncomp size fields (local+central) */
    MODE_RANDOM_RANGE,         /* flip anywhere in the file (or [off,off+size) if set)     */
    MODE_MANIFEST_VALID_ONEBIT, /* one compressed bit with valid deflate + repaired CRC     */
    MODE_MANIFEST_AXML_ONEBIT,  /* valid-onebit that also keeps binary XML structure sound  */
    MODE_INVALID
} mut_mode_t;

/* ------------------------------------------------------------------ */
/* Field patterns / targets (crc-fields, size-fields)                  */
/* ------------------------------------------------------------------ */
/* How a 4-byte little-endian field is perturbed. */
typedef enum {
    FP_FLIP_BIT = 0, /* flip one random bit inside the field   */
    FP_ZERO,         /* write 0x00000000                       */
    FP_ONES,         /* write 0xFFFFFFFF                        */
    FP_PLUS_ONE,     /* value + 1 (LE)                         */
    FP_MINUS_ONE,    /* value - 1 (LE)                         */
    FP_RANDOM32,     /* four random bytes                      */
    FP_KEEP,         /* leave the field untouched              */
    FP_INVALID
} field_pattern_t;

/* Which copies of the field are touched: the local file header, the central
 * directory record, both identically, or both with independently drawn values.
 * BOTH_DIFFERENT is the research-interesting one: it desynchronizes what a ZIP
 * verifier (central dir) sees from what a loader (local header) sees. */
typedef enum {
    FT_LOCAL_ONLY = 0,
    FT_CD_ONLY,
    FT_BOTH_SAME,
    FT_BOTH_DIFFERENT,
    FT_INVALID
} field_target_t;

const char      *apkfuzz_field_pattern_name(field_pattern_t p);
field_pattern_t  apkfuzz_field_pattern_from_string(const char *s);
const char      *apkfuzz_field_target_name(field_target_t t);
field_target_t   apkfuzz_field_target_from_string(const char *s);

/* ------------------------------------------------------------------ */
/* RNG: xoshiro256++ seeded from splitmix64 (no global state)          */
/* ------------------------------------------------------------------ */
typedef struct { uint64_t s[4]; } apkfuzz_rng_t;

void     apkfuzz_rng_seed(apkfuzz_rng_t *r, uint64_t seed);
uint64_t apkfuzz_rng_next(apkfuzz_rng_t *r);
uint64_t apkfuzz_rng_below(apkfuzz_rng_t *r, uint64_t bound); /* unbiased [0,bound) */

/* ------------------------------------------------------------------ */
/* Edit list: the single source of truth for patch / log / flip count  */
/* ------------------------------------------------------------------ */
#define APKFUZZ_MAX_EDITS 256
typedef struct { uint64_t off; uint8_t oldv; uint8_t newv; } apkfuzz_edit_t;
typedef struct {
    apkfuzz_edit_t items[APKFUZZ_MAX_EDITS];
    int count;
    int overflow; /* set if more than APKFUZZ_MAX_EDITS distinct bytes were touched */
} apkfuzz_edits_t;

void apkfuzz_edits_reset(apkfuzz_edits_t *e);

/* ------------------------------------------------------------------ */
/* Named region spans (for the log)                                    */
/* ------------------------------------------------------------------ */
#define APKFUZZ_MAX_REGIONS 4
typedef struct { const char *name; uint64_t start; uint64_t end; } apkfuzz_region_t;
typedef struct { apkfuzz_region_t items[APKFUZZ_MAX_REGIONS]; int count; } apkfuzz_regions_t;

/* ------------------------------------------------------------------ */
/* Mutation status                                                     */
/* ------------------------------------------------------------------ */
typedef enum {
    MST_OK = 0,
    MST_NO_MANIFEST,        /* target entry not locatable and mode needs it     */
    MST_REGION_EMPTY,       /* computed region had no bytes to fuzz             */
    MST_LOAD_FAILED,        /* could not read the input APK                     */
    MST_WRITE_FAILED,       /* could not write the mutant                       */
    MST_FALLBACK_TO_ORIGIN, /* descendant unavailable or unparsable; used origin */
    MST_GEN_CAP_RESTART,    /* generation cap hit; restarted from the origin    */
    MST_NO_VALID_MUTATION,  /* bounded attempts found no valid manifest edit   */
    MST_ERROR
} mut_status_t;

const char *apkfuzz_status_name(mut_status_t s);

/* ------------------------------------------------------------------ */
/* Config                                                              */
/* ------------------------------------------------------------------ */
typedef struct {
    mut_mode_t      mode;            /* effective mode                          */
    const char     *mode_name;       /* effective mode name                     */
    const char     *requested_mode;  /* raw APKFUZZ_MUTATOR_MODE ("" if unset)  */
    const char     *compiled_mode;   /* APKFUZZ_COMPILED_MODE                    */
    int             locked;          /* APKFUZZ_LOCK_COMPILED_MODE               */

    long            seg_offset;      /* -1 = unset                              */
    long            seg_size;        /* -1 = unset                              */
    long            max_flips;       /* -1 = random 1..50 (baseline)            */

    field_pattern_t field_pattern;   /* crc/size: forced pattern if *_fixed     */
    field_target_t  field_target;    /* crc/size: forced target if *_fixed      */
    int             field_pattern_fixed;
    int             field_target_fixed;

    long            gen_cap;         /* APKFUZZ_GEN_CAP (default 20)             */
    int             no_dedup;        /* APKFUZZ_NO_DEDUP=1 -> allow dup flips    */

    int             do_log;          /* APKFUZZ_LOG                             */
    int             log_jsonl;       /* APKFUZZ_LOG_FORMAT=jsonl                */
    const char     *log_file;        /* APKFUZZ_LOG_FILE or default             */
    const char     *out_dir;         /* APKFUZZ_OUT_DIR (NULL = next to seed)   */
    const char     *save_dir;        /* APKFUZZ_SAVE_DIR (NULL = off)           */
} apkfuzz_cfg_t;

mut_mode_t   apkfuzz_mode_from_string(const char *s);
const char  *apkfuzz_mode_name(mut_mode_t m);
const char  *apkfuzz_compiled_mode(void);   /* the -D APKFUZZ_COMPILED_MODE value */
int          apkfuzz_mode_is_locked(void);  /* the -D APKFUZZ_LOCK_COMPILED_MODE  */

/* Load config from environment (defaults preserve baseline behavior). */
void apkfuzz_cfg_load(apkfuzz_cfg_t *cfg);

/* Full compressed-manifest validation used only by the opt-in valid modes.
 * `strict` additionally requires apkfuzz_axml_valid() on the decoded manifest. */
int apkfuzz_manifest_valid(const uint8_t *buf, size_t size, const zip_layout_t *zl,
                           int strict);

/* Structural check of a decoded Android binary XML manifest: chunk framing,
 * string-pool bounds and termination, string references, element nesting.
 * Must agree with scripts/android_binary_xml.py (tests/test_axml_structure.py).
 * Structure only: Android can still refuse a manifest that passes. */
int apkfuzz_axml_valid(const uint8_t *data, size_t size);

/* ------------------------------------------------------------------ */
/* Result of one mutation                                              */
/* ------------------------------------------------------------------ */
typedef struct {
    int              requested_flips; /* what the mode asked for                */
    int              actual_flips;    /* distinct changes actually applied      */
    mut_status_t     status;
    const char      *source_reason; /* source selection detail for the log      */
    field_pattern_t  used_pattern;    /* FP_INVALID for non-field modes         */
    field_target_t   used_target;     /* FT_INVALID for non-field modes         */
    apkfuzz_edits_t  edits;
    apkfuzz_regions_t regions;
} apkfuzz_result_t;

/*
 * Mutate `buf` in place according to cfg + zip layout, using `rng`. Fills `res`
 * with the edit list, region spans, status and flip counts. Returns the number
 * of edits applied (>=0), or -1 on hard error (res->status set accordingly).
 */
int apkfuzz_mutate(uint8_t *buf, size_t size, const zip_layout_t *zl,
                   apkfuzz_cfg_t *cfg, apkfuzz_rng_t *rng, apkfuzz_result_t *res);

/* Append one structured line describing this fuzz iteration (if do_log). */
void apkfuzz_log_line(const apkfuzz_cfg_t *cfg,
                      const char *src_path, const char *out_path,
                      uint64_t seed, uint64_t iter, int gen,
                      const zip_layout_t *zl, int manifest_found,
                      const apkfuzz_result_t *res);

#endif /* APKFUZZ_STRATEGIES_H */
