/*
 * cm_ApkVulFuzz2.c - Multi-strategy AFL++ custom mutator (parallel build).
 *
 * This is a SEPARATE mutator from the frozen baseline cm_ApkVulFuzz.c. It keeps
 * the same path-file workflow (AFL feeds a text file whose contents are a path
 * to a real APK; the mutator loads that APK, mutates it, writes the mutant, and
 * returns the mutant's path to AFL), but:
 *
 *   - randomness comes from a per-instance RNG seeded from AFL's seed, so a run
 *     is reproducible (afl-fuzz -s) and parallel instances never collide;
 *   - the mutant filename is deterministic (<base>_<seed>_<iter>.apk), so the
 *     same seed produces the same file names and contents;
 *   - each mutant carries a <mutant>.meta sidecar (origin + generation) so a
 *     later generation that no longer parses can fall back to its origin instead
 *     of dead-ending;
 *   - APKFUZZ_SAVE_DIR keeps a tiny PATCH (origin + byte edits) per mutant for
 *     post-run analysis, instead of a full multi-MB APK copy.
 *
 * Build as AFL custom mutator:  -D AFL_CM (links afl-fuzz.h)
 * Build as standalone tester:   -D APKFUZZ_STANDALONE (adds main())
 */
#include <stdint.h>

#ifdef AFL_CM
  #include "afl-fuzz.h"
#else
  typedef void    afl_state_t;
  typedef uint8_t u8;
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "zip2.h"
#include "strategies.h"

#define TARGET_ENTRY "AndroidManifest.xml"

typedef struct {
#ifdef AFL_CM
    afl_state_t   *afl;
#endif
    uint8_t       *out_buf;       /* whole APK buffer being mutated */
    size_t         buf_size;
    char          *fileout_name;  /* path of the mutant we write */
    char          *origin_path;   /* ultimate original this chain descends from */
    int            out_gen;       /* generation number of the mutant we produce */
    zip_layout_t   zl;
    apkfuzz_cfg_t  cfg;
    apkfuzz_rng_t  rng;
    uint64_t       seed;
    uint64_t       iter;
    apkfuzz_result_t res;
    mut_status_t   src_status;    /* source-resolution note (fallback / gen-cap) */
} my_mutator2_t;

/* ---- filename builder: <dir><base>_<seed>_<iter>.apk -----------------------
 * Deterministic: the same seed + iteration always yields the same name (and,
 * with the reproducible RNG, the same bytes). <base> is re-derived by stripping
 * any trailing _<digits>_<digits> so a mutant fed back in keeps the app base. */
static char *build_output_filename(const char *input_path, const char *out_dir,
                                   uint64_t seed, uint64_t iter) {
    const char *slash = strrchr(input_path, '/');
    const char *dir = "";
    const char *base = slash ? slash + 1 : input_path;
    char *dir_buf = NULL;

    if (out_dir && *out_dir) {
        size_t dl = strlen(out_dir);
        int add_slash = (dl == 0 || out_dir[dl - 1] != '/');
        dir_buf = malloc(dl + (add_slash ? 1 : 0) + 1);
        if (!dir_buf) return NULL;
        memcpy(dir_buf, out_dir, dl);
        if (add_slash) dir_buf[dl] = '/';
        dir_buf[dl + (add_slash ? 1 : 0)] = '\0';
        dir = dir_buf;
    } else if (slash) {
        size_t dir_len = (size_t)(slash - input_path) + 1;
        dir_buf = malloc(dir_len + 1);
        if (!dir_buf) return NULL;
        memcpy(dir_buf, input_path, dir_len);
        dir_buf[dir_len] = '\0';
        dir = dir_buf;
    }

    char name[512];
    strncpy(name, base, sizeof(name));
    name[sizeof(name) - 1] = '\0';

    char *dot = strrchr(name, '.');
    if (dot && strcmp(dot, ".apk") == 0) *dot = '\0';

    /* strip trailing _<digits> (and a second _<digits>) so we re-derive base */
    char *p = name + strlen(name) - 1;
    while (p > name && *p >= '0' && *p <= '9') p--;
    if (*p == '_') {
        *p = '\0';
        p--;
        while (p > name && *p >= '0' && *p <= '9') p--;
        if (*p == '_') *p = '\0';
    }

    size_t out_size = strlen(dir) + strlen(name) + 96;
    char *out = malloc(out_size);
    if (!out) { free(dir_buf); return NULL; }
    snprintf(out, out_size, "%s%s_%llu_%llu.apk", dir, name,
             (unsigned long long)seed, (unsigned long long)iter);
    free(dir_buf);
    return out;
}

static void free_state_buffers(my_mutator2_t *d) {
    if (d->out_buf)      { free(d->out_buf);      d->out_buf = NULL; }
    if (d->fileout_name) { free(d->fileout_name); d->fileout_name = NULL; }
    if (d->origin_path)  { free(d->origin_path);  d->origin_path = NULL; }
    d->buf_size = 0;
    d->out_gen  = 0;
}

static int write_file_exact(const char *path, const uint8_t *buf, size_t size,
                            const char *label, int required) {
    FILE *out = fopen(path, "wb");
    if (!out) {
        fprintf(stderr, "[apkfuzz] %s: failed to open %s\n", label, path);
        return required ? -1 : 0;
    }
    size_t wrote = fwrite(buf, 1, size, out);
    if (wrote != size) {
        fprintf(stderr, "[apkfuzz] %s: short write for %s (%zu/%zu)\n", label, path, wrote, size);
        fclose(out);
        return required ? -1 : 0;
    }
    if (fclose(out) != 0) {
        fprintf(stderr, "[apkfuzz] %s: failed to close %s\n", label, path);
        return required ? -1 : 0;
    }
    return 1;
}

/* Read whole file into a fresh malloc'd buffer. Returns NULL on failure. */
static uint8_t *slurp(const char *path, size_t *out_size) {
    FILE *in = fopen(path, "rb");
    if (!in) return NULL;
    if (fseek(in, 0, SEEK_END) != 0) { fclose(in); return NULL; }
    long size = ftell(in);
    if (size < 0) { fclose(in); return NULL; }
    rewind(in);
    uint8_t *buf = malloc((size_t)size ? (size_t)size : 1);
    if (!buf) { fclose(in); return NULL; }
    if (fread(buf, 1, (size_t)size, in) != (size_t)size) { free(buf); fclose(in); return NULL; }
    fclose(in);
    *out_size = (size_t)size;
    return buf;
}

/* Read a <mutant>.meta sidecar: origin path + generation. Returns 1 if found. */
static int read_meta(const char *apk_path, char *origin_out, size_t origin_cap, int *gen_out) {
    char meta[1100];
    if (snprintf(meta, sizeof(meta), "%s.meta", apk_path) >= (int)sizeof(meta)) return 0;
    FILE *f = fopen(meta, "r");
    if (!f) return 0;
    int got_origin = 0;
    char line[1100];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strncmp(line, "origin ", 7) == 0) {
            strncpy(origin_out, line + 7, origin_cap - 1);
            origin_out[origin_cap - 1] = '\0';
            got_origin = 1;
        } else if (strncmp(line, "gen ", 4) == 0) {
            *gen_out = atoi(line + 4);
        }
    }
    fclose(f);
    return got_origin;
}

static void write_meta(const char *apk_path, const char *origin, int gen) {
    char meta[1100];
    if (snprintf(meta, sizeof(meta), "%s.meta", apk_path) >= (int)sizeof(meta)) return;
    FILE *f = fopen(meta, "w");
    if (!f) return;
    fprintf(f, "origin %s\ngen %d\n", origin, gen);
    fclose(f);
}

/* Write a compact patch (origin + byte edits) for post-run analysis. Cheap:
 * no hashing of the multi-MB mutant in the hot path (apply-patch.py verifies). */
static void write_patch(const char *save_dir, const char *mutant_path,
                        const char *origin, const apkfuzz_cfg_t *cfg,
                        uint64_t seed, uint64_t iter, int gen,
                        const apkfuzz_result_t *res) {
    const char *bn = strrchr(mutant_path, '/');
    bn = bn ? bn + 1 : mutant_path;
    char path[1200];
    if (snprintf(path, sizeof(path), "%s/%s.patch", save_dir, bn) >= (int)sizeof(path)) {
        fprintf(stderr, "[apkfuzz] save-patch: path too long for %s\n", bn);
        return;
    }
    FILE *f = fopen(path, "w");
    if (!f) return;
    fprintf(f, "# apkfuzz-patch v1\n");
    fprintf(f, "origin %s\n", origin ? origin : "?");
    fprintf(f, "mode %s\n", cfg->mode_name);
    fprintf(f, "seed %llu\niter %llu\ngen %d\n",
            (unsigned long long)seed, (unsigned long long)iter, gen);
    fprintf(f, "status %s\n", apkfuzz_status_name(res->status));
    fprintf(f, "edits %d\n", res->edits.count);
    for (int i = 0; i < res->edits.count; i++) {
        fprintf(f, "%llu %02x %02x\n",
                (unsigned long long)res->edits.items[i].off,
                res->edits.items[i].oldv, res->edits.items[i].newv);
    }
    fclose(f);
}

/*
 * Resolve which bytes to mutate, honoring generation chaining:
 *   - read the input's .meta (origin + gen); a pristine seed is its own origin.
 *   - if the input's generation has hit the cap, mutate the origin instead.
 *   - load + analyze; if the chosen source does not parse but the origin does,
 *     fall back to the origin.
 * On return: d->out_buf/buf_size hold the bytes to mutate, d->zl is analyzed,
 * d->origin_path is the ultimate origin, d->out_gen is the mutant's generation.
 * res->status carries any fallback/cap note. Returns 0 on success (buffer
 * loaded, though zl.found may still be false for random-range), -1 on hard I/O.
 */
static int resolve_source(my_mutator2_t *d, const char *input_path) {
    free_state_buffers(d);
    d->src_status = MST_OK;

    char origin[1024];
    int  in_gen = 0;
    if (!read_meta(input_path, origin, sizeof(origin), &in_gen)) {
        strncpy(origin, input_path, sizeof(origin) - 1);
        origin[sizeof(origin) - 1] = '\0';
        in_gen = 0;
    }

    const char *source = input_path;
    d->out_gen = in_gen + 1;
    if (d->cfg.gen_cap > 0 && in_gen >= d->cfg.gen_cap) {
        source = origin;                 /* population would degrade; restart */
        d->out_gen = 1;
        d->src_status = MST_GEN_CAP_RESTART;
    }

    size_t sz = 0;
    uint8_t *buf = slurp(source, &sz);
    if (!buf) {
        /* chosen source unreadable; try the origin if it is a different file */
        if (strcmp(source, origin) != 0) {
            buf = slurp(origin, &sz);
            if (buf) { source = origin; d->out_gen = 1; d->src_status = MST_FALLBACK_TO_ORIGIN; }
        }
        if (!buf) { d->src_status = MST_LOAD_FAILED; return -1; }
    }
    d->out_buf = buf;
    d->buf_size = sz;

    int ok = zip2_analyze(d->out_buf, d->buf_size, TARGET_ENTRY, &d->zl) && d->zl.found;

    /* Parse failed on a descendant mutant: fall back to the origin so the chain
     * does not dead-end (measured via status=fallback_to_origin). */
    if (!ok && strcmp(source, origin) != 0) {
        size_t osz = 0;
        uint8_t *obuf = slurp(origin, &osz);
        if (obuf) {
            free(d->out_buf);
            d->out_buf = obuf;
            d->buf_size = osz;
            zip2_analyze(d->out_buf, d->buf_size, TARGET_ENTRY, &d->zl);
            d->out_gen = 1;
            d->src_status = MST_FALLBACK_TO_ORIGIN;
        }
    }

    d->origin_path = strdup(origin);
    if (!d->origin_path) { free_state_buffers(d); d->src_status = MST_ERROR; return -1; }

    d->fileout_name = build_output_filename(input_path, d->cfg.out_dir, d->seed, d->iter);
    if (!d->fileout_name) { free_state_buffers(d); d->src_status = MST_ERROR; return -1; }
    return 0;
}

/* ----------------------------- AFL interface ----------------------------- */
my_mutator2_t *afl_custom_init(afl_state_t *afl, unsigned int seed) {
    my_mutator2_t *d = calloc(1, sizeof(my_mutator2_t));
    if (!d) return NULL;
#ifdef AFL_CM
    d->afl = afl;
#else
    (void)afl;
#endif
    apkfuzz_cfg_load(&d->cfg);
    d->seed = (uint64_t)seed;
    d->iter = 0;
    apkfuzz_rng_seed(&d->rng, d->seed);      /* the ONLY seeding; no rand()/srand() */

    if (d->cfg.out_dir)  mkdir(d->cfg.out_dir, 0777);
    if (d->cfg.save_dir) mkdir(d->cfg.save_dir, 0777);
    return d;
}

void afl_custom_deinit(my_mutator2_t *d) {
    if (!d) return;
    free_state_buffers(d);
#ifdef AFL_CM
    d->afl = 0;
#endif
    free(d);
}

size_t afl_custom_fuzz(my_mutator2_t *d, uint8_t *buf, size_t buf_size,
                       u8 **out_buf, uint8_t *add_buf, size_t add_buf_size,
                       size_t max_size) {
    (void)add_buf; (void)add_buf_size;

    if (!d || !buf || buf_size < 5 || max_size < buf_size) {
        *out_buf = NULL; return 0;
    }

    /* buf holds the text of a path-file: extract the APK path. */
    char path[512];
    size_t len = (buf_size < sizeof(path) - 1) ? buf_size : sizeof(path) - 1;
    memcpy(path, buf, len);
    path[len] = '\0';
    path[strcspn(path, "\r\n")] = '\0';
    size_t plen = strlen(path);
    if (plen < 4 || strcmp(path + plen - 4, ".apk") != 0) { *out_buf = NULL; return 0; }

    d->iter++;

    /* Clean slate each call so a failure log never carries a previous iteration's
     * edits/regions/status. */
    apkfuzz_edits_reset(&d->res.edits);
    d->res.regions.count   = 0;
    d->res.requested_flips = 0;
    d->res.actual_flips    = 0;
    d->res.status          = MST_OK;
    d->res.used_pattern    = FP_INVALID;
    d->res.used_target     = FT_INVALID;

    if (resolve_source(d, path) != 0 || !d->out_buf || !d->fileout_name) {
        /* still log the failed attempt so dead-ends are measurable */
        d->res.status = d->src_status;
        apkfuzz_log_line(&d->cfg, path, d->fileout_name, d->seed, d->iter,
                         d->out_gen, &d->zl, 0, &d->res);
        *out_buf = NULL; return 0;
    }

    size_t out_len = strlen(d->fileout_name);
    if (out_len + 1 > max_size) { *out_buf = NULL; return 0; }

    int manifest_found = d->zl.found ? 1 : 0;
    int flips = -1;
    if (d->zl.found || d->cfg.mode == MODE_RANDOM_RANGE) {
        flips = apkfuzz_mutate(d->out_buf, d->buf_size, &d->zl, &d->cfg, &d->rng, &d->res);
        /* apkfuzz_mutate owns the mutation status; if it is clean, surface any
         * source-resolution note (fallback / gen-cap restart) instead. */
        if (d->res.status == MST_OK && d->src_status != MST_OK)
            d->res.status = d->src_status;
    } else {
        d->res.status = MST_NO_MANIFEST;
    }

    apkfuzz_log_line(&d->cfg, path, d->fileout_name, d->seed, d->iter,
                     d->out_gen, &d->zl, manifest_found, &d->res);

    if (flips < 0) { *out_buf = NULL; return 0; }

    if (write_file_exact(d->fileout_name, d->out_buf, d->buf_size, "mutant-output", 1) < 0) {
        d->res.status = MST_WRITE_FAILED;
        *out_buf = NULL; return 0;
    }
    /* sidecar so a later generation that no longer parses can find its origin */
    write_meta(d->fileout_name, d->origin_path, d->out_gen);

    /* Optionally keep a tiny patch (origin + edits) for post-run analysis. */
    if (d->cfg.save_dir) {
        write_patch(d->cfg.save_dir, d->fileout_name, d->origin_path,
                    &d->cfg, d->seed, d->iter, d->out_gen, &d->res);
    }

    char *nb = malloc(out_len + 1);
    if (!nb) { *out_buf = NULL; return 0; }
    memcpy(nb, d->fileout_name, out_len + 1);
    *out_buf = (u8 *)nb;
    return out_len;
}

/* ------------------------------- standalone ------------------------------ */
#ifdef APKFUZZ_STANDALONE
int main(int argc, char **argv) {
    const char *path = (argc > 1) ? argv[1] : "F-Droid.apk";
    uint8_t *buf = (uint8_t *)path;
    size_t file_size = strlen(path);
    u8 *out_buf = NULL;

    unsigned int seed = (argc > 2) ? (unsigned int)strtoul(argv[2], NULL, 0) : 12345u;
    my_mutator2_t *d = afl_custom_init(NULL, seed);
    if (!d) { fprintf(stderr, "init failed\n"); return 1; }

    fprintf(stderr, "[apkfuzz] compiled_mode=%s effective_mode=%s locked=%d seed=%u "
            "max_flips=%ld field_pattern=%s field_target=%s\n",
            d->cfg.compiled_mode, d->cfg.mode_name, d->cfg.locked, seed, d->cfg.max_flips,
            d->cfg.field_pattern_fixed ? apkfuzz_field_pattern_name(d->cfg.field_pattern) : "(random)",
            d->cfg.field_target_fixed ? apkfuzz_field_target_name(d->cfg.field_target) : "(random)");

    size_t n = afl_custom_fuzz(d, buf, file_size, &out_buf, NULL, 0, 512);
    if (!out_buf || n == 0) { fprintf(stderr, "fuzz failed\n"); afl_custom_deinit(d); return 2; }
    printf("%s\n", (char *)out_buf);
    free(out_buf);
    afl_custom_deinit(d);
    return 0;
}
#endif
