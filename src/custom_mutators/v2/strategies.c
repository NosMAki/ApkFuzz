/*
 * strategies.c - Implementation of the selectable mutation strategies.
 */
#include "strategies.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <zlib.h>

/* ---- compile-time strategy locking (for locked campaign variants) ---- */
#ifndef APKFUZZ_COMPILED_MODE
#define APKFUZZ_COMPILED_MODE "manifest-bitflip"
#endif
#ifndef APKFUZZ_LOCK_COMPILED_MODE
#define APKFUZZ_LOCK_COMPILED_MODE 0
#endif
#ifndef APKFUZZ_COMPILED_SEGMENT_OFFSET
#define APKFUZZ_COMPILED_SEGMENT_OFFSET -1
#endif
#ifndef APKFUZZ_COMPILED_SEGMENT_SIZE
#define APKFUZZ_COMPILED_SEGMENT_SIZE -1
#endif
#ifndef APKFUZZ_COMPILED_MAX_FLIPS
#define APKFUZZ_COMPILED_MAX_FLIPS -1
#endif
#ifndef APKFUZZ_COMPILED_FIELD_PATTERN
#define APKFUZZ_COMPILED_FIELD_PATTERN ""   /* "" -> random per fuzz */
#endif
#ifndef APKFUZZ_COMPILED_FIELD_TARGET
#define APKFUZZ_COMPILED_FIELD_TARGET ""    /* "" -> random per fuzz */
#endif

/* ------------------------------------------------------------------ */
/* Name <-> enum tables                                                */
/* ------------------------------------------------------------------ */
static const char *k_mode_names[] = {
    "manifest-bitflip", "manifest-segment", "manifest-start",
    "manifest-middle",  "manifest-end",     "zip-local-header",
    "zip-central-directory", "crc-fields",  "size-fields",
    "random-range", "manifest-valid-onebit", "manifest-axml-onebit"
};

const char *apkfuzz_mode_name(mut_mode_t m) {
    if (m < 0 || m >= MODE_INVALID) return "invalid";
    return k_mode_names[m];
}

mut_mode_t apkfuzz_mode_from_string(const char *s) {
    if (!s || !*s) return MODE_MANIFEST_BITFLIP;
    for (int i = 0; i < (int)MODE_INVALID; i++) {
        if (strcmp(s, k_mode_names[i]) == 0) return (mut_mode_t)i;
    }
    if (strcmp(s, "central-directory") == 0) return MODE_ZIP_CENTRAL_DIR;
    if (strcmp(s, "local-header") == 0)      return MODE_ZIP_LOCAL_HEADER;
    if (strcmp(s, "random") == 0)            return MODE_RANDOM_RANGE;
    return MODE_INVALID;
}

const char *apkfuzz_compiled_mode(void) { return APKFUZZ_COMPILED_MODE; }
int         apkfuzz_mode_is_locked(void) { return APKFUZZ_LOCK_COMPILED_MODE; }

static const char *k_pattern_names[] = {
    "flip-bit", "zero", "ones", "plus-one", "minus-one", "random32", "keep"
};
const char *apkfuzz_field_pattern_name(field_pattern_t p) {
    if (p < 0 || p >= FP_INVALID) return "invalid";
    return k_pattern_names[p];
}
field_pattern_t apkfuzz_field_pattern_from_string(const char *s) {
    if (!s || !*s) return FP_INVALID;
    for (int i = 0; i < (int)FP_INVALID; i++)
        if (strcmp(s, k_pattern_names[i]) == 0) return (field_pattern_t)i;
    return FP_INVALID;
}

static const char *k_target_names[] = {
    "local-only", "cd-only", "both-same", "both-different"
};
const char *apkfuzz_field_target_name(field_target_t t) {
    if (t < 0 || t >= FT_INVALID) return "invalid";
    return k_target_names[t];
}
field_target_t apkfuzz_field_target_from_string(const char *s) {
    if (!s || !*s) return FT_INVALID;
    for (int i = 0; i < (int)FT_INVALID; i++)
        if (strcmp(s, k_target_names[i]) == 0) return (field_target_t)i;
    return FT_INVALID;
}

static const char *k_status_names[] = {
    "ok", "no_manifest", "region_empty", "load_failed",
    "write_failed", "fallback_to_origin", "gen_cap_restart", "no_valid_mutation", "error"
};
const char *apkfuzz_status_name(mut_status_t s) {
    if (s < 0 || s > MST_ERROR) return "error";
    return k_status_names[s];
}

/* ------------------------------------------------------------------ */
/* RNG: splitmix64 seed expansion -> xoshiro256++                      */
/* ------------------------------------------------------------------ */
static uint64_t splitmix64(uint64_t *x) {
    uint64_t z = (*x += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

void apkfuzz_rng_seed(apkfuzz_rng_t *r, uint64_t seed) {
    uint64_t sm = seed ? seed : 0xA5A5A5A5DEADBEEFULL;
    for (int i = 0; i < 4; i++) r->s[i] = splitmix64(&sm);
    /* xoshiro must not be all-zero; splitmix output never is here, but guard. */
    if (!(r->s[0] | r->s[1] | r->s[2] | r->s[3])) r->s[0] = 1;
}

static inline uint64_t rotl(uint64_t x, int k) { return (x << k) | (x >> (64 - k)); }

uint64_t apkfuzz_rng_next(apkfuzz_rng_t *r) {
    uint64_t *s = r->s;
    const uint64_t result = rotl(s[0] + s[3], 23) + s[0];
    const uint64_t t = s[1] << 17;
    s[2] ^= s[0];
    s[3] ^= s[1];
    s[1] ^= s[2];
    s[0] ^= s[3];
    s[2] ^= t;
    s[3] = rotl(s[3], 45);
    return result;
}

uint64_t apkfuzz_rng_below(apkfuzz_rng_t *r, uint64_t bound) {
    if (bound == 0) return 0;
    /* Unbiased: reject the short tail so every value in [0,bound) is equally likely. */
    const uint64_t threshold = (uint64_t)(-bound) % bound; /* 2^64 mod bound */
    for (;;) {
        uint64_t x = apkfuzz_rng_next(r);
        if (x >= threshold) return x % bound;
    }
}

/* ------------------------------------------------------------------ */
/* Edit list                                                           */
/* ------------------------------------------------------------------ */
void apkfuzz_edits_reset(apkfuzz_edits_t *e) {
    e->count = 0;
    e->overflow = 0;
}

/* Record buf[off] changing to newv. If off was already edited this round,
 * update newv but keep the original oldv, so a byte hit twice stays one edit
 * with a correct original->final delta. */
static void edits_record(apkfuzz_edits_t *e, uint64_t off, uint8_t oldv, uint8_t newv) {
    for (int i = 0; i < e->count; i++) {
        if (e->items[i].off == off) { e->items[i].newv = newv; return; }
    }
    if (e->count >= APKFUZZ_MAX_EDITS) { e->overflow = 1; return; }
    e->items[e->count].off  = off;
    e->items[e->count].oldv = oldv;
    e->items[e->count].newv = newv;
    e->count++;
}

static void regions_add(apkfuzz_regions_t *rg, const char *name, uint64_t s, uint64_t e) {
    if (rg->count >= APKFUZZ_MAX_REGIONS) return;
    rg->items[rg->count].name  = name;
    rg->items[rg->count].start = s;
    rg->items[rg->count].end   = e;
    rg->count++;
}

/* ------------------------------------------------------------------ */
/* Config loading                                                      */
/* ------------------------------------------------------------------ */
static long env_long(const char *name, long dflt) {
    const char *v = getenv(name);
    if (!v || !*v) return dflt;
    char *end = NULL;
    long r = strtol(v, &end, 0);
    if (end == v) return dflt;
    return r;
}

void apkfuzz_cfg_load(apkfuzz_cfg_t *cfg) {
    if (!cfg) return;
    memset(cfg, 0, sizeof(*cfg));

    const char *req = getenv("APKFUZZ_MUTATOR_MODE");
    cfg->requested_mode = (req && *req) ? req : "";
    cfg->compiled_mode  = APKFUZZ_COMPILED_MODE;
    cfg->locked         = APKFUZZ_LOCK_COMPILED_MODE;

    const char *mode_s = req;
#if APKFUZZ_LOCK_COMPILED_MODE
    mode_s = APKFUZZ_COMPILED_MODE;          /* locked build ignores the env */
#else
    if (!mode_s || !*mode_s) mode_s = APKFUZZ_COMPILED_MODE;
#endif
    cfg->mode = apkfuzz_mode_from_string(mode_s);
    if (cfg->mode == MODE_INVALID) {
        fprintf(stderr,
                "[apkfuzz] WARNING: unknown mode '%s', falling back to manifest-bitflip\n",
                mode_s ? mode_s : "");
        cfg->mode = MODE_MANIFEST_BITFLIP;
    }
    cfg->mode_name  = apkfuzz_mode_name(cfg->mode);
    cfg->seg_offset = env_long("APKFUZZ_SEGMENT_OFFSET", APKFUZZ_COMPILED_SEGMENT_OFFSET);
    cfg->seg_size   = env_long("APKFUZZ_SEGMENT_SIZE",   APKFUZZ_COMPILED_SEGMENT_SIZE);
    cfg->max_flips  = env_long("APKFUZZ_MAX_FLIPS",      APKFUZZ_COMPILED_MAX_FLIPS);
    cfg->gen_cap    = env_long("APKFUZZ_GEN_CAP",        20);

    /* Field pattern/target: env overrides compiled default; empty => random per fuzz. */
    const char *fp_env = getenv("APKFUZZ_FIELD_PATTERN");
    const char *fp_s   = (fp_env && *fp_env) ? fp_env : APKFUZZ_COMPILED_FIELD_PATTERN;
    field_pattern_t fp = apkfuzz_field_pattern_from_string(fp_s);
    cfg->field_pattern       = (fp != FP_INVALID) ? fp : FP_FLIP_BIT;
    cfg->field_pattern_fixed = (fp != FP_INVALID);

    const char *ft_env = getenv("APKFUZZ_FIELD_TARGET");
    const char *ft_s   = (ft_env && *ft_env) ? ft_env : APKFUZZ_COMPILED_FIELD_TARGET;
    field_target_t ft = apkfuzz_field_target_from_string(ft_s);
    cfg->field_target       = (ft != FT_INVALID) ? ft : FT_BOTH_SAME;
    cfg->field_target_fixed = (ft != FT_INVALID);

    const char *nd = getenv("APKFUZZ_NO_DEDUP");
    cfg->no_dedup = (nd && *nd && strcmp(nd, "0") != 0) ? 1 : 0;

    const char *lg = getenv("APKFUZZ_LOG");
    cfg->do_log = (lg && *lg && strcmp(lg, "0") != 0) ? 1 : 0;
    const char *lfmt = getenv("APKFUZZ_LOG_FORMAT");
    cfg->log_jsonl = (lfmt && strcmp(lfmt, "jsonl") == 0) ? 1 : 0;
    const char *lf = getenv("APKFUZZ_LOG_FILE");
    cfg->log_file = (lf && *lf) ? lf : "apkfuzz_mutator.log";
    const char *od = getenv("APKFUZZ_OUT_DIR");
    cfg->out_dir = (od && *od) ? od : NULL;
    const char *sd = getenv("APKFUZZ_SAVE_DIR");
    cfg->save_dir = (sd && *sd) ? sd : NULL;
}

/* ------------------------------------------------------------------ */
/* Bit flipping with de-duplication                                    */
/* ------------------------------------------------------------------ */
static int pick_flip_count(apkfuzz_cfg_t *cfg, apkfuzz_rng_t *rng) {
    if (cfg->max_flips >= 0) return (int)cfg->max_flips;
    return (int)apkfuzz_rng_below(rng, 50) + 1;   /* baseline: 1..50 */
}

/* Flip `n` distinct random bits within [start,end). Records each into `edits`.
 * Returns the number of distinct bits actually flipped (== n unless the region
 * is too small to supply n distinct bits, or dedup is disabled). */
static int flip_bits_in_range(uint8_t *buf, uint64_t start, uint64_t end, int n,
                              apkfuzz_rng_t *rng, apkfuzz_edits_t *edits,
                              int no_dedup) {
    if (end <= start || n <= 0) return 0;
    uint64_t range = end - start;
    uint64_t bitspace = range * 8;

    if (no_dedup) {
        int done = 0;
        for (int k = 0; k < n; k++) {
            uint64_t off = start + apkfuzz_rng_below(rng, range);
            int bit = (int)apkfuzz_rng_below(rng, 8);
            uint8_t oldv = buf[off];
            buf[off] ^= (uint8_t)(1u << bit);
            edits_record(edits, off, oldv, buf[off]);
            done++;
        }
        return done;
    }

    int want = n;
    if ((uint64_t)want > bitspace) want = (int)bitspace; /* can't exceed distinct bits */

    /* Track chosen (off,bit) keys to guarantee distinct flips. want is bounded by
     * max_flips (<=50 in practice) so a small stack set + linear scan is ample. */
    uint64_t chosen[APKFUZZ_MAX_EDITS];
    int nchosen = 0;
    int cap = (want < APKFUZZ_MAX_EDITS) ? want : APKFUZZ_MAX_EDITS;

    int done = 0;
    int attempts = 0;
    int max_attempts = cap * 8 + 128;    /* fallback so tiny regions can't spin */
    while (done < cap && attempts < max_attempts) {
        attempts++;
        uint64_t off = start + apkfuzz_rng_below(rng, range);
        int bit = (int)apkfuzz_rng_below(rng, 8);
        uint64_t key = (off << 3) | (uint64_t)bit;
        int dup = 0;
        for (int i = 0; i < nchosen; i++) if (chosen[i] == key) { dup = 1; break; }
        if (dup) continue;
        chosen[nchosen++] = key;
        uint8_t oldv = buf[off];
        buf[off] ^= (uint8_t)(1u << bit);
        edits_record(edits, off, oldv, buf[off]);
        done++;
    }
    return done;
}

/* ------------------------------------------------------------------ */
/* Region computation per range-style mode                             */
/* ------------------------------------------------------------------ */
static int compute_region(size_t size, const zip_layout_t *zl,
                          apkfuzz_cfg_t *cfg, uint64_t *rs, uint64_t *re) {
    uint64_t ms = zl->data_start, me = zl->data_end;
    uint64_t mlen = me - ms;

    switch (cfg->mode) {
        case MODE_MANIFEST_BITFLIP:
            *rs = ms; *re = me; return 1;
        case MODE_MANIFEST_SEGMENT: {
            uint64_t off = (cfg->seg_offset >= 0) ? (uint64_t)cfg->seg_offset : 0;
            uint64_t sz  = (cfg->seg_size   >= 0) ? (uint64_t)cfg->seg_size   : mlen;
            uint64_t s = ms + off;
            if (s > me) s = me;
            uint64_t e = s + sz;
            if (e > me) e = me;
            *rs = s; *re = e; return 1;
        }
        case MODE_MANIFEST_START:
            *rs = ms; *re = ms + (mlen / 3 ? mlen / 3 : mlen); return 1;
        case MODE_MANIFEST_MIDDLE:
            *rs = ms + mlen / 3; *re = ms + (2 * mlen) / 3;
            if (*re <= *rs) *re = me;
            return 1;
        case MODE_MANIFEST_END:
            *rs = ms + (2 * mlen) / 3; *re = me;
            if (*re <= *rs) *rs = ms;
            return 1;
        case MODE_ZIP_LOCAL_HEADER:
            *rs = zl->local_header_off; *re = zl->local_data_off; return 1;
        case MODE_ZIP_CENTRAL_DIR:
            *rs = zl->cd_start; *re = zl->cd_end; return 1;
        case MODE_RANDOM_RANGE: {
            uint64_t off = (cfg->seg_offset >= 0) ? (uint64_t)cfg->seg_offset : 0;
            uint64_t sz  = (cfg->seg_size   >= 0) ? (uint64_t)cfg->seg_size   : (size - off);
            uint64_t s = off, e = off + sz;
            if (s > size) s = size;
            if (e > size) e = size;
            *rs = s; *re = e; return 1;
        }
        case MODE_CRC_FIELDS:
        case MODE_SIZE_FIELDS:
        default:
            return 0;
    }
}

static const char *region_name_for(mut_mode_t m) {
    switch (m) {
        case MODE_MANIFEST_BITFLIP: return "manifest";
        case MODE_MANIFEST_SEGMENT: return "manifest_segment";
        case MODE_MANIFEST_START:   return "manifest_start";
        case MODE_MANIFEST_MIDDLE:  return "manifest_middle";
        case MODE_MANIFEST_END:     return "manifest_end";
        case MODE_ZIP_LOCAL_HEADER: return "local_header";
        case MODE_ZIP_CENTRAL_DIR:  return "central_directory";
        case MODE_RANDOM_RANGE:     return "file_range";
        default:                    return "region";
    }
}

/* ------------------------------------------------------------------ */
/* Field patterns (crc/size)                                           */
/* ------------------------------------------------------------------ */
static uint32_t rd32le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint16_t rd16le(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

/* ------------------------------------------------------------------ */
/* Android binary XML structure (mirror of scripts/android_binary_xml.py) */
/* ------------------------------------------------------------------ */
#define AXML_NO_STRING 0xFFFFFFFFu

static int axml_ref(const uint8_t *d, size_t off, uint32_t strings) {
    uint32_t v = rd32le(d + off);
    return v == AXML_NO_STRING || v < strings;
}

/* The pool occupies [start, start + size); the caller checked that range. */
static int axml_string_pool(const uint8_t *d, size_t start, uint32_t size,
                            uint32_t *count_out) {
    if (rd16le(d + start + 2) != 28 || size < 28) return 0;
    uint32_t count = rd32le(d + start + 8), styles = rd32le(d + start + 12);
    uint32_t flags = rd32le(d + start + 16);
    uint32_t strings_start = rd32le(d + start + 20);
    uint32_t styles_start = rd32le(d + start + 24);
    if (count > size / 4 || styles > size / 4) return 0;
    uint64_t table_end = 28 + 4 * ((uint64_t)count + styles);
    if (table_end > size || strings_start < table_end || strings_start > size) return 0;
    uint64_t data_len = size - strings_start;
    if (styles) {
        if (styles_start < strings_start || styles_start > size) return 0;
        data_len = styles_start - strings_start;
    }
    const uint8_t *base = d + start + strings_start;
    int utf8 = (flags & (1u << 8)) != 0;
    for (uint32_t i = 0; i < count; i++) {
        uint64_t off = rd32le(d + start + 28 + 4 * (size_t)i);
        uint64_t length = 0;
        if (utf8) {
            for (int k = 0; k < 2; k++) {   /* UTF-16 length, then byte length */
                if (off >= data_len) return 0;
                length = base[off++];
                if (length & 0x80) {
                    if (off >= data_len) return 0;
                    length = ((length & 0x7F) << 8) | base[off++];
                }
            }
            if (off + length >= data_len || base[off + length] != 0) return 0;
        } else {
            if (off + 2 > data_len) return 0;
            length = rd16le(base + off);
            off += 2;
            if (length & 0x8000) {
                if (off + 2 > data_len) return 0;
                length = ((length & 0x7FFF) << 16) | rd16le(base + off);
                off += 2;
            }
            uint64_t end = off + 2 * length;
            if (end + 2 > data_len || rd16le(base + end) != 0) return 0;
        }
    }
    *count_out = count;
    return 1;
}

int apkfuzz_axml_valid(const uint8_t *d, size_t size) {
    if (!d || size < 8 || size > 16u * 1024u * 1024u) return 0;
    if (rd16le(d) != 0x0003 || rd16le(d + 2) != 8 || rd32le(d + 4) != size) return 0;
    size_t cursor = 8;
    uint32_t strings = 0;
    int have_pool = 0;
    long depth = 0, namespaces = 0, elements = 0;
    while (cursor < size) {
        if (size - cursor < 8) return 0;
        uint16_t kind = rd16le(d + cursor), header = rd16le(d + cursor + 2);
        uint32_t chunk = rd32le(d + cursor + 4);
        if (header < 8 || chunk < header || chunk > size - cursor ||
            ((header | chunk) & 3)) return 0;
        if (!have_pool) {
            if (kind != 0x0001 || !axml_string_pool(d, cursor, chunk, &strings)) return 0;
            have_pool = 1;
        } else if (kind == 0x0180) {                 /* resource map */
            if (header != 8) return 0;
        } else if (kind >= 0x0100 && kind <= 0x0104) { /* XML tree nodes */
            size_t ext = cursor + 16;
            uint32_t need = kind == 0x0102 ? 20 : kind == 0x0104 ? 12 : 8;
            if (header != 16 || chunk < 16 + need) return 0;
            if (!axml_ref(d, cursor + 12, strings)) return 0;
            if (kind == 0x0100 || kind == 0x0101) {   /* namespace start / end */
                if (!axml_ref(d, ext, strings) || rd32le(d + ext + 4) >= strings) return 0;
                namespaces += kind == 0x0100 ? 1 : -1;
                if (namespaces < 0) return 0;
            } else if (kind == 0x0104) {              /* character data */
                if (rd32le(d + ext) >= strings) return 0;
            } else {
                if (!axml_ref(d, ext, strings) || rd32le(d + ext + 4) >= strings) return 0;
                if (kind == 0x0103) {                 /* element end */
                    if (--depth < 0) return 0;
                } else {                              /* element start */
                    uint64_t attr_start = rd16le(d + ext + 8);
                    uint64_t attr_size = rd16le(d + ext + 10);
                    uint64_t attr_count = rd16le(d + ext + 12);
                    if (attr_start < 20 || attr_size < 20 ||
                        attr_start + attr_size * attr_count > chunk - 16) return 0;
                    for (uint64_t i = 0; i < attr_count; i++) {
                        size_t attr = ext + attr_start + i * attr_size;
                        if (!axml_ref(d, attr, strings) ||
                            rd32le(d + attr + 4) >= strings ||
                            !axml_ref(d, attr + 8, strings) ||
                            rd16le(d + attr + 12) != 8 ||
                            (d[attr + 15] == 0x03 && rd32le(d + attr + 16) >= strings))
                            return 0;
                    }
                    depth++;
                    elements++;
                }
            }
        } else {
            return 0;
        }
        cursor += chunk;
    }
    return have_pool && elements && !depth && !namespaces;
}

/* Decode the complete raw-deflate manifest and enforce both ZIP header views.
 * A bounded output buffer rejects size-changing or bomb-like descendants.
 * `strict` also requires a structurally sound binary XML document. */
static int manifest_crc(const uint8_t *buf, size_t size, const zip_layout_t *zl,
                        uint32_t *decoded_crc, int strict) {
    const uint32_t max_manifest_size = 16u * 1024u * 1024u;
    if (!buf || !zl || !zl->found || !decoded_crc ||
        zl->local_header_off > size || size - zl->local_header_off < 30 ||
        zl->cd_entry_off > size || size - zl->cd_entry_off < 46 ||
        zl->data_end > size || zl->data_start >= zl->data_end ||
        zl->data_end - zl->data_start > UINT_MAX ||
        zl->local_crc_off > size || size - zl->local_crc_off < 12 ||
        zl->cd_crc_off > size || size - zl->cd_crc_off < 12) return 0;

    uint32_t csize = (uint32_t)(zl->data_end - zl->data_start);
    uint32_t usize = rd32le(buf + zl->local_usize_off);
    if (!usize || usize > max_manifest_size ||
        csize != rd32le(buf + zl->local_csize_off) ||
        csize != rd32le(buf + zl->cd_csize_off) ||
        usize != rd32le(buf + zl->cd_usize_off) ||
        rd16le(buf + zl->local_header_off + 8) != 8 ||
        rd16le(buf + zl->cd_entry_off + 10) != 8 ||
        (rd16le(buf + zl->local_header_off + 6) & 0x0009u) ||
        (rd16le(buf + zl->cd_entry_off + 8) & 0x0009u)) return 0;

    uint8_t *decoded = malloc((size_t)usize + 1);
    if (!decoded) return 0;
    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    stream.next_in = (Bytef *)(buf + zl->data_start);
    stream.avail_in = (uInt)csize;
    stream.next_out = decoded;
    stream.avail_out = (uInt)usize + 1;
    int ok = 0;
    if (inflateInit2(&stream, -MAX_WBITS) == Z_OK) {
        int result = inflate(&stream, Z_FINISH);
        ok = result == Z_STREAM_END && stream.total_in == csize &&
             stream.total_out == usize;
        inflateEnd(&stream);
    }
    if (ok && strict) ok = apkfuzz_axml_valid(decoded, usize);
    if (ok) *decoded_crc = (uint32_t)crc32(0L, decoded, (uInt)usize);
    free(decoded);
    return ok;
}

int apkfuzz_manifest_valid(const uint8_t *buf, size_t size, const zip_layout_t *zl,
                           int strict) {
    uint32_t actual_crc = 0;
    return manifest_crc(buf, size, zl, &actual_crc, strict) &&
           actual_crc == rd32le(buf + zl->local_crc_off) &&
           actual_crc == rd32le(buf + zl->cd_crc_off);
}

static int mutate_valid_manifest_bit(uint8_t *buf, size_t size,
                                     const zip_layout_t *zl, apkfuzz_rng_t *rng,
                                     apkfuzz_result_t *res, int strict) {
    uint32_t old_crc = 0;
    res->requested_flips = 1;
    regions_add(&res->regions, "manifest", zl->data_start, zl->data_end);
    regions_add(&res->regions, "local_crc", zl->local_crc_off, zl->local_crc_off + 4);
    regions_add(&res->regions, "cd_crc", zl->cd_crc_off, zl->cd_crc_off + 4);
    if (!manifest_crc(buf, size, zl, &old_crc, strict) ||
        old_crc != rd32le(buf + zl->local_crc_off) ||
        old_crc != rd32le(buf + zl->cd_crc_off)) {
        res->status = MST_NO_VALID_MUTATION;
        return -1;
    }
    uint64_t span = zl->data_end - zl->data_start;
    for (int attempt = 0; attempt < 64; attempt++) {
        uint64_t off = zl->data_start + apkfuzz_rng_below(rng, span);
        uint8_t bit = (uint8_t)(1u << apkfuzz_rng_below(rng, 8));
        uint8_t before = buf[off];
        buf[off] ^= bit;
        uint32_t new_crc = 0;
        if (manifest_crc(buf, size, zl, &new_crc, strict) && new_crc != old_crc) {
            edits_record(&res->edits, off, before, buf[off]);
            for (int i = 0; i < 4; i++) {
                uint8_t new_byte = (uint8_t)(new_crc >> (8 * i));
                uint64_t offsets[2] = {zl->local_crc_off + i, zl->cd_crc_off + i};
                for (int j = 0; j < 2; j++) {
                    uint64_t field_off = offsets[j];
                    if (buf[field_off] != new_byte) {
                        edits_record(&res->edits, field_off, buf[field_off], new_byte);
                        buf[field_off] = new_byte;
                    }
                }
            }
            res->actual_flips = 1;
            return 1;
        }
        buf[off] = before;
    }
    res->status = MST_NO_VALID_MUTATION;
    return -1;
}

/* Apply `pat` to the 4-byte LE field at off, recording byte edits. Returns the
 * number of bytes actually changed. */
static int apply_field_pattern(uint8_t *buf, uint64_t off, uint64_t size,
                               field_pattern_t pat, apkfuzz_rng_t *rng,
                               apkfuzz_edits_t *edits) {
    if (off + 4 > size || pat == FP_KEEP) return 0;

    uint8_t old4[4] = { buf[off], buf[off+1], buf[off+2], buf[off+3] };
    uint8_t new4[4];
    memcpy(new4, old4, 4);

    switch (pat) {
        case FP_FLIP_BIT: {
            int b = (int)apkfuzz_rng_below(rng, 32);
            new4[b >> 3] ^= (uint8_t)(1u << (b & 7));
            break;
        }
        case FP_ZERO:     new4[0]=new4[1]=new4[2]=new4[3]=0x00; break;
        case FP_ONES:     new4[0]=new4[1]=new4[2]=new4[3]=0xFF; break;
        case FP_PLUS_ONE: {
            uint32_t v = rd32le(old4) + 1u;
            new4[0]=(uint8_t)v; new4[1]=(uint8_t)(v>>8);
            new4[2]=(uint8_t)(v>>16); new4[3]=(uint8_t)(v>>24);
            break;
        }
        case FP_MINUS_ONE: {
            uint32_t v = rd32le(old4) - 1u;
            new4[0]=(uint8_t)v; new4[1]=(uint8_t)(v>>8);
            new4[2]=(uint8_t)(v>>16); new4[3]=(uint8_t)(v>>24);
            break;
        }
        case FP_RANDOM32: {
            uint64_t r = apkfuzz_rng_next(rng);
            new4[0]=(uint8_t)r; new4[1]=(uint8_t)(r>>8);
            new4[2]=(uint8_t)(r>>16); new4[3]=(uint8_t)(r>>24);
            break;
        }
        default: break;
    }

    int changed = 0;
    for (int b = 0; b < 4; b++) {
        if (new4[b] != old4[b]) {
            buf[off + b] = new4[b];
            edits_record(edits, off + b, old4[b], new4[b]);
            changed++;
        }
    }
    return changed;
}

/* Two field offsets (local + central copy of the same logical field) and a
 * target/pattern selection. Records regions + edits, returns bytes changed. */
static int perturb_field_pair(uint8_t *buf, uint64_t size,
                              uint64_t local_off, const char *local_name,
                              uint64_t cd_off, const char *cd_name,
                              field_pattern_t pat, field_target_t tgt,
                              apkfuzz_rng_t *rng, apkfuzz_edits_t *edits,
                              apkfuzz_regions_t *regions) {
    int changed = 0;
    int do_local = (tgt == FT_LOCAL_ONLY || tgt == FT_BOTH_SAME || tgt == FT_BOTH_DIFFERENT);
    int do_cd    = (tgt == FT_CD_ONLY    || tgt == FT_BOTH_SAME || tgt == FT_BOTH_DIFFERENT);

    if (do_local) {
        changed += apply_field_pattern(buf, local_off, size, pat, rng, edits);
        regions_add(regions, local_name, local_off, local_off + 4);
    }
    if (do_cd) {
        /* BOTH_DIFFERENT draws an independent pattern for the CD copy so the two
         * views of the field diverge; the others reuse the same pattern. */
        field_pattern_t cd_pat = pat;
        if (tgt == FT_BOTH_DIFFERENT) {
            do { cd_pat = (field_pattern_t)apkfuzz_rng_below(rng, FP_INVALID); }
            while (cd_pat == FP_KEEP); /* KEEP on the diverging copy would be a no-op */
        }
        changed += apply_field_pattern(buf, cd_off, size, cd_pat, rng, edits);
        regions_add(regions, cd_name, cd_off, cd_off + 4);
    }
    return changed;
}

/* ------------------------------------------------------------------ */
/* Public mutate                                                       */
/* ------------------------------------------------------------------ */
int apkfuzz_mutate(uint8_t *buf, size_t size, const zip_layout_t *zl,
                   apkfuzz_cfg_t *cfg, apkfuzz_rng_t *rng, apkfuzz_result_t *res) {
    if (!buf || !zl || !cfg || !rng || !res) {
        if (res) res->status = MST_ERROR;
        return -1;
    }
    apkfuzz_edits_reset(&res->edits);
    res->regions.count   = 0;
    res->requested_flips = 0;
    res->actual_flips    = 0;
    res->status          = MST_OK;
    res->used_pattern    = FP_INVALID;
    res->used_target     = FT_INVALID;

    /* random-range works on the whole file; every other mode needs the manifest. */
    if (!zl->found && cfg->mode != MODE_RANDOM_RANGE) {
        res->status = MST_NO_MANIFEST;
        return -1;
    }

    if (cfg->mode == MODE_MANIFEST_VALID_ONEBIT || cfg->mode == MODE_MANIFEST_AXML_ONEBIT)
        return mutate_valid_manifest_bit(buf, size, zl, rng, res,
                                         cfg->mode == MODE_MANIFEST_AXML_ONEBIT);

    if (cfg->mode == MODE_CRC_FIELDS || cfg->mode == MODE_SIZE_FIELDS) {
        field_pattern_t pat = cfg->field_pattern_fixed
            ? cfg->field_pattern
            : (field_pattern_t)apkfuzz_rng_below(rng, FP_INVALID);
        field_target_t tgt = cfg->field_target_fixed
            ? cfg->field_target
            : (field_target_t)apkfuzz_rng_below(rng, FT_INVALID);
        res->used_pattern = pat;
        res->used_target  = tgt;

        int changed = 0;
        if (cfg->mode == MODE_CRC_FIELDS) {
            res->requested_flips = 1;
            changed = perturb_field_pair(buf, size,
                        zl->local_crc_off, "local_crc",
                        zl->cd_crc_off,    "cd_crc",
                        pat, tgt, rng, &res->edits, &res->regions);
        } else {
            res->requested_flips = 2; /* comp size + uncomp size (each has 2 copies) */
            changed  = perturb_field_pair(buf, size,
                         zl->local_csize_off, "local_csize",
                         zl->cd_csize_off,    "cd_csize",
                         pat, tgt, rng, &res->edits, &res->regions);
            changed += perturb_field_pair(buf, size,
                         zl->local_usize_off, "local_usize",
                         zl->cd_usize_off,    "cd_usize",
                         pat, tgt, rng, &res->edits, &res->regions);
        }
        res->actual_flips = changed;
        return changed;
    }

    /* range-style modes */
    uint64_t rs = 0, re = 0;
    if (!compute_region(size, zl, cfg, &rs, &re)) { res->status = MST_ERROR; return -1; }
    if (re > size) re = size;
    if (re <= rs)  { res->status = MST_REGION_EMPTY; return -1; }

    int want = pick_flip_count(cfg, rng);
    res->requested_flips = want;
    int done = flip_bits_in_range(buf, rs, re, want, rng, &res->edits, cfg->no_dedup);
    res->actual_flips = done;
    regions_add(&res->regions, region_name_for(cfg->mode), rs, re);
    return done;
}

/* ------------------------------------------------------------------ */
/* Logging                                                             */
/* ------------------------------------------------------------------ */
static void write_regions_kv(FILE *f, const apkfuzz_regions_t *rg) {
    for (int i = 0; i < rg->count; i++) {
        fprintf(f, "%s%s:[%llu,%llu)", i ? ";" : "",
                rg->items[i].name,
                (unsigned long long)rg->items[i].start,
                (unsigned long long)rg->items[i].end);
    }
    if (rg->count == 0) fputs("-", f);
}

void apkfuzz_log_line(const apkfuzz_cfg_t *cfg,
                      const char *src_path, const char *out_path,
                      uint64_t seed, uint64_t iter, int gen,
                      const zip_layout_t *zl, int manifest_found,
                      const apkfuzz_result_t *res) {
    if (!cfg || !cfg->do_log) return;
    FILE *f = fopen(cfg->log_file, "a");
    if (!f) return;

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    double t = (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;

    const char *pat = (res->used_pattern != FP_INVALID)
        ? apkfuzz_field_pattern_name(res->used_pattern) : "-";
    const char *tgt = (res->used_target != FT_INVALID)
        ? apkfuzz_field_target_name(res->used_target) : "-";
    uint64_t mstart = zl ? zl->data_start : 0;
    uint64_t mend   = zl ? zl->data_end   : 0;

    if (cfg->log_jsonl) {
        fprintf(f,
          "{\"ts\":%.6f,\"seed\":%llu,\"iter\":%llu,\"gen\":%d,"
          "\"compiled_mode\":\"%s\",\"effective_mode\":\"%s\",\"requested_mode\":\"%s\","
          "\"locked\":%d,\"status\":\"%s\",\"source_reason\":\"%s\",\"manifest_found\":%d,"
          "\"manifest\":[%llu,%llu],\"requested_flips\":%d,\"actual_flips\":%d,"
          "\"edits\":%d,\"field_pattern\":\"%s\",\"field_target\":\"%s\",\"regions\":\"",
          t, (unsigned long long)seed, (unsigned long long)iter, gen,
          cfg->compiled_mode, cfg->mode_name,
          (cfg->requested_mode && *cfg->requested_mode) ? cfg->requested_mode : "-",
          cfg->locked, apkfuzz_status_name(res->status),
          res->source_reason ? res->source_reason : "none", manifest_found,
          (unsigned long long)mstart, (unsigned long long)mend,
          res->requested_flips, res->actual_flips, res->edits.count, pat, tgt);
        write_regions_kv(f, &res->regions);
        fprintf(f, "\",\"src\":\"%s\",\"out\":\"%s\"}\n",
                src_path ? src_path : "?", out_path ? out_path : "?");
    } else {
        fprintf(f,
          "ts=%.6f seed=%llu iter=%llu gen=%d compiled_mode=%s effective_mode=%s "
          "requested_mode=%s locked=%d status=%s source_reason=%s manifest_found=%d "
          "manifest=[%llu,%llu) requested_flips=%d actual_flips=%d edits=%d "
          "field_pattern=%s field_target=%s regions=",
          t, (unsigned long long)seed, (unsigned long long)iter, gen,
          cfg->compiled_mode, cfg->mode_name,
          (cfg->requested_mode && *cfg->requested_mode) ? cfg->requested_mode : "-",
          cfg->locked, apkfuzz_status_name(res->status),
          res->source_reason ? res->source_reason : "none", manifest_found,
          (unsigned long long)mstart, (unsigned long long)mend,
          res->requested_flips, res->actual_flips, res->edits.count, pat, tgt);
        write_regions_kv(f, &res->regions);
        fprintf(f, " src=%s out=%s\n", src_path ? src_path : "?", out_path ? out_path : "?");
    }
    fclose(f);
}
