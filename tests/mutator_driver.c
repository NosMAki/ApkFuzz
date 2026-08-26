/*
 * mutator_driver.c - standalone harness for the v2 custom mutator .so files.
 *
 * It dlopen()s a mutator, drives afl_custom_fuzz() N times against one APK with
 * a fixed seed, and prints, for every round, the byte offsets it changed. It
 * links zip2 directly so it can also print the true ZIP layout of the APK, which
 * lets the sanity test assert that each strategy only touches its declared
 * structure -- without trusting the mutator's own log.
 *
 * Output (stdout), stable and diffable:
 *   LAYOUT manifest=[a,b) local_header=[a,b) cd=[a,b) local_crc=x cd_crc=x \
 *          local_csize=x local_usize=x cd_csize=x cd_usize=x size=N
 *   R<k> <off>:<xor> <off>:<xor> ...
 *
 * Build: cc -O1 mutator_driver.c zip2.c -I<v2dir> -o mutator_driver -ldl
 * Usage: APKFUZZ_OUT_DIR=... ./mutator_driver <so> <apk> <rounds> <seed>
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dlfcn.h>
#include "zip2.h"

typedef void  *(*init_fn)(void *, unsigned int);
typedef size_t (*fuzz_fn)(void *, uint8_t *, size_t, uint8_t **, uint8_t *, size_t, size_t);
typedef void   (*deinit_fn)(void *);

static uint8_t *slurp(const char *p, size_t *n) {
    FILE *f = fopen(p, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END); long s = ftell(f); rewind(f);
    if (s < 0) { fclose(f); return NULL; }
    uint8_t *b = malloc((size_t)s ? (size_t)s : 1);
    if (!b) { fclose(f); return NULL; }
    if (fread(b, 1, (size_t)s, f) != (size_t)s) { free(b); fclose(f); return NULL; }
    fclose(f);
    *n = (size_t)s;
    return b;
}

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "usage: %s <so> <apk> <rounds> <seed>\n", argv[0]);
        return 2;
    }
    const char *so   = argv[1];
    const char *apk  = argv[2];
    int   rounds     = atoi(argv[3]);
    unsigned seed    = (unsigned)strtoul(argv[4], NULL, 0);

    size_t orig_n = 0;
    uint8_t *orig = slurp(apk, &orig_n);
    if (!orig) { fprintf(stderr, "cannot read %s\n", apk); return 2; }

    zip_layout_t zl;
    if (zip2_analyze(orig, orig_n, "AndroidManifest.xml", &zl) && zl.found) {
        printf("LAYOUT manifest=[%llu,%llu) local_header=[%llu,%llu) cd=[%llu,%llu) "
               "local_crc=%llu cd_crc=%llu local_csize=%llu local_usize=%llu "
               "cd_csize=%llu cd_usize=%llu size=%zu\n",
               (unsigned long long)zl.data_start, (unsigned long long)zl.data_end,
               (unsigned long long)zl.local_header_off, (unsigned long long)zl.local_data_off,
               (unsigned long long)zl.cd_start, (unsigned long long)zl.cd_end,
               (unsigned long long)zl.local_crc_off, (unsigned long long)zl.cd_crc_off,
               (unsigned long long)zl.local_csize_off, (unsigned long long)zl.local_usize_off,
               (unsigned long long)zl.cd_csize_off, (unsigned long long)zl.cd_usize_off,
               orig_n);
    } else {
        printf("LAYOUT none size=%zu\n", orig_n);
    }

    void *h = dlopen(so, RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    init_fn   f_init   = (init_fn)dlsym(h, "afl_custom_init");
    fuzz_fn   f_fuzz   = (fuzz_fn)dlsym(h, "afl_custom_fuzz");
    deinit_fn f_deinit = (deinit_fn)dlsym(h, "afl_custom_deinit");
    if (!f_init || !f_fuzz || !f_deinit) { fprintf(stderr, "missing afl_custom_* symbols\n"); return 2; }

    char pathbuf[512];
    int plen = snprintf(pathbuf, sizeof(pathbuf), "%s\n", apk);

    void *d = f_init(NULL, seed);
    if (!d) { fprintf(stderr, "init failed\n"); return 2; }

    int rc = 0;
    for (int r = 0; r < rounds; r++) {
        uint8_t *out = NULL;
        size_t n = f_fuzz(d, (uint8_t *)pathbuf, (size_t)plen, &out, NULL, 0, 4096);
        if (!n || !out) { printf("R%d NONE\n", r); continue; }
        char mpath[600];
        memcpy(mpath, out, n); mpath[n] = '\0';
        size_t mut_n = 0;
        uint8_t *mut = slurp(mpath, &mut_n);
        if (!mut) { printf("R%d UNREADABLE\n", r); free(out); rc = 1; continue; }
        printf("R%d", r);
        size_t lim = mut_n < orig_n ? mut_n : orig_n;
        for (size_t i = 0; i < lim; i++)
            if (mut[i] != orig[i]) printf(" %zu:%02x", i, mut[i] ^ orig[i]);
        printf("\n");
        free(mut); free(out);
    }
    f_deinit(d);
    dlclose(h);
    free(orig);
    return rc;
}
