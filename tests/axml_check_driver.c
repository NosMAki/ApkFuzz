/* Test driver: report apkfuzz_axml_valid() for a manifest and for single-byte
 * XOR variants of it. Usage: axml_check_driver MANIFEST < "offset mask" lines.
 * Prints one '1' or '0' per line: first the unmodified file, then each variant. */
#include <stdio.h>
#include <stdlib.h>
#include "strategies.h"

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    FILE *in = fopen(argv[1], "rb");
    if (!in) return 2;
    if (fseek(in, 0, SEEK_END) != 0) return 2;
    long size = ftell(in);
    rewind(in);
    if (size < 0) return 2;
    uint8_t *data = malloc((size_t)size + 1);
    if (!data || fread(data, 1, (size_t)size, in) != (size_t)size) return 2;
    fclose(in);
    printf("%d\n", apkfuzz_axml_valid(data, (size_t)size));
    unsigned long offset, mask;
    while (scanf("%lu %lu", &offset, &mask) == 2) {
        if (offset >= (unsigned long)size || mask == 0 || mask > 255) return 2;
        data[offset] ^= (uint8_t)mask;
        printf("%d\n", apkfuzz_axml_valid(data, (size_t)size));
        data[offset] ^= (uint8_t)mask;
    }
    free(data);
    return 0;
}
