/*
 * harness_persistent.c — persistent-mode AFL++ harness for libpng 1.2.x.
 *
 * Same decoding pipeline as harness.c, but wrapped in __AFL_LOOP so we avoid the fork() per
 * test case. AFL++ delivers each test case in the __AFL_FUZZ_TESTCASE_BUF buffer, length in
 * __AFL_FUZZ_TESTCASE_LEN, *not* via argv anymore.
 *
 * Why this is faster:
 *   Fork mode pays ~1-3 ms per case for fork() + COW + exec(). Persistent mode reuses the same
 *   process across __AFL_LOOP(N) iterations. Typical speedup: 2-20x. Cost: leaked state between
 *   iterations can lower stability (we mitigate by destroy/create-ing every libpng struct each
 *   iteration).
 *
 * Stability hazards in this harness:
 *   - libpng has internal global state (e.g., warning handlers); we use the per-call hook so this
 *     is fine.
 *   - ASan does not reset shadow memory between iterations. Heap allocations are correctly freed
 *     each iteration so this should be a non-issue, but lower N if stability drops.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/* libpng's png.h pulls in setjmp.h. Including <setjmp.h> first triggers a libpng 1.2.x #error. */
#include <png.h>

#define MAX_INPUT_SIZE  (1u << 20)
#define MAX_PIXELS      (4096u * 4096u)
#define PNG_SIG_BYTES   8

/* AFL++ persistent-mode macros. Provided by afl-clang-fast at link time. */
__AFL_FUZZ_INIT();

struct in_cursor {
    const unsigned char *data;
    size_t off;
    size_t len;
};

static void in_read(png_structp png_ptr, png_bytep out, png_size_t n) {
    struct in_cursor *c = (struct in_cursor *)png_get_io_ptr(png_ptr);
    if (!c || c->off + n > c->len) {
        png_error(png_ptr, "short read");
        return;
    }
    memcpy(out, c->data + c->off, n);
    c->off += n;
}

/* Single fuzzing iteration. Mirrors harness.c. */
static void run_once(const unsigned char *data, size_t len) {
    if (len < PNG_SIG_BYTES) return;
    if (png_sig_cmp((png_bytep)data, 0, PNG_SIG_BYTES) != 0) return;

    png_structp png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png_ptr) return;
    png_infop info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr) {
        png_destroy_read_struct(&png_ptr, NULL, NULL);
        return;
    }

    if (setjmp(png_jmpbuf(png_ptr))) {
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        return;
    }

    struct in_cursor cur = { data, 0, len };
    png_set_read_fn(png_ptr, &cur, in_read);

    png_read_info(png_ptr, info_ptr);

    png_uint_32 w = png_get_image_width(png_ptr, info_ptr);
    png_uint_32 h = png_get_image_height(png_ptr, info_ptr);
    if ((uint64_t)w * (uint64_t)h > (uint64_t)MAX_PIXELS) {
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        return;
    }

    png_set_expand(png_ptr);
    png_set_strip_16(png_ptr);
    png_set_gray_to_rgb(png_ptr);
    png_set_packing(png_ptr);
    png_read_update_info(png_ptr, info_ptr);

    png_uint_32 rowbytes = (png_uint_32)png_get_rowbytes(png_ptr, info_ptr);
    if (rowbytes == 0 || h == 0 || rowbytes > (1u << 24)) {
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        return;
    }

    png_bytepp rows = (png_bytepp)malloc(sizeof(png_bytep) * h);
    if (!rows) {
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        return;
    }
    int alloc_ok = 1;
    for (png_uint_32 i = 0; i < h; i++) {
        rows[i] = (png_bytep)malloc(rowbytes);
        if (!rows[i]) { alloc_ok = 0; break; }
    }
    if (alloc_ok) {
        png_read_image(png_ptr, rows);
        png_read_end(png_ptr, info_ptr);
    }

    for (png_uint_32 i = 0; i < h; i++) {
        if (rows[i]) free(rows[i]);
    }
    free(rows);
    png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;

    /* __AFL_INIT installs the deferred fork server. After this call, AFL++ snapshots process
     * state and re-uses it for each __AFL_LOOP iteration. Anything expensive that does not depend
     * on the test case (e.g., dlopen, large constant tables) should happen *before* __AFL_INIT.
     * For libpng we have nothing of that kind. */
    __AFL_INIT();

    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    /* 10000 iterations per process is AFL++'s recommended ceiling. If stability dips below ~95%
     * we should lower this; libpng with create/destroy per iter should be fine. */
    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        if (len <= 0 || (size_t)len > MAX_INPUT_SIZE) continue;
        run_once(buf, (size_t)len);
    }

    return 0;
}
