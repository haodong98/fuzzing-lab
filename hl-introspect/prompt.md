# HL Round 2 Prompt — libpng AFL++ campaign

You are a coding agent maintaining a fuzzing harness. The current harness has plateaued.

## Round 1 stats
duration=836s edges_found=747 corpus=239 overall_slope=0.183/s tail_slope=0.054/s verdict=still climbing

## Top 10 queue items by depth (proxy for hard-to-reach paths)
total 956
-rw-r--r-- 4 root root 849 May 10 17:53 id:000002,time:0,execs:0,orig:03_palette.png
-rw------- 1 root root 849 May 10 19:20 id:000173,src:000002,time:431659,execs:62502,op:inf,rep:2
-rw------- 1 root root 849 May 10 19:21 id:000175,src:000002,time:439292,execs:63341,op:quick,pos:824
-rw------- 1 root root 849 May 10 19:21 id:000176,src:000002,time:439807,execs:63403,op:flip2,pos:824,+cov
-rw------- 1 root root 849 May 10 19:21 id:000177,src:000002,time:439887,execs:63412,op:flip2,pos:824
-rw------- 1 root root 849 May 10 19:21 id:000178,src:000002,time:441562,execs:63640,op:int16,pos:824,val:be:-128
-rw------- 1 root root 849 May 10 19:21 id:000179,src:000002,time:441666,execs:63652,op:int16,pos:824,val:+32
-rw------- 1 root root 797 May 10 19:21 id:000180,src:000002,time:447828,execs:64466,op:havoc,rep:4
-rw-r--r-- 4 root root 164 May 10 17:53 id:000006,time:0,execs:0,orig:07_with_text.png
-rw------- 1 root root 118 May 10 19:26 id:000205,src:000168,time:764644,execs:115254,op:havoc,rep:7,+cov

## Crashes so far


## Current harness (src/harness.c)
```c
/*
 * harness.c — fork-mode AFL++ harness for libpng 1.2.x.
 *
 * Entry point rationale (Q1):
 *   We exercise the full pull-mode read pipeline:
 *     png_create_read_struct -> png_read_info -> png_set_*  ->
 *     png_read_update_info   -> png_read_image -> png_read_end -> destroy.
 *   This is the path real applications take (browsers, ImageMagick, terminal emulators) and is the
 *   region where the historical CVEs cluster (PLTE expansion, IDAT defilter, tEXt/zTXt parsing).
 *
 * Alternatives we considered and rejected for the *primary* harness:
 *   - Just png_read_info: too shallow. Skips IDAT defilter where most CVEs live.
 *   - png_set_PLTE-only micro-harness: deep but narrow, would miss CVE-2016-10087 etc.
 *   - Encoder API (png_write_*): less commonly attacker-controlled. Worth fuzzing separately.
 *   - Progressive read (png_push_*): different state machine. Worth a sibling harness.
 *
 * AFL++ I/O contract: AFL++ delivers each test case as the file path passed in argv[1] (the @@
 * placeholder). File-based delivery is simpler than stdin and works identically with afl-tmin.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/* libpng's png.h pulls in setjmp.h itself (see pngconf.h). Including <setjmp.h> ourselves before
 * <png.h> triggers an intentional #error inside libpng 1.2.x. */
#include <png.h>

/* Caps. Each one removes a class of "uninteresting failure" from the campaign:
 *   MAX_INPUT_SIZE — refuse >1 MiB inputs. zlib can blow up by orders of magnitude during IDAT
 *                    decompression; capping the input size keeps per-exec time bounded and stable.
 *   MAX_PIXELS     — refuse images with more than 4096*4096 pixels. A crafted 65535×65535 IHDR
 *                    forces libpng to allocate an enormous row buffer, OOMing the fork worker
 *                    without exposing any memory-safety bug. We give up the ability to find OOM
 *                    bugs to keep the harness fast and stable.
 *   PNG_SIG_BYTES  — early signature reject. libpng aborts at the signature check anyway, but
 *                    rejecting in the harness avoids wasting fork-server work on obviously bad
 *                    inputs (most random mutations).
 */
#define MAX_INPUT_SIZE  (1u << 20)
#define MAX_PIXELS      (4096u * 4096u)
#define PNG_SIG_BYTES   8

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

static unsigned char *slurp(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long sz = ftell(f);
    if (sz < 0 || (size_t)sz > MAX_INPUT_SIZE) { fclose(f); return NULL; }
    rewind(f);
    unsigned char *buf = (unsigned char *)malloc((size_t)sz);
    if (!buf) { fclose(f); return NULL; }
    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (got != (size_t)sz) { free(buf); return NULL; }
    *out_len = (size_t)sz;
    return buf;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <png file>\n", argv[0]);
        return 0;
    }

    size_t len = 0;
    unsigned char *data = slurp(argv[1], &len);
    if (!data) return 0;
    if (len < PNG_SIG_BYTES || png_sig_cmp((png_bytep)data, 0, PNG_SIG_BYTES) != 0) {
        free(data);
        return 0;
    }

    png_structp png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png_ptr) { free(data); return 0; }
    png_infop info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr) {
        png_destroy_read_struct(&png_ptr, NULL, NULL);
        free(data);
        return 0;
    }

    /* libpng reports errors via longjmp. Without this jmpbuf, every malformed input becomes a
     * SIGABRT crash and floods the campaign with false positives. With it, libpng's own error
     * paths are exercised but cleanly recovered from. */
    if (setjmp(png_jmpbuf(png_ptr))) {
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        free(data);
        return 0;
    }

    struct in_cursor cur = { data, 0, len };
    png_set_read_fn(png_ptr, &cur, in_read);

    /* Phase 1 — header + ancillary chunks before IDAT. */
    png_read_info(png_ptr, info_ptr);

    png_uint_32 w = png_get_image_width(png_ptr, info_ptr);
    png_uint_32 h = png_get_image_height(png_ptr, info_ptr);
    if ((uint64_t)w * (uint64_t)h > (uint64_t)MAX_PIXELS) {
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        free(data);
        return 0;
    }

    /* Phase 2 — enable as many transformations as possible. Each png_set_* opens a different
     * code path inside libpng; turning them all on widens the per-execution surface area.
     *
     *   png_set_expand        — palette -> RGB, low-bit-depth gray -> 8-bit, tRNS -> alpha.
     *                           Region of CVE-2015-8126 (PLTE overflow, fixed in 1.2.54).
     *   png_set_strip_16      — 16-bit channel -> 8-bit. Integer-arithmetic-heavy path.
     *   png_set_gray_to_rgb   — gray -> RGB conversion.
     *   png_set_packing       — sub-byte channels -> one-pixel-per-byte.
     */
    png_set_expand(png_ptr);
    png_set_strip_16(png_ptr);
    png_set_gray_to_rgb(png_ptr);
    png_set_packing(png_ptr);
    png_read_update_info(png_ptr, info_ptr);

    /* Phase 3 — IDAT defilter pipeline. Allocate row buffers based on post-transformation rowbytes
     * (which can differ from the on-disk rowbytes). */
    png_uint_32 rowbytes = (png_uint_32)png_get_rowbytes(png_ptr, info_ptr);
    if (rowbytes == 0 || h == 0 || rowbytes > (1u << 24)) {
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        free(data);
        return 0;
    }

    png_bytepp rows = (png_bytepp)malloc(sizeof(png_bytep) * h);
    if (!rows) {
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        free(data);
        return 0;
    }
    for (png_uint_32 i = 0; i < h; i++) {
        rows[i] = (png_bytep)malloc(rowbytes);
        if (!rows[i]) {
            for (png_uint_32 j = 0; j < i; j++) free(rows[j]);
            free(rows);
            png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
            free(data);
            return 0;
        }
    }
    png_read_image(png_ptr, rows);

    /* Phase 4 — chunks after IDAT (post-image tEXt/zTXt/tIME). CVE-2016-10087 lives here. */
    png_read_end(png_ptr, info_ptr);

    for (png_uint_32 i = 0; i < h; i++) free(rows[i]);
    free(rows);
    png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
    free(data);
    return 0;
}
```

## Current dictionary entry count
45

## Task
Propose a unified diff that:
  1. Enables additional png_set_* transformations to widen coverage.
  2. Adds dictionary entries for any unimplemented chunk types you can identify
     in libpng source (cf. /opt/libpng-1.2.56/pngrutil.c).
  3. (Optional) Defines a custom mutator skeleton at src/png_custom_mutator.c.

Output ONLY the diff in patches/hl-round2.diff.
