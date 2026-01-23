#include "../include/gzip.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Use a larger chunk size for better file I/O performance
#define CHUNK_SIZE (16 * 1024)
#define GZIP_WINDOW_BITS (15 + 16)  // 15 for max window, +16 for gzip header

bool gzip_compress_file(FILE* infile, FILE* outfile) {
    if (!infile || !outfile)
        return false;

    z_stream strm = {0};
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;

    if (deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, GZIP_WINDOW_BITS, 8,
                     Z_DEFAULT_STRATEGY) != Z_OK) {
        return false;
    }

    uint8_t in[CHUNK_SIZE];
    uint8_t out[CHUNK_SIZE];
    int flush;
    int ret;

    /* Compress until end of file */
    do {
        strm.avail_in = fread(in, 1, CHUNK_SIZE, infile);
        if (ferror(infile)) {
            deflateEnd(&strm);
            return false;
        }

        flush = feof(infile) ? Z_FINISH : Z_NO_FLUSH;
        strm.next_in = in;

        /* Run deflate() on input until output buffer not full */
        do {
            strm.avail_out = CHUNK_SIZE;
            strm.next_out = out;

            ret = deflate(&strm, flush);
            if (ret == Z_STREAM_ERROR) {
                deflateEnd(&strm);
                return false;
            }

            size_t have = CHUNK_SIZE - strm.avail_out;
            if (fwrite(out, 1, have, outfile) != have || ferror(outfile)) {
                deflateEnd(&strm);
                return false;
            }
        } while (strm.avail_out == 0);

        assert(strm.avail_in == 0); /* All input will be used */

    } while (flush != Z_FINISH);

    assert(ret == Z_STREAM_END); /* Stream will be complete */
    deflateEnd(&strm);
    return true;
}

bool gzip_decompress_file(FILE* infile, FILE* outfile) {
    if (!infile || !outfile)
        return false;

    z_stream strm = {0};
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;

    if (inflateInit2(&strm, GZIP_WINDOW_BITS) != Z_OK) {
        return false;
    }

    uint8_t in[CHUNK_SIZE];
    uint8_t out[CHUNK_SIZE];
    int ret;

    do {
        strm.avail_in = fread(in, 1, CHUNK_SIZE, infile);
        if (ferror(infile)) {
            inflateEnd(&strm);
            return false;
        }

        if (strm.avail_in == 0)
            break;
        strm.next_in = in;

        do {
            strm.avail_out = CHUNK_SIZE;
            strm.next_out = out;

            ret = inflate(&strm, Z_NO_FLUSH);
            assert(ret != Z_STREAM_ERROR); /* state not clobbered */

            switch (ret) {
                case Z_NEED_DICT:
                    ret = Z_DATA_ERROR; /* fall through */
                case Z_DATA_ERROR:
                case Z_MEM_ERROR:
                    inflateEnd(&strm);
                    return false;
            }

            size_t have = CHUNK_SIZE - strm.avail_out;
            if (fwrite(out, 1, have, outfile) != have || ferror(outfile)) {
                inflateEnd(&strm);
                return false;
            }
        } while (strm.avail_out == 0);

    } while (ret != Z_STREAM_END);

    inflateEnd(&strm);
    return ret == Z_STREAM_END;
}

bool gzip_compress_bytes(const uint8_t* data, size_t data_len, uint8_t** compressed_data,
                         size_t* compressed_data_len) {
    if (!data || !compressed_data || !compressed_data_len)
        return false;

    z_stream strm = {0};
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;

    if (deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, GZIP_WINDOW_BITS, 8,
                     Z_DEFAULT_STRATEGY) != Z_OK) {
        return false;
    }

    // Optimization: Calculate max size required
    size_t max_size = deflateBound(&strm, (unsigned long)data_len);
    uint8_t* buffer = (uint8_t*)malloc(max_size);
    if (!buffer) {
        deflateEnd(&strm);
        return false;
    }

    strm.next_in = (Bytef*)data;  // Cast for zlib compatibility
    strm.avail_in = (uInt)data_len;
    strm.next_out = buffer;
    strm.avail_out = (uInt)max_size;

    int ret = deflate(&strm, Z_FINISH);

    if (ret != Z_STREAM_END) {
        free(buffer);
        deflateEnd(&strm);
        return false;
    }

    *compressed_data_len = strm.total_out;

    // Shrink buffer to fit exactly (realloc down is generally cheap/safe)
    uint8_t* final_buffer = realloc(buffer, *compressed_data_len);
    *compressed_data = final_buffer ? final_buffer : buffer;

    deflateEnd(&strm);
    return true;
}

bool gzip_decompress_bytes(const uint8_t* compressed_data, size_t compressed_data_len,
                           uint8_t** uncompressed_data, size_t* uncompressed_data_len) {
    if (!compressed_data || !uncompressed_data || !uncompressed_data_len)
        return false;

    z_stream strm = {0};
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;

    if (inflateInit2(&strm, GZIP_WINDOW_BITS) != Z_OK) {
        return false;
    }

    // Start with a reasonable guess (e.g., 2x compressed size or 4KB)
    size_t capacity = compressed_data_len * 2;
    if (capacity < CHUNK_SIZE)
        capacity = CHUNK_SIZE;

    uint8_t* buffer = (uint8_t*)malloc(capacity);
    if (!buffer) {
        inflateEnd(&strm);
        return false;
    }

    strm.next_in = (Bytef*)compressed_data;
    strm.avail_in = (uInt)compressed_data_len;
    strm.next_out = buffer;
    strm.avail_out = (uInt)capacity;

    int ret;
    do {
        ret = inflate(&strm, Z_NO_FLUSH);

        if (ret == Z_STREAM_ERROR || ret == Z_NEED_DICT || ret == Z_DATA_ERROR ||
            ret == Z_MEM_ERROR) {
            free(buffer);
            inflateEnd(&strm);
            return false;
        }

        if (strm.avail_out == 0) {
            // Buffer full, need to grow (Geometric growth: 1.5x or 2x)
            size_t new_capacity = capacity * 2;
            uint8_t* new_buffer = (uint8_t*)realloc(buffer, new_capacity);

            if (!new_buffer) {
                free(buffer);  // Prevent leak
                inflateEnd(&strm);
                return false;
            }

            buffer = new_buffer;
            // Point zlib to the new available space
            strm.next_out = buffer + capacity;
            strm.avail_out = (uInt)(new_capacity - capacity);
            capacity = new_capacity;
        }
    } while (ret != Z_STREAM_END);

    *uncompressed_data_len = strm.total_out;
    *uncompressed_data = buffer;

    inflateEnd(&strm);
    return true;
}
