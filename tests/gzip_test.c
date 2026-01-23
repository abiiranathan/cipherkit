#define _POSIX_C_SOURCE 200809L

#include "../include/gzip.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char* make_tempfile(void) {
    // use mkstemp
    char* filename = malloc(16);
    if (!filename) {
        return NULL;
    }

    strcpy(filename, "tempfileXXXXXX");
    int fd = mkstemp(filename);
    if (fd == -1) {
        free(filename);
        return NULL;
    }

    close(fd);
    return filename;
}

static void test_gzip_file_compression_and_decompression(void) {
    char* filename = make_tempfile();
    char* compressed_filename = make_tempfile();

    assert(filename && "Failed to create temporary file");
    assert(compressed_filename && "Failed to create temporary file");

    FILE* file = fopen(filename, "wb");
    assert(file && "Failed to open file for writing");

    const char* data = "Hello, World!";
    fwrite(data, 1, strlen(data), file);
    fclose(file);

    file = fopen(filename, "rb");
    assert(file && "Failed to open file for reading");

    FILE* compressed_file = fopen(compressed_filename, "wb");
    assert(compressed_file && "Failed to open file for writing");

    bool success = gzip_compress_file(file, compressed_file);
    fclose(file);
    fclose(compressed_file);
    assert(success && "Failed to compress file");

    file = fopen(compressed_filename, "rb");
    assert(file && "Failed to open compressed file for reading");

    char* decompressed_filename = make_tempfile();
    compressed_file = fopen(decompressed_filename, "wb");
    assert(compressed_file && "Failed to open file for writing");

    success = gzip_decompress_file(file, compressed_file);
    fclose(file);
    fclose(compressed_file);
    assert(success && "Failed to decompress file");

    file = fopen(decompressed_filename, "rb");
    assert(file && "Failed to open decompressed file for reading");

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    if (file_size == -1) {
        fclose(file);
        exit(1);
    }

    fseek(file, 0, SEEK_SET);
    assert(file_size == (long)strlen(data) &&
           "Decompressed file size does not match original file size");

    char* buffer = malloc((size_t)(file_size + 1));
    assert(buffer && "Failed to allocate memory for buffer");

    size_t n = fread(buffer, 1, (size_t)file_size, file);
    assert(n == (size_t)file_size && "Failed to read decompressed file");
    fclose(file);
    buffer[n] = '\0';
    printf("Decompressed data: %s\n", buffer);

    assert(strcmp(data, buffer) == 0 && "Decompressed data does not match original data");

    free(buffer);
    remove(filename);
    remove(compressed_filename);
    remove(decompressed_filename);

    free(filename);
    free(compressed_filename);
    free(decompressed_filename);

    puts("Gzip file compression and decompression tests passed");
}

static void test_gzip_bytes_compression_and_decompression(void) {
    const char* data = "Hello, World!";
    size_t data_len = strlen(data);

    uint8_t* compressed_data;
    size_t compressed_data_len;
    bool success =
        gzip_compress_bytes((const uint8_t*)data, data_len, &compressed_data, &compressed_data_len);
    assert(success && "Failed to compress data");

    uint8_t* uncompressed_data = NULL;
    size_t uncompressed_data_len = 0;
    success = gzip_decompress_bytes(compressed_data, compressed_data_len, &uncompressed_data,
                                    &uncompressed_data_len);
    assert(success && "Failed to decompress data");

    assert(data_len == uncompressed_data_len &&
           "Decompressed data length does not match original data length");
    assert(memcmp(data, uncompressed_data, data_len) == 0 &&
           "Decompressed data does not match original data");

    free(compressed_data);
    free(uncompressed_data);

    puts("Gzip bytes compression and decompression tests passed");
}

int main() {
    test_gzip_file_compression_and_decompression();
    test_gzip_bytes_compression_and_decompression();
    return 0;
}
