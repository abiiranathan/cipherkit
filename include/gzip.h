#ifndef BA374F62_2CF0_43AD_9D7A_2D80B9D267A5
#define BA374F62_2CF0_43AD_9D7A_2D80B9D267A5

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <zlib.h>

// GZIP compression and decompression functions using zlib.
// Compresses the contents of the input file and writes the compressed data to the output file.
// Both streams must be opened in binary write mode.
// Both streams are not closed by this function.
bool gzip_compress_file(FILE* infile, FILE* outfile);

// Decompresses the contents of the input file and writes the decompressed data to the output file.
// Both streams must be opened in binary write mode.
// Both streams are not closed by this function.
bool gzip_decompress_file(FILE* infile, FILE* outfile);

// Compresses the input data using gzip.
// The compressed_data buffer is allocated by this function and must be freed by the caller.
bool gzip_compress_bytes(const uint8_t* data, size_t data_len, uint8_t** compressed_data,
                         size_t* compressed_data_len);

// Decompresses the input data that was compressed using gzip.
// The uncompressed_data buffer is allocated by this function and must be freed by the caller.
bool gzip_decompress_bytes(const uint8_t* compressed_data, size_t compressed_data_len,
                           uint8_t** uncompressed_data, size_t* uncompressed_data_len);

#ifdef __cplusplus
}
#endif

#endif /* BA374F62_2CF0_43AD_9D7A_2D80B9D267A5 */
