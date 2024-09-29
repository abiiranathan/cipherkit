# Gzip Compression/Decompression Module

This library provides functions to compress and decompress data using the GZIP format, implemented with the `zlib` library. The functions operate both on files and on in-memory data buffers.

## Features

- **File compression and decompression**: Compresses and decompresses the contents of files using GZIP.
- **Byte compression and decompression**: Compresses and decompresses raw data buffers in memory.
- Utilizes **zlib** for compression algorithms, ensuring portability and performance.

## Installation
See the [main README](../README.md) for installation instructions.

## API Documentation

### File Compression

#### `bool gzip_compress_file(FILE* infile, FILE* outfile);`

Compresses the contents of the input file and writes the compressed data to the output file.

- **Parameters**:
  - `infile`: Input file stream (must be opened in write binary mode).
  - `outfile`: Output file stream (must be opened in write binary mode).
- **Returns**: `true` on success, `false` on failure.

*Note*: The input and output file streams must be opened before passing them to the function. This function does **not** close the streams.

#### `bool gzip_decompress_file(FILE* infile, FILE* outfile);`

Decompresses the contents of the input file and writes the decompressed data to the output file.

- **Parameters**:
  - `infile`: Input file stream containing compressed data (must be opened in binary mode).
  - `outfile`: Output file stream for decompressed data (must be opened in binary mode).
- **Returns**: `true` on success, `false` on failure.

*Note*: The input and output file streams must be opened before passing them to the function. This function does **not** close the streams.

### Byte Compression

#### `bool gzip_compress_bytes(const uint8_t* data, size_t data_len, uint8_t** compressed_data, size_t* compressed_data_len);`

Compresses raw data in memory and returns the compressed data.

- **Parameters**:
  - `data`: Pointer to the raw input data.
  - `data_len`: Length of the input data.
  - `compressed_data`: Pointer to the buffer where compressed data will be stored. The buffer is allocated by the function and must be freed by the caller.
  - `compressed_data_len`: Pointer to a variable that will store the size of the compressed data.
- **Returns**: `true` on success, `false` on failure.

*Note*: The caller is responsible for freeing the `compressed_data` buffer.

#### `bool gzip_decompress_bytes(const uint8_t* compressed_data, size_t compressed_data_len, uint8_t** uncompressed_data, size_t* uncompressed_data_len);`

Decompresses raw compressed data in memory and returns the uncompressed data.

- **Parameters**:
  - `compressed_data`: Pointer to the compressed input data.
  - `compressed_data_len`: Length of the compressed input data.
  - `uncompressed_data`: Pointer to the buffer where uncompressed data will be stored. The buffer is allocated by the function and must be freed by the caller.
  - `uncompressed_data_len`: Pointer to a variable that will store the size of the uncompressed data.
- **Returns**: `true` on success, `false` on failure.

*Note*: The caller is responsible for freeing the `uncompressed_data` buffer.

## Example Usage

### File Compression

```c
#include <stdio.h>
#include <cipherkit/gzip.h>

int main() {
    FILE* infile = fopen("input.txt", "rb");
    FILE* outfile = fopen("output.gz", "wb");
    
    if (gzip_compress_file(infile, outfile)) {
        printf("File compressed successfully.\n");
    } else {
        printf("Compression failed.\n");
    }

    fclose(infile);
    fclose(outfile);
    return 0;
}
```

### Byte Compression

```c
#include <stdio.h>
#include <stdlib.h>
#include "gzip.h"

int main() {
    const char* text = "Hello, World!";
    uint8_t* compressed_data;
    size_t compressed_len;

    if (gzip_compress_bytes((const uint8_t*)text, strlen(text), &compressed_data, &compressed_len)) {
        printf("Data compressed successfully. Compressed size: %zu bytes.\n", compressed_len);
        free(compressed_data);
    } else {
        printf("Compression failed.\n");
    }

    return 0;
}
```

## License
This library uses zlib, which is licensed under the **zlib License**. 
Ensure that you comply with the license when using or distributing this code.