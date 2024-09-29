# cipherkit

A collection of fast and secure cryptographic algorithms implemented in C on top of OpenSSL and Libsodium.
 
## API Documentation

1. [crypto](docs/crypto.md)
2. [gzip](docs/gzip.md)
3. [jwt](docs/jwt.md)

## Installation

Install the dependencies:

```bash
sudo apt-get install libssl-dev libsodium-dev zlib1g-dev pkg-config libjson-c-dev make
```

On Arch Linux:
```bash
sudo pacman -S openssl libsodium zlib pkg-config json-c make
```

Compile the library:
```bash
git clone githttps://github.com/abiiranathan/cipherkit.git
cd cipherkit
make

# To install the library
sudo make install
# Default installation path is /usr/local
# You can adjust it in the Makefile
```

## Linking
```bash
gcc -o example example.c `pkg-config --cflags --libs cipherkit`
```

## Running Tests
```bash
make test
```

## Memory Leak Check
```bash
make memcheck
```

## Examples

1. **Data Encryption and Decryption**

```c
#include <stdio.h>
#include <stdlib.h>
#include <cipherkit/crypto.h>


int main() {
    // Generate a cryptographic key from a master password
    const char* master_password = "testpassword";
    char* key = crypto_generate_key(master_password);
    LOG_ASSERT(key != NULL, "Failed to generate key");

    char data[] = "test data";
    size_t data_len = sizeof(data);
    size_t encrypted_len;
    size_t decrypted_len;

    // Encrypt the data
    uint8_t* encrypted_data =
    crypto_encrypt((uint8_t*)data, data_len, &encrypted_len, (unsigned char*)key);
    LOG_ASSERT(encrypted_data != NULL, "Failed to encrypt data");

    // Decrypt the data
    uint8_t* decrypted_data =
    crypto_decrypt(encrypted_data, encrypted_len, &decrypted_len, (unsigned char*)key);
    LOG_ASSERT(decrypted_data != NULL, "Failed to decrypt data");

    // Check if decrypted data matches original data
    LOG_ASSERT(decrypted_len == data_len,
             "Decrypted data length does not match original data length");
    LOG_ASSERT(memcmp(data, decrypted_data, data_len) == 0,
             "Decrypted data does not match original data");

    // Free allocated memory
    free(encrypted_data);
    free(decrypted_data);
    free(key);
    return 0;
}
```

Compile the example:
```bash
gcc -o example example.c `pkg-config --cflags --libs cipherkit`
```

Run the example:
```bash
./example
```

See docs and read the tests for more examples(Nothing beats the tests).

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License
MIT
