# Crypto Module Documentation

This module provides cryptographic functions for generating cryptographically secure random numbers, password hashing, key generation, encryption, decryption, and random number generation using different algorithms like ChaCha20, Mersenne Twister, and Argon2id.

## Table of Contents
- [Crypto Module Documentation](#crypto-module-documentation)
  - [Table of Contents](#table-of-contents)
  - [Installation](#installation)
  - [Initialization and Cleanup](#initialization-and-cleanup)
    - [Functions:](#functions)
    - [Usage:](#usage)
  - [Key Generation](#key-generation)
    - [Functions:](#functions-1)
    - [Usage:](#usage-1)
  - [Encryption and Decryption](#encryption-and-decryption)
    - [Functions:](#functions-2)
    - [Usage:](#usage-2)
  - [Random Number Generation](#random-number-generation)
    - [ChaCha20-based Random Numbers](#chacha20-based-random-numbers)
    - [Mersenne Twister (Non-cryptographic Random Numbers)](#mersenne-twister-non-cryptographic-random-numbers)
    - [Usage:](#usage-3)
  - [Password Hashing and Verification](#password-hashing-and-verification)
    - [Functions:](#functions-3)
    - [Usage:](#usage-4)
  - [Base64 Encoding and Decoding](#base64-encoding-and-decoding)
    - [Functions:](#functions-4)
    - [Usage:](#usage-5)
  - [License](#license)

## Installation
See the [main README](../README.md) for installation instructions.

## Initialization and Cleanup

Before using the cryptographic functions, you must initialize the cryptographic library. At the end of your application, you should clean up resources.

### Functions:
- **`void crypto_init(void);`**  
  Initializes the cryptographic library (i.e., libsodium and OpenSSL). Must be called before using any cryptographic operations.

- **`void crypto_cleanup(void);`**  
  Cleans up any resources used by the cryptographic library.

### Usage:
```c
crypto_init();
// Use cryptographic functions...
crypto_cleanup();
```

## Key Generation

This library supports generating cryptographically secure keys using libsodium.

### Functions:
- **`char* crypto_generate_key(const char* master_password);`**  
  Generates a cryptographically secure random key based on the provided master password. It is the caller's responsibility to free the memory.

- **`bool crypto_verify_key(const char* key, const char* master_password);`**  
  Verifies if the provided key matches the master password.

### Usage:
```c
char* key = crypto_generate_key("my_master_password");
// Use the key...
free(key);
```

## Encryption and Decryption

The library supports encryption and decryption of data using a cryptographic key.

### Functions:
- **`uint8_t* crypto_encrypt(const uint8_t* data, size_t data_len, size_t* out_len, const unsigned char* secret_key);`**  
  Encrypts the given plaintext or binary data using the provided secret key. The length of the encrypted data is stored in `out_len`. Returns a heap-allocated pointer to the ciphertext or `NULL` on error.

- **`uint8_t* crypto_decrypt(const uint8_t* data, size_t data_len, size_t* out_len, const unsigned char* secret_key);`**  
  Decrypts the given ciphertext using the provided secret key. The length of the decrypted data is stored in `out_len`. Returns a heap-allocated pointer to the plaintext or `NULL` on error.

Because the encrypted data may contain null bytes, the length of the encrypted data is stored separately from the data itself. No assumption is made about null-termination.

### Usage:
```c
size_t encrypted_len, decrypted_len;
uint8_t* encrypted_data = crypto_encrypt(plaintext_data, plaintext_len, &encrypted_len, secret_key);
uint8_t* decrypted_data = crypto_decrypt(encrypted_data, encrypted_len, &decrypted_len, secret_key);

// Be sure to free the memory after use:
free(encrypted_data);
free(decrypted_data);

```

## Random Number Generation

This library provides multiple methods to generate random numbers using both cryptographic and non-cryptographic algorithms (ChaCha20 and Mersenne Twister).

### ChaCha20-based Random Numbers

- **`bool crypto_random_bytes(uint8_t* out, size_t out_len);`**  
  Fills the buffer with cryptographically secure random bytes using the ChaCha20 cipher. Returns `true` on success, `false` on failure.

- **`uint64_t crypto_random_uint64(void);`**  
  Generates a cryptographically secure random 64-bit unsigned integer.

- **`uint32_t crypto_random_uint32(void);`**  
  Generates a cryptographically secure random 32-bit unsigned integer.

- **`uint16_t crypto_random_uint16(void);`**  
  Generates a cryptographically secure random 16-bit unsigned integer.

- **`uint8_t crypto_random_uint8(void);`**  
  Generates a cryptographically secure random 8-bit unsigned integer.

### Mersenne Twister (Non-cryptographic Random Numbers)

- **`MTRand crypto_seedRand(uint32_t seed);`**  
  Initializes the Mersenne Twister random number generator with the given seed.

- **`uint32_t crypto_genRandLong(MTRand* rand);`**  
  Generates a random 32-bit unsigned integer using the Mersenne Twister algorithm.

- **`double crypto_genRand(MTRand* rand);`**  
  Generates a random double between 0 and 1 using the Mersenne Twister algorithm.

- **`uint32_t crypto_randRange(uint32_t min, uint32_t max);`**  
  Generates a random 32-bit unsigned integer between the specified `min` and `max`.

### Usage:
```c
uint8_t random_bytes[16];
crypto_random_bytes(random_bytes, 16);

MTRand mt_rand = crypto_seedRand(1234);
uint32_t rand_num = crypto_genRandLong(&mt_rand);
```

## Password Hashing and Verification

The library supports secure password hashing using the Argon2id algorithm from libsodium.

### Functions:
- **`bool crypto_password_hash(const char* password, char hash[CRYPTO_HASH_LENGTH]);`**  
  Generates a password hash using the Argon2id algorithm. Returns `true` on success, `false` on failure.

- **`bool crypto_password_verify(const char* password, const char* hash);`**  
  Verifies if the given password matches the hash.

### Usage:
```c
char hash[CRYPTO_HASH_LENGTH];
crypto_password_hash("my_password", hash);

bool is_valid = crypto_password_verify("my_password", hash);
```

## Base64 Encoding and Decoding

This library provides functions to encode and decode data using Base64, which is useful for storing and transmitting binary data like cryptographic keys.

### Functions:
- **`char* crypto_base64_encode(uint8_t* data, size_t data_len);`**  
  Encodes raw bytes into a Base64 string. The caller is responsible for freeing the returned string.

- **`uint8_t* crypto_base64_decode(const char* data, size_t* out_len);`**  
  Decodes a Base64 string back into raw bytes. The caller is responsible for freeing the returned buffer.

### Usage:
```c
char* encoded = crypto_base64_encode(key_data, key_data_len);
uint8_t* decoded = crypto_base64_decode(encoded, &decoded_len);
free(encoded);
free(decoded);
```

More examples can be found in the tests directory.
See the [crypto_test.c](../tests/crypto_test.c) for more examples.

## License
MIT

