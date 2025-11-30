#include "../include/crypto.h"
#include "../include/logging.h"

#include <string.h>
#include <sys/cdefs.h>

/** Initializes cryptographic libraries (libsodium and OpenSSL). */
static void crypto_init(void) {
    // Initialize the sodium library
    if (sodium_init() == -1) {
        LOG_FATAL("Failed to initialize the sodium library");
    }

    // Initialize the OpenSSL library
    OpenSSL_add_all_algorithms();

    // Initialize the crypto library
    int ret = OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    if (ret != 1) {
        LOG_FATAL("Failed to initialize the crypto library");
    }

    // Initialize the random number generator
    ret = RAND_poll();
    if (ret != 1) {
        LOG_FATAL("Failed to initialize the random number generator");
    }
}

/** Cleans up OpenSSL resources. */
static void crypto_cleanup(void) {
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
}

// Initialization constructor - runs before main()
__attribute__((constructor(200))) void __initialize_crypto(void) {
    crypto_init();
}

// Destructor - runs after main()
__attribute__((destructor(300))) void __cleanup_crypto(void) {
    crypto_cleanup();
}

// ============================================================================
// Key Generation and Verification
// ============================================================================

char* crypto_generate_key(const char* master_password) {
    if (master_password == NULL) {
        LOG_ERROR("Master password cannot be NULL");
        return NULL;
    }

    size_t password_len = strlen(master_password);
    if (password_len == 0) {
        LOG_ERROR("Master password cannot be empty");
        return NULL;
    }

    uint8_t salt[crypto_pwhash_SALTBYTES];
    randombytes_buf(salt, sizeof(salt));

    // Derive the key using the master password and the salt
    uint8_t derived_key[crypto_secretbox_KEYBYTES];
    if (crypto_pwhash(derived_key, sizeof(derived_key), master_password, password_len, salt,
                      crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_DEFAULT) != 0) {
        LOG_ERROR("Failed to derive the key");
        return NULL;
    }

    // Buffer to hold the salt and the derived key
    uint8_t key_with_salt[crypto_pwhash_SALTBYTES + crypto_secretbox_KEYBYTES];

    // Copy the salt to the beginning of the buffer
    memcpy(key_with_salt, salt, sizeof(salt));

    // Copy the derived key after the salt
    memcpy(key_with_salt + sizeof(salt), derived_key, sizeof(derived_key));

    // Encode the salt and derived key to hex
    size_t key_with_salt_len = sizeof(key_with_salt);
    size_t max_hex_len = key_with_salt_len * 2 + 1;  // 2 hex chars per byte + null terminator
    char* encoded_key = malloc(max_hex_len);
    if (encoded_key == NULL) {
        LOG_ERROR("Failed to allocate memory for the encoded key");
        return NULL;
    }

    sodium_bin2hex(encoded_key, max_hex_len, key_with_salt, key_with_salt_len);

    // Clear sensitive data from stack
    sodium_memzero(derived_key, sizeof(derived_key));
    sodium_memzero(key_with_salt, sizeof(key_with_salt));

    return encoded_key;
}

bool crypto_verify_key(const char* encoded_key, const char* master_password) {
    if (encoded_key == NULL || master_password == NULL) {
        LOG_ERROR("Encoded key and master password cannot be NULL");
        return false;
    }

    size_t encoded_len = strlen(encoded_key);
    if (encoded_len == 0 || encoded_len % 2 != 0) {
        LOG_ERROR("Invalid encoded key length");
        return false;
    }

    size_t password_len = strlen(master_password);
    if (password_len == 0) {
        LOG_ERROR("Master password cannot be empty");
        return false;
    }

    // Calculate the length of the binary data
    size_t key_with_salt_len = encoded_len / 2;
    size_t expected_len = crypto_pwhash_SALTBYTES + crypto_secretbox_KEYBYTES;

    if (key_with_salt_len != expected_len) {
        LOG_ERROR("Invalid encoded key length: expected %zu bytes, got %zu bytes", expected_len,
                  key_with_salt_len);
        return false;
    }

    uint8_t* key_with_salt = malloc(key_with_salt_len);
    if (key_with_salt == NULL) {
        LOG_ERROR("Failed to allocate memory for the key with salt");
        return false;
    }

    // Decode the hex string back to binary
    if (sodium_hex2bin(key_with_salt, key_with_salt_len, encoded_key, encoded_len, NULL, NULL,
                       NULL) != 0) {
        LOG_ERROR("Failed to decode the hex string");
        free(key_with_salt);
        return false;
    }

    // Extract the salt from the decoded binary data
    uint8_t salt[crypto_pwhash_SALTBYTES];
    memcpy(salt, key_with_salt, crypto_pwhash_SALTBYTES);

    // Derive the key using the master password and extracted salt
    uint8_t derived_key[crypto_secretbox_KEYBYTES];
    if (crypto_pwhash(derived_key, sizeof(derived_key), master_password, password_len, salt,
                      crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_DEFAULT) != 0) {
        LOG_ERROR("Failed to derive the key");
        sodium_memzero(key_with_salt, key_with_salt_len);
        free(key_with_salt);
        return false;
    }

    // Compare the derived key with the stored derived key using constant-time comparison
    bool result = (sodium_memcmp(derived_key, key_with_salt + crypto_pwhash_SALTBYTES,
                                 crypto_secretbox_KEYBYTES) == 0);

    // Clear sensitive data and free memory
    sodium_memzero(derived_key, sizeof(derived_key));
    sodium_memzero(key_with_salt, key_with_salt_len);
    free(key_with_salt);

    return result;
}

// ============================================================================
// Encryption and Decryption (AES-128-ECB)
// ============================================================================

uint8_t* crypto_encrypt(const uint8_t* data, size_t data_len, size_t* out_len,
                        const unsigned char* secret_key) {
    if (data == NULL || out_len == NULL || secret_key == NULL) {
        LOG_ERROR("Invalid parameters: data, out_len, and secret_key cannot be NULL");
        return NULL;
    }

    if (data_len == 0) {
        LOG_ERROR("Data length cannot be zero");
        return NULL;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        LOG_ERROR("Failed to initialize EVP_CIPHER_CTX");
        return NULL;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, secret_key, NULL) != 1) {
        LOG_ERROR("Failed to initialize encryption");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    int block_size = EVP_CIPHER_block_size(EVP_aes_128_ecb());

    // Allocate buffer for ciphertext (data + padding)
    uint8_t* ciphertext = malloc(data_len + (size_t)block_size);
    if (ciphertext == NULL) {
        LOG_ERROR("Failed to allocate memory for ciphertext");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    int len = 0;
    int ciphertext_len = 0;

    // Encrypt the data
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, data, (int)data_len) != 1) {
        LOG_ERROR("Failed to encrypt data");
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    ciphertext_len = len;

    // Finalize encryption (add padding)
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        LOG_ERROR("Failed to finalize encryption");
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    // Reallocate buffer to fit the exact ciphertext length
    uint8_t* trimmed_ciphertext = realloc(ciphertext, (size_t)ciphertext_len);
    if (trimmed_ciphertext == NULL) {
        // realloc failed, but original buffer is still valid
        LOG_ERROR("Failed to reallocate memory for ciphertext");
        free(ciphertext);
        return NULL;
    }

    *out_len = (size_t)ciphertext_len;
    return trimmed_ciphertext;
}

uint8_t* crypto_decrypt(const uint8_t* data, size_t data_len, size_t* out_len,
                        const unsigned char* secret_key) {
    if (data == NULL || out_len == NULL || secret_key == NULL) {
        LOG_ERROR("Invalid parameters: data, out_len, and secret_key cannot be NULL");
        return NULL;
    }

    if (data_len == 0) {
        LOG_ERROR("Data length cannot be zero");
        return NULL;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        LOG_ERROR("Failed to initialize EVP_CIPHER_CTX");
        return NULL;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, secret_key, NULL) != 1) {
        LOG_ERROR("Failed to initialize decryption");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    int block_size = EVP_CIPHER_block_size(EVP_aes_128_ecb());

    // Allocate buffer for plaintext
    uint8_t* plaintext = malloc(data_len + (size_t)block_size);
    if (plaintext == NULL) {
        LOG_ERROR("Failed to allocate memory for plaintext");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    int len = 0;
    int plaintext_len = 0;

    // Decrypt the data
    if (EVP_DecryptUpdate(ctx, plaintext, &len, data, (int)data_len) != 1) {
        LOG_ERROR("Failed to decrypt data");
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    plaintext_len = len;

    // Finalize decryption (handle padding)
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        LOG_ERROR("Failed to finalize decryption (padding error or authentication failure)");
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    // Reallocate buffer to fit the exact plaintext length
    uint8_t* trimmed_plaintext = realloc(plaintext, (size_t)plaintext_len);
    if (trimmed_plaintext == NULL) {
        // realloc failed, but original buffer is still valid
        LOG_ERROR("Failed to reallocate memory for plaintext");
        free(plaintext);
        return NULL;
    }

    *out_len = (size_t)plaintext_len;
    return trimmed_plaintext;
}

// ============================================================================
// Base64 Encoding and Decoding
// ============================================================================

char* crypto_base64_encode(uint8_t* data, size_t data_len) {
    if (data == NULL) {
        LOG_ERROR("Data cannot be NULL");
        return NULL;
    }

    if (data_len == 0) {
        LOG_ERROR("Data length cannot be zero");
        return NULL;
    }

    BIO* b64 = BIO_new(BIO_f_base64());
    if (b64 == NULL) {
        LOG_ERROR("Failed to create base64 BIO");
        return NULL;
    }

    BIO* bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        LOG_ERROR("Failed to create memory BIO");
        BIO_free(b64);
        return NULL;
    }

    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);  // Disable newlines

    int write_ret = BIO_write(bio, data, (int)data_len);
    if (write_ret <= 0) {
        LOG_ERROR("Failed to write data to BIO");
        BIO_free_all(bio);
        return NULL;
    }

    if (BIO_flush(bio) != 1) {
        LOG_ERROR("Failed to flush BIO");
        BIO_free_all(bio);
        return NULL;
    }

    BUF_MEM* bufferPtr = NULL;
    BIO_get_mem_ptr(bio, &bufferPtr);
    if (bufferPtr == NULL || bufferPtr->data == NULL) {
        LOG_ERROR("Failed to get BIO memory pointer");
        BIO_free_all(bio);
        return NULL;
    }

    char* b64text = malloc(bufferPtr->length + 1);  // +1 for null terminator
    if (b64text == NULL) {
        LOG_ERROR("Failed to allocate memory for base64 string");
        BIO_free_all(bio);
        return NULL;
    }

    memcpy(b64text, bufferPtr->data, bufferPtr->length);
    b64text[bufferPtr->length] = '\0';  // Null-terminate the string

    BIO_free_all(bio);
    return b64text;
}

uint8_t* crypto_base64_decode(const char* data, size_t* out_len) {
    if (data == NULL || out_len == NULL) {
        LOG_ERROR("Data and out_len cannot be NULL");
        return NULL;
    }

    size_t data_len = strlen(data);
    if (data_len == 0) {
        LOG_ERROR("Data length cannot be zero");
        return NULL;
    }

    // Create memory BIO for encoded data
    BIO* bio_mem = BIO_new_mem_buf((void*)data, (int)data_len);
    if (bio_mem == NULL) {
        LOG_ERROR("Failed to create memory BIO");
        return NULL;
    }

    // Create Base64 filter BIO
    BIO* bio_b64 = BIO_new(BIO_f_base64());
    if (bio_b64 == NULL) {
        LOG_ERROR("Failed to create base64 BIO");
        BIO_free(bio_mem);
        return NULL;
    }

    // Set decode mode, no newline characters expected
    BIO_set_flags(bio_b64, BIO_FLAGS_BASE64_NO_NL);

    // Chain the BIOs
    bio_b64 = BIO_push(bio_b64, bio_mem);

    // Allocate buffer for decoded data (base64 decoding produces at most 3/4 of input size)
    size_t estimated_size = (data_len * 3) / 4 + 1;
    uint8_t* buffer = malloc(estimated_size);
    if (buffer == NULL) {
        LOG_ERROR("Failed to allocate memory for decoded data");
        BIO_free_all(bio_b64);
        return NULL;
    }

    memset(buffer, 0, estimated_size);

    // Decode the data
    int decode_len = BIO_read(bio_b64, buffer, (int)estimated_size);
    if (decode_len < 0) {
        LOG_ERROR("Failed to decode base64 data");
        free(buffer);
        BIO_free_all(bio_b64);
        return NULL;
    }

    *out_len = (size_t)decode_len;
    BIO_free_all(bio_b64);

    return buffer;
}

// ============================================================================
// Cryptographically Secure Random Number Generation
// ============================================================================

bool crypto_random_bytes(uint8_t* out, size_t out_len) {
    if (out == NULL) {
        LOG_ERROR("Output buffer cannot be NULL");
        return false;
    }

    if (out_len == 0) {
        LOG_ERROR("Output length cannot be zero");
        return false;
    }

    // Use OpenSSL's RAND_bytes for cryptographically secure random bytes
    if (RAND_bytes(out, (int)out_len) != 1) {
        LOG_ERROR("Failed to generate random bytes");
        return false;
    }

    return true;
}

uint64_t crypto_random_uint64(void) {
    uint64_t random_value = 0;
    if (!crypto_random_bytes((uint8_t*)&random_value, sizeof(random_value))) {
        LOG_ERROR("Failed to generate random uint64");
        return 0;
    }
    return random_value;
}

uint32_t crypto_random_uint32(void) {
    uint32_t random_value = 0;
    if (!crypto_random_bytes((uint8_t*)&random_value, sizeof(random_value))) {
        LOG_ERROR("Failed to generate random uint32");
        return 0;
    }
    return random_value;
}

uint16_t crypto_random_uint16(void) {
    uint16_t random_value = 0;
    if (!crypto_random_bytes((uint8_t*)&random_value, sizeof(random_value))) {
        LOG_ERROR("Failed to generate random uint16");
        return 0;
    }
    return random_value;
}

uint8_t crypto_random_uint8(void) {
    uint8_t random_value = 0;
    if (!crypto_random_bytes((uint8_t*)&random_value, sizeof(random_value))) {
        LOG_ERROR("Failed to generate random uint8");
        return 0;
    }
    return random_value;
}

// ============================================================================
// Non-Cryptographic Random Number Generator (Mersenne Twister)
// ============================================================================

/* An implementation of the MT19937 Algorithm for the Mersenne Twister
 * by Evan Sultanik.  Based upon the pseudocode in: M. Matsumoto and
 * T. Nishimura, "Mersenne Twister: A 623-dimensionally
 * equidistributed uniform pseudorandom number generator," ACM
 * Transactions on Modeling and Computer Simulation Vol. 8, No. 1,
 * January pp.3-30 1998.
 *
 * http://www.sultanik.com/Mersenne_twister
 */

#define UPPER_MASK 0x80000000
#define LOWER_MASK 0x7fffffff
#define TEMPERING_MASK_B 0x9d2c5680
#define TEMPERING_MASK_C 0xefc60000

/** Seeds the Mersenne Twister PRNG with the given seed value. */
inline static void m_seedRand(MTRand* rand, uint32_t seed) {
    if (rand == NULL) {
        return;
    }

    /* Set initial seeds to mt[STATE_VECTOR_LENGTH] using the generator
     * from Line 25 of Table 1 in: Donald Knuth, "The Art of Computer
     * Programming," Vol. 2 (2nd Ed.) pp.102.
     */
    rand->mt[0] = seed & 0xffffffff;
    for (rand->index = 1; rand->index < STATE_VECTOR_LENGTH; rand->index++) {
        rand->mt[rand->index] = (6069 * rand->mt[rand->index - 1]) & 0xffffffff;
    }
}

MTRand crypto_seedRand(uint32_t seed) {
    MTRand rand = {0};
    m_seedRand(&rand, seed);
    return rand;
}

uint32_t crypto_genRandLong(MTRand* rand) {
    if (rand == NULL) {
        LOG_ERROR("MTRand pointer cannot be NULL");
        return 0;
    }

    uint32_t y;
    static const uint32_t mag[2] = {0x0, 0x9908b0df};  // mag[x] = x * 0x9908b0df for x = 0,1

    if (rand->index >= STATE_VECTOR_LENGTH || rand->index < 0) {
        // Generate STATE_VECTOR_LENGTH words at a time
        int32_t kk;

        // Re-seed if uninitialized
        if (rand->index >= STATE_VECTOR_LENGTH + 1 || rand->index < 0) {
            m_seedRand(rand, 4357);
        }

        for (kk = 0; kk < STATE_VECTOR_LENGTH - STATE_VECTOR_M; kk++) {
            y = (rand->mt[kk] & UPPER_MASK) | (rand->mt[kk + 1] & LOWER_MASK);
            rand->mt[kk] = rand->mt[kk + STATE_VECTOR_M] ^ (y >> 1) ^ mag[y & 0x1];
        }

        for (; kk < STATE_VECTOR_LENGTH - 1; kk++) {
            y = (rand->mt[kk] & UPPER_MASK) | (rand->mt[kk + 1] & LOWER_MASK);
            rand->mt[kk] =
                rand->mt[kk + (STATE_VECTOR_M - STATE_VECTOR_LENGTH)] ^ (y >> 1) ^ mag[y & 0x1];
        }

        y = (rand->mt[STATE_VECTOR_LENGTH - 1] & UPPER_MASK) | (rand->mt[0] & LOWER_MASK);
        rand->mt[STATE_VECTOR_LENGTH - 1] = rand->mt[STATE_VECTOR_M - 1] ^ (y >> 1) ^ mag[y & 0x1];

        rand->index = 0;
    }

    y = rand->mt[rand->index++];
    y ^= (y >> 11);
    y ^= (y << 7) & TEMPERING_MASK_B;
    y ^= (y << 15) & TEMPERING_MASK_C;
    y ^= (y >> 18);

    return y;
}

double crypto_genRand(MTRand* rand) {
    if (rand == NULL) {
        LOG_ERROR("MTRand pointer cannot be NULL");
        return 0.0;
    }

    return ((double)crypto_genRandLong(rand) / (double)0xffffffff);
}

uint32_t crypto_randRange(uint32_t min, uint32_t max) {
    if (min > max) {
        LOG_ERROR("Invalid range: min (%u) > max (%u)", min, max);
        return min;
    }

    if (min == max) {
        return min;
    }

    uint32_t seed = crypto_random_uint32();
    MTRand rand = crypto_seedRand(seed);
    uint32_t range = max - min + 1;

    return (crypto_genRandLong(&rand) % range) + min;
}

// ============================================================================
// Password Hashing and Verification
// ============================================================================

bool crypto_password_hash(const char* password, char hash[CRYPTO_HASH_LENGTH]) {
    if (password == NULL || hash == NULL) {
        LOG_ERROR("Password and hash buffer cannot be NULL");
        return false;
    }

    size_t password_len = strlen(password);
    if (password_len == 0) {
        LOG_ERROR("Password cannot be empty");
        return false;
    }

    // Hash the password using libsodium's password hashing (includes salt generation)
    if (crypto_pwhash_str(hash, password, password_len, crypto_pwhash_OPSLIMIT_INTERACTIVE,
                          crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
        LOG_ERROR("Failed to hash password (out of memory)");
        return false;
    }

    return true;
}

bool crypto_password_verify(const char* password, const char* hash) {
    if (password == NULL || hash == NULL) {
        LOG_ERROR("Password and hash cannot be NULL");
        return false;
    }

    size_t password_len = strlen(password);
    if (password_len == 0) {
        LOG_ERROR("Password cannot be empty");
        return false;
    }

    // Verify the password against the hash
    if (crypto_pwhash_str_verify(hash, password, password_len) != 0) {
        return false;
    }

    return true;
}
