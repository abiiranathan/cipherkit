#ifndef BE4FD858_E745_486F_B1AF_99C95F83CAAC
#define BE4FD858_E745_486F_B1AF_99C95F83CAAC

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <sodium.h>

// Constants for the crypto library
#define CRYPTO_SALT_LENGTH crypto_pwhash_SALTBYTES
#define CRYPTO_HASH_LENGTH crypto_pwhash_STRBYTES

// uses libsoodium to generate a cryptographically secure random key.
// Returns a pointer to a string containing the null-terminated key.
// It is the caller's responsibility to free the memory.
char* crypto_generate_key(const char* master_password);

// Verifies if the given key is valid.
bool crypto_verify_key(const char* key, const char* master_password);

// Encrypts the given plain test or binary data using the given key.
// The length of the data is stored in out_len.
// Returns a heap-allocated pointer to the ciphertext or NULL on error.
uint8_t* crypto_encrypt(const uint8_t* data, size_t data_len, size_t* out_len,
                        const unsigned char* secret_key);

// Decrypts the given ciphertext using the given key.
// The length of the data is stored in out_len.
// Returns a heap-allocated pointer to the data or NULL on error.
uint8_t* crypto_decrypt(const uint8_t* data, size_t data_len, size_t* out_len,
                        const unsigned char* secret_key);

// base64 encode raw bytes to a string. It can be used to encode the key.
char* crypto_base64_encode(uint8_t* data, size_t data_len);

// base64 decode raw bytes to a string. It can be used to decode the key.
uint8_t* crypto_base64_decode(const char* data, size_t* out_len);

#define CHACHA20_KEY_SIZE 32  // 256 bits
#define CHACHA20_IV_SIZE 12   // 96 bits

/* Generates cryptographically secure random bytes using ChaCha20 cipher.
* The key and IV are generated using the RAND_bytes function from OpenSSL.
* Returns true on success, false on failure.
* 
* @param out: pointer to the buffer where the random bytes will be stored.
* @param out_len: the number of random bytes to generate.
*/
bool crypto_random_bytes(uint8_t* out, size_t out_len);

// Generates a random uint8_t using the ChaCha20 cipher.
// This is cryptographically secure but may be slower than the rand() function,
// Mersenne Twister, or other PRNGs.
uint64_t crypto_random_uint64(void);

// Generates a random uint32_t.
// This is cryptographically secure but may be slower than the rand() function,
// Mersenne Twister, or other PRNGs.
uint32_t crypto_random_uint32(void);

// Generates a random uint16_t.
// This is cryptographically secure but may be slower than the rand() function,
// Mersenne Twister, or other PRNGs.
uint16_t crypto_random_uint16(void);

// Generates a random uint8_t.
// This is cryptographically secure but may be slower than the rand() function,
// Mersenne Twister, or other PRNGs.
uint8_t crypto_random_uint8(void);

// ============ FASTER NON-CRYPTOGRAPHIC RANDOM NUMBER GENERATOR ============
/* An implementation of the MT19937 Algorithm for the Mersenne Twister
* https://github.com/ESultanik/mtwister/blob/master/mtwister.h
* 
* by Evan Sultanik.  Based upon the pseudocode in: M. Matsumoto and
* T. Nishimura, "Mersenne Twister: A 623-dimensionally
* equidistributed uniform pseudorandom number generator," ACM
* Transactions on Modeling and Computer Simulation Vol. 8, No. 1,
* January pp.3-30 1998.
*
* http://www.sultanik.com/Mersenne_twister
* 
* Licence: 
* Public domain. Have fun!
*/

#define STATE_VECTOR_LENGTH 624
#define STATE_VECTOR_M 397 /* changes to STATE_VECTOR_LENGTH also require changes to this */

typedef struct tagMTRand {
    uint32_t mt[STATE_VECTOR_LENGTH];
    int32_t index;
} MTRand;

// Initializes the Mersenne Twister random number generator with the given seed.
MTRand crypto_seedRand(uint32_t seed);

// Generates a random uint32_t using the Mersenne Twister algorithm.
uint32_t crypto_genRandLong(MTRand* rand);

// Generates a random double between 0 and 1 using the Mersenne Twister algorithm.
double crypto_genRand(MTRand* rand);

// Generates a random uint32_t between min and max using the Mersenne Twister algorithm.
uint32_t crypto_randRange(uint32_t min, uint32_t max);

// ============= Password hashing and verification =============

// Generate a password hash. Returns 0 on success, -1 on failure
// You must initialize libsodium with sodium_init() before calling this function
// uses argon2id algorithm from libsodium.
bool crypto_password_hash(const char* password, char hash[CRYPTO_HASH_LENGTH]);

// Verify a password hash. Returns true if the password matches the hash, false otherwise
// uses argon2id algorithm from libsodium.
bool crypto_password_verify(const char* password, const char* hash);

#ifdef __cplusplus
}
#endif

#endif /* BE4FD858_E745_486F_B1AF_99C95F83CAAC */
