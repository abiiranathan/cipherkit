#ifndef JWT_H
#define JWT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief JWT Payload structure.
 * 
 * Contains the standard claims and custom data.
 * fixed-width buffers are used for simplicity, but inputs are truncated safely.
 */
typedef struct {
    char sub[256];  /**< Subject (User ID) */
    int64_t exp;    /**< Expiration time (Unix timestamp) */
    char data[256]; /**< Custom user data */
} jwt_payload_t;

/**
 * @brief JWT Error codes.
 */
typedef enum {
    JWT_SUCCESS = 0,
    JWT_ERROR_INVALID_INPUT,
    JWT_ERROR_MEMORY_ALLOCATION,
    JWT_ERROR_HMAC_CREATION,
    JWT_ERROR_BASE64_ENCODING,
    JWT_ERROR_BASE64_DECODING,
    JWT_ERROR_JSON_GENERATION,
    JWT_ERROR_JSON_PARSING,
    JWT_ERROR_INVALID_FORMAT,
    JWT_ERROR_INVALID_ALGORITHM,
    JWT_ERROR_WEAK_SECRET,
    JWT_ERROR_SIGNATURE_MISMATCH,
    JWT_ERROR_TOKEN_EXPIRED,
    JWT_ERROR_UNKNOWN
} jwt_error_t;

/**
 * @brief Get a human-readable string for a JWT error code.
 * 
 * @param error The error code.
 * @return const char* String representation of the error.
 */
const char* jwt_error_string(jwt_error_t error);

/**
 * @brief Generate a JWT token (HS256).
 * 
 * Creates a standard JWT with Header.Payload.Signature.
 * The payload JSON is generated safely using yyjson to prevent injection.
 * 
 * @param payload Pointer to the payload structure containing claims.
 * @param secret The secret key used for HMAC signing (min 32 bytes recommended).
 * @param out_token Pointer to a char* that will be allocated. Caller must free().
 * @return jwt_error_t JWT_SUCCESS on success, error code otherwise.
 */
jwt_error_t jwt_token_create(const jwt_payload_t* payload, const char* secret, char** out_token);

/**
 * @brief Verify a JWT token.
 * 
 * Validates the signature, algorithm, structure, and expiration time.
 * 
 * @param token The raw JWT token string.
 * @param secret The secret key used to verify the HMAC signature.
 * @param out_payload Pointer to a structure where the parsed claims will be stored.
 * @return jwt_error_t JWT_SUCCESS on success, error code otherwise.
 */
jwt_error_t jwt_token_verify(const char* token, const char* secret, jwt_payload_t* out_payload);

/**
 * @brief Parse the payload component of a JWT without verification.
 * 
 * @warning This does not verify the signature. Only use this if the token 
 *          integrity has already been verified or for debugging.
 * 
 * @param raw_payload The decoded JSON string of the payload.
 * @param out_payload Pointer to the structure to fill.
 * @return jwt_error_t JWT_SUCCESS on success, error code otherwise.
 */
jwt_error_t jwt_parse_payload_json(const char* raw_payload, jwt_payload_t* out_payload);

#ifdef __cplusplus
}
#endif

#endif  // JWT_H
