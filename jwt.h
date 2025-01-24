#ifndef JWT_H
#define JWT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

// JWT Payload struct definition
typedef struct {
    char sub[256];      // Subject representing the user ID
    unsigned long exp;  // Expiration time as a UNIX timestamp
    char data[256];     // JSON data representing the user data
} JWTPayload;

// Error codes
typedef enum {
    JWT_SUCCESS = 0,
    JWT_ERROR_INVALID_INPUT,
    JWT_ERROR_MEMORY_ALLOCATION,
    JWT_ERROR_HMAC_CREATION,
    JWT_ERROR_BASE64_ENCODING,
    JWT_ERROR_BASE64_DECODING,
    JWT_ERROR_JSON_PARSING,
    JWT_ERROR_INVALID_FORMAT,
    JWT_ERROR_SIGNATURE_MISMATCH,
    JWT_ERROR_TOKEN_EXPIRED
} jwt_error_t;

const char* jwt_error_string(jwt_error_t error);

// Generate a JWT token for the given payload and secret.
// The token is written to out_token that is allocated by the function and must be freed by the caller.
// Returns JWT_SUCCESS on success, or an error code on failure. use jwt_error_string to get the error
// message.
jwt_error_t jwt_token_create(const JWTPayload* payload, const char* secret, char** out_token);

// Verify the JWT token using the given secret.
// The payload is written to p.
// Returns JWT_SUCCESS on success, or an error code on failure. use jwt_error_string to get the error
// message.
jwt_error_t jwt_token_verify(const char* token, const char* secret, JWTPayload* p);

// Function to parse the payload from the JWT token.
// The payload is written to p.
// Returns JWT_SUCCESS on success, or an error code on failure. use jwt_error_string to get the error
// message.
jwt_error_t jwt_parse_payload(const char* payload, JWTPayload* p);

#ifdef __cplusplus
}
#endif

#endif  // JWT_H
