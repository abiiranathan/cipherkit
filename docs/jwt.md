# JWT (JSON Web Token) C Library

This C library provides utilities to create, verify, and parse JSON Web Tokens (JWT) using HMAC-SHA256 for signing. JWTs are commonly used for securely transmitting information between parties as a JSON object, typically used in authorization and authentication mechanisms.

## Features

- **JWT Generation**: Create a JWT with a payload and a secret.
- **JWT Verification**: Verify a JWT using a secret, and retrieve the payload.
- **JWT Payload Parsing**: Parse the payload from a JWT without verification.
- Provides detailed error handling with descriptive error codes.

## Installation

## Installation

See the [main README](../README.md) for installation instructions.

## API Documentation

### Structures and Types

#### `JWTPayload`

This structure represents the payload of a JWT:

```c
typedef struct {
  char sub[256];      // Subject representing the user ID
  unsigned long exp;  // Expiration time as a UNIX timestamp
  char data[256];     // JSON data representing the user data
} JWTPayload;
```

- **`sub`**: User identifier (Subject).
- **`exp`**: Expiration time of the token (in UNIX timestamp).
- **`data`**: Additional JSON data.

#### `jwt_error_t`

Enum representing the possible error codes returned by the JWT functions:

```c
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
```

Use `jwt_error_string()` to convert the error code into a human-readable string.

### Error Handling

#### `const char* jwt_error_string(jwt_error_t error);`

Returns a string describing the error code.

- **Parameters**:
  - `error`: The `jwt_error_t` error code.
- **Returns**: A pointer to a constant string literal containing the error description.

### JWT Token Creation

#### `jwt_error_t jwt_token_create(const JWTPayload* payload, const char* secret, char** out_token);`

Generates a JWT for the provided payload using the given secret.

- **Parameters**:
  - `payload`: A pointer to the `JWTPayload` structure containing the token's payload.
  - `secret`: The secret key used for signing the token.
  - `out_token`: A pointer to the buffer that will contain the generated token. The buffer is allocated by the function and must be freed by the caller.
- **Returns**: `JWT_SUCCESS` on success, or an error code on failure.

_Note_: The caller is responsible for freeing the `out_token` buffer.

### JWT Token Verification

#### `jwt_error_t jwt_token_verify(const char* token, const char* secret, JWTPayload* p);`

Verifies the JWT signature and decodes the payload using the provided secret.

- **Parameters**:
  - `token`: The JWT token to verify.
  - `secret`: The secret key used for verifying the token.
  - `p`: A pointer to the `JWTPayload` structure that will receive the decoded payload.
- **Returns**: `JWT_SUCCESS` on success, or an error code on failure.

### JWT Payload Parsing

#### `jwt_error_t jwt_parse_payload(const char* payload, JWTPayload* p);`

Parses the payload of a JWT without verifying its signature.

- **Parameters**:
  - `payload`: The base64-encoded payload string.
  - `p`: A pointer to the `JWTPayload` structure that will receive the parsed payload.
- **Returns**: `JWT_SUCCESS` on success, or an error code on failure.

## Example Usage

### JWT Token Creation

```c
#include <stdio.h>
#include <stdlib.h>
#include <cipherkit/jwt.h>

int main() {
    JWTPayload payload = { "user123", 1699999999, "{\"role\":\"admin\"}" };
    char* token = nullptr;

    jwt_error_t result = jwt_token_create(&payload, "mysecretkey", &token);

    if (result == JWT_SUCCESS) {
        printf("JWT Token: %s\n", token);
        free(token);
    } else {
        printf("Error creating JWT: %s\n", jwt_error_string(result));
    }

    return 0;
}
```

### JWT Token Verification

```c
#include <stdio.h>
#include <cipherkit/jwt.h>

int main() {
    const char* token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";  // Example JWT token
    JWTPayload payload;

    jwt_error_t result = jwt_token_verify(token, "mysecretkey", &payload);

    if (result == JWT_SUCCESS) {
        printf("Token verified successfully!\n");
        printf("Subject: %s\n", payload.sub);
        printf("Expiration: %lu\n", payload.exp);
        printf("Data: %s\n", payload.data);
    } else {
        printf("JWT verification failed: %s\n", jwt_error_string(result));
    }

    return 0;
}
```

## License

This library is licensed under the MIT License.
You are free to use, modify, and distribute this code, provided that you include attribution to the original author(s).

Make sure to comply with the licenses of any third-party libraries used in conjunction with this code.
