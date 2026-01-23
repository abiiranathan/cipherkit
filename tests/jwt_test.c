#include "../include/jwt.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SECRET "this-is-a-test-secret-key-that-is-at-least-32-bytes-long"

void test_jwt_token_create() {
    printf("Running test_jwt_token_create...\n");

    jwt_payload_t payload = {
        .sub = "1234567890",
        .exp = time(NULL) + 3600,  // 1 hour from now
        .data = "Test data",
    };

    char* token = NULL;
    jwt_error_t result = jwt_token_create(&payload, SECRET, &token);
    assert(token != NULL && "Token is NULL");
    assert(result == JWT_SUCCESS && "jwt_token_create failed");
    assert(strlen(token) > 0 && "Token is empty");

    printf("Created token: %s\n", token);
    free(token);
}

void test_jwt_token_verify_valid() {
    printf("Running test_jwt_token_verify_valid...\n");

    jwt_payload_t original_payload = {
        .sub = "1234567890",
        .exp = time(NULL) + 3600,  // 1 hour from now
        .data = "Test data",
    };

    char* token = NULL;
    jwt_error_t result = jwt_token_create(&original_payload, SECRET, &token);
    assert(result == JWT_SUCCESS && "jwt_token_create failed");

    jwt_payload_t verified_payload;
    result = jwt_token_verify(token, SECRET, &verified_payload);

    assert(result == JWT_SUCCESS && "jwt_token_verify failed");

    assert(strcmp(verified_payload.sub, original_payload.sub) == 0 && "Sub mismatch");
    assert(verified_payload.exp == original_payload.exp && "Exp mismatch");
    assert(strcmp(verified_payload.data, original_payload.data) == 0 && "Data mismatch");

    free(token);
}

void test_jwt_token_verify_invalid_signature() {
    printf("Running test_jwt_token_verify_invalid_signature...\n");

    jwt_payload_t payload = {.sub = "1234567890", .exp = time(NULL) + 3600, .data = "Test data"};

    char* token = NULL;
    jwt_error_t result = jwt_token_create(&payload, SECRET, &token);
    assert(result == JWT_SUCCESS && "jwt_token_create failed");

    // Modify the last character of the token to simulate an invalid signature
    token[strlen(token) - 1] = token[strlen(token) - 1] == 'A' ? 'B' : 'A';

    jwt_payload_t verified_payload;
    result = jwt_token_verify(token, SECRET, &verified_payload);

    assert(result == JWT_ERROR_SIGNATURE_MISMATCH && "Expected JWT_ERROR_SIGNATURE_MISMATCH");

    free(token);
}

void test_jwt_token_verify_expired() {
    printf("Running test_jwt_token_verify_expired...\n");

    jwt_payload_t payload = {
        .sub = "1234567890",
        .exp = time(NULL) - 3600,  // 1 hour in the past
        .data = "Test data",
    };

    char* token = NULL;
    jwt_error_t result = jwt_token_create(&payload, SECRET, &token);
    assert(result == JWT_SUCCESS && "jwt_token_create failed");

    jwt_payload_t verified_payload;
    result = jwt_token_verify(token, SECRET, &verified_payload);
    assert(result == JWT_ERROR_TOKEN_EXPIRED && "Expected JWT_ERROR_TOKEN_EXPIRED");
    free(token);
}

void test_jwt_token_create_invalid_input() {
    printf("Running test_jwt_token_create_invalid_input...\n");

    jwt_payload_t payload = {
        .sub = "",  // Empty subject
        .exp = time(NULL) + 3600,
        .data = "Test data",
    };

    char* token = NULL;
    jwt_error_t result = jwt_token_create(&payload, SECRET, &token);
    assert(result == JWT_ERROR_INVALID_INPUT && "Expected JWT_ERROR_INVALID_INPUT");
    assert(token == NULL && "Token should be NULL for invalid input");
}

void test_jwt_token_verify_invalid_format() {
    printf("Running test_jwt_token_verify_invalid_format...\n");

    const char* invalid_token = "invalid.token.format.with.too.many.parts";

    jwt_payload_t verified_payload;
    jwt_error_t result = jwt_token_verify(invalid_token, SECRET, &verified_payload);
    assert(result == JWT_ERROR_INVALID_FORMAT && "Expected JWT_ERROR_INVALID_FORMAT");
}

int main() {
    test_jwt_token_create();
    test_jwt_token_verify_valid();
    test_jwt_token_verify_invalid_signature();
    test_jwt_token_verify_expired();
    test_jwt_token_create_invalid_input();
    test_jwt_token_verify_invalid_format();

    printf("All tests completed.\n");
    return 0;
}
