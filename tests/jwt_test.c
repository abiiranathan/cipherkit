#include "../jwt.h"
#include "../logging.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#define SECRET "my_secret_key"

void test_jwt_token_create() {
  printf("Running test_jwt_token_create...\n");

  JWTPayload payload = {.sub = "1234567890",
                        .exp = (unsigned long)time(NULL) + 3600,  // 1 hour from now
                        .data = "Test data"};

  char* token = NULL;
  jwt_error_t result = jwt_token_create(&payload, SECRET, &token);

  LOG_ASSERT(result == JWT_SUCCESS, "jwt_token_create failed: %s", jwt_error_string(result));
  LOG_ASSERT(token != NULL, "Token is NULL");
  LOG_ASSERT(strlen(token) > 0, "Token is empty");

  printf("Created token: %s\n", token);

  free(token);
}

void test_jwt_token_verify_valid() {
  printf("Running test_jwt_token_verify_valid...\n");

  JWTPayload original_payload = {.sub = "1234567890",
                                 .exp = (unsigned long)time(NULL) + 3600,  // 1 hour from now
                                 .data = "Test data"};

  char* token = NULL;
  jwt_error_t result = jwt_token_create(&original_payload, SECRET, &token);
  LOG_ASSERT(result == JWT_SUCCESS, "jwt_token_create failed: %s", jwt_error_string(result));

  JWTPayload verified_payload;
  result = jwt_token_verify(token, SECRET, &verified_payload);

  LOG_ASSERT(result == JWT_SUCCESS, "jwt_token_verify failed: %s", jwt_error_string(result));
  LOG_ASSERT(strcmp(verified_payload.sub, original_payload.sub) == 0, "Sub mismatch");
  LOG_ASSERT(verified_payload.exp == original_payload.exp, "Exp mismatch");
  LOG_ASSERT(strcmp(verified_payload.data, original_payload.data) == 0, "Data mismatch");

  free(token);
}

void test_jwt_token_verify_invalid_signature() {
  printf("Running test_jwt_token_verify_invalid_signature...\n");

  JWTPayload payload = {.sub = "1234567890",
                        .exp = (unsigned long)time(NULL) + 3600,
                        .data = "Test data"};

  char* token = NULL;
  jwt_error_t result = jwt_token_create(&payload, SECRET, &token);
  LOG_ASSERT(result == JWT_SUCCESS, "jwt_token_create failed: %s", jwt_error_string(result));

  // Modify the last character of the token to simulate an invalid signature
  token[strlen(token) - 1] = token[strlen(token) - 1] == 'A' ? 'B' : 'A';

  JWTPayload verified_payload;
  result = jwt_token_verify(token, SECRET, &verified_payload);

  LOG_ASSERT(result == JWT_ERROR_SIGNATURE_MISMATCH,
             "Expected JWT_ERROR_SIGNATURE_MISMATCH, got: %s", jwt_error_string(result));

  free(token);
}

void test_jwt_token_verify_expired() {
  printf("Running test_jwt_token_verify_expired...\n");

  JWTPayload payload = {.sub = "1234567890",
                        .exp = (unsigned long)time(NULL) - 3600,  // 1 hour in the past
                        .data = "Test data"};

  char* token = NULL;
  jwt_error_t result = jwt_token_create(&payload, SECRET, &token);
  LOG_ASSERT(result == JWT_SUCCESS, "jwt_token_create failed: %s", jwt_error_string(result));

  JWTPayload verified_payload;
  result = jwt_token_verify(token, SECRET, &verified_payload);

  LOG_ASSERT(result == JWT_ERROR_TOKEN_EXPIRED, "Expected JWT_ERROR_TOKEN_EXPIRED, got: %s",
             jwt_error_string(result));

  free(token);
}

void test_jwt_token_create_invalid_input() {
  printf("Running test_jwt_token_create_invalid_input...\n");

  JWTPayload payload = {.sub = "",  // Empty subject
                        .exp = (unsigned long)time(NULL) + 3600,
                        .data = "Test data"};

  char* token = NULL;
  jwt_error_t result = jwt_token_create(&payload, SECRET, &token);

  LOG_ASSERT(result == JWT_ERROR_INVALID_INPUT, "Expected JWT_ERROR_INVALID_INPUT, got: %s",
             jwt_error_string(result));
  LOG_ASSERT(token == NULL, "Token should be NULL for invalid input");
}

void test_jwt_token_verify_invalid_format() {
  printf("Running test_jwt_token_verify_invalid_format...\n");

  const char* invalid_token = "invalid.token.format.with.too.many.parts";

  JWTPayload verified_payload;
  jwt_error_t result = jwt_token_verify(invalid_token, SECRET, &verified_payload);

  LOG_ASSERT(result == JWT_ERROR_INVALID_FORMAT, "Expected JWT_ERROR_INVALID_FORMAT, got: %s",
             jwt_error_string(result));
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
