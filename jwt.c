#include "jwt.h"
#include "crypto.h"
#include "logging.h"

#include <cjson/cJSON.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define JWT_HEADER "{\"alg\":\"HS256\",\"typ\":\"JWT\"}"
#define JWT_MAX_LEN 8192  // Maximum length for JWT token (8KB)

const char* jwt_error_string(jwt_error_t error) {
  switch (error) {
    case JWT_SUCCESS:
      return "Success";
    case JWT_ERROR_INVALID_INPUT:
      return "Invalid input";
    case JWT_ERROR_MEMORY_ALLOCATION:
      return "Memory allocation failed";
    case JWT_ERROR_HMAC_CREATION:
      return "HMAC creation failed";
    case JWT_ERROR_BASE64_ENCODING:
      return "Base64 encoding failed";
    case JWT_ERROR_BASE64_DECODING:
      return "Base64 decoding failed";
    case JWT_ERROR_JSON_PARSING:
      return "JSON parsing failed";
    case JWT_ERROR_INVALID_FORMAT:
      return "Invalid JWT format";
    case JWT_ERROR_SIGNATURE_MISMATCH:
      return "Signature mismatch";
    case JWT_ERROR_TOKEN_EXPIRED:
      return "Token expired";
    default:
      return "Unknown error";
  }
}

static jwt_error_t create_hmac_sha256(const char* key, const char* data,
                                      unsigned char hmac_buf[EVP_MAX_MD_SIZE], unsigned int* len) {
  if (!key || !data || !hmac_buf || !len) {
    return JWT_ERROR_INVALID_INPUT;
  }

  ERR_clear_error();
  HMAC(EVP_sha256(), key, strlen(key), (unsigned char*)data, strlen(data), hmac_buf, len);

  if (ERR_get_error()) {
    LOG_ERROR("Failed to create HMAC SHA-256 signature.");
    return JWT_ERROR_HMAC_CREATION;
  }

  return JWT_SUCCESS;
}

static jwt_error_t jwt_generate(const JWTPayload* payload, const char* secret, char** out_token) {
  if (!payload || !secret || !out_token) {
    return JWT_ERROR_INVALID_INPUT;
  }

  *out_token = NULL;
  jwt_error_t result = JWT_SUCCESS;
  char *payload_str = NULL, *encoded_header = NULL, *encoded_payload = NULL;
  char *message = NULL, *encoded_signature = NULL, *jwt_token = NULL;

  cJSON* json = cJSON_CreateObject();
  if (!json) {
    result = JWT_ERROR_MEMORY_ALLOCATION;
    goto cleanup;
  }

  cJSON_AddStringToObject(json, "sub", payload->sub);
  cJSON_AddNumberToObject(json, "exp", payload->exp);
  cJSON_AddStringToObject(json, "data", payload->data);

  payload_str = cJSON_PrintUnformatted(json);
  if (!payload_str) {
    result = JWT_ERROR_MEMORY_ALLOCATION;
    goto cleanup;
  }

  encoded_header = crypto_base64_encode((unsigned char*)JWT_HEADER, strlen(JWT_HEADER));
  encoded_payload = crypto_base64_encode((unsigned char*)payload_str, strlen(payload_str));

  if (!encoded_header || !encoded_payload) {
    result = JWT_ERROR_BASE64_ENCODING;
    goto cleanup;
  }

  size_t message_len = strlen(encoded_header) + strlen(encoded_payload) + 2;
  message = (char*)malloc(message_len);
  if (!message) {
    result = JWT_ERROR_MEMORY_ALLOCATION;
    goto cleanup;
  }

  snprintf(message, message_len, "%s.%s", encoded_header, encoded_payload);

  unsigned int hmac_len = 0;
  unsigned char hmac[EVP_MAX_MD_SIZE] = {0};
  result = create_hmac_sha256(secret, message, hmac, &hmac_len);
  if (result != JWT_SUCCESS) {
    goto cleanup;
  }

  encoded_signature = crypto_base64_encode(hmac, hmac_len);
  if (!encoded_signature) {
    result = JWT_ERROR_BASE64_ENCODING;
    goto cleanup;
  }

  size_t jwt_token_len = strlen(message) + strlen(encoded_signature) + 2;
  if (jwt_token_len > JWT_MAX_LEN) {
    result = JWT_ERROR_INVALID_INPUT;
    goto cleanup;
  }

  jwt_token = (char*)malloc(jwt_token_len);
  if (!jwt_token) {
    result = JWT_ERROR_MEMORY_ALLOCATION;
    goto cleanup;
  }

  snprintf(jwt_token, jwt_token_len, "%s.%s", message, encoded_signature);
  *out_token = jwt_token;

cleanup:
  cJSON_Delete(json);
  free(payload_str);
  free(encoded_header);
  free(encoded_payload);
  free(message);
  free(encoded_signature);

  if (result != JWT_SUCCESS && jwt_token) {
    free(jwt_token);
    *out_token = NULL;
  }

  return result;
}

jwt_error_t jwt_parse_payload(const char* payload, JWTPayload* p) {
  if (!payload || !p) {
    return JWT_ERROR_INVALID_INPUT;
  }

  cJSON* json = cJSON_Parse(payload);
  if (!json) {
    return JWT_ERROR_JSON_PARSING;
  }

  cJSON* sub = cJSON_GetObjectItemCaseSensitive(json, "sub");
  cJSON* exp = cJSON_GetObjectItemCaseSensitive(json, "exp");
  cJSON* data = cJSON_GetObjectItemCaseSensitive(json, "data");

  if (!cJSON_IsString(sub) || !cJSON_IsNumber(exp) || !cJSON_IsString(data)) {
    cJSON_Delete(json);
    return JWT_ERROR_JSON_PARSING;
  }

  strncpy(p->sub, sub->valuestring, sizeof(p->sub) - 1);
  p->sub[sizeof(p->sub) - 1] = '\0';

  p->exp = (unsigned long)cJSON_GetNumberValue(exp);

  strncpy(p->data, data->valuestring, sizeof(p->data) - 1);
  p->data[sizeof(p->data) - 1] = '\0';

  cJSON_Delete(json);
  return JWT_SUCCESS;
}

jwt_error_t jwt_token_create(const JWTPayload* payload, const char* secret, char** out_token) {
  if (!payload || !secret || !out_token) {
    LOG_ERROR("Invalid input for jwt_token_create");
    return JWT_ERROR_INVALID_INPUT;
  }

  if (strlen(payload->sub) == 0 || strlen(payload->data) == 0) {
    return JWT_ERROR_INVALID_INPUT;
  }

  return jwt_generate(payload, secret, out_token);
}

jwt_error_t jwt_token_verify(const char* token, const char* secret, JWTPayload* p) {
  if (!token || !secret || !p) {
    return JWT_ERROR_INVALID_INPUT;
  }

  memset(p, 0, sizeof(JWTPayload));

  const char* first_dot = strchr(token, '.');
  const char* second_dot = first_dot ? strchr(first_dot + 1, '.') : NULL;
  if (!first_dot || !second_dot || strchr(second_dot + 1, '.')) {
    return JWT_ERROR_INVALID_FORMAT;
  }

  size_t header_len = first_dot - token;
  size_t payload_len = second_dot - (first_dot + 1);
  size_t signature_len = strlen(second_dot + 1);
  size_t message_len = header_len + payload_len + 1;

  if (message_len > JWT_MAX_LEN) {
    return JWT_ERROR_INVALID_INPUT;
  }

  char* message = (char*)malloc(message_len + 1);
  if (!message) {
    return JWT_ERROR_MEMORY_ALLOCATION;
  }

  memcpy(message, token, header_len);
  message[header_len] = '.';
  memcpy(message + header_len + 1, first_dot + 1, payload_len);
  message[message_len] = '\0';

  unsigned char hmac[EVP_MAX_MD_SIZE];
  unsigned int hmac_len;
  jwt_error_t result = create_hmac_sha256(secret, message, hmac, &hmac_len);
  if (result != JWT_SUCCESS) {
    free(message);
    return result;
  }

  char* encoded_signature = crypto_base64_encode(hmac, hmac_len);
  if (!encoded_signature) {
    free(message);
    return JWT_ERROR_BASE64_ENCODING;
  }

  bool signatures_match = (strlen(encoded_signature) == signature_len) &&
                          (memcmp(encoded_signature, second_dot + 1, signature_len) == 0);

  free(encoded_signature);
  if (!signatures_match) {
    free(message);
    return JWT_ERROR_SIGNATURE_MISMATCH;
  }

  // the payload is from first_dot + 1 to second_dot
  char* valid_token = (char*)malloc(payload_len + 1);
  if (!valid_token) {
    free(message);
    return JWT_ERROR_MEMORY_ALLOCATION;
  }

  memcpy(valid_token, first_dot + 1, payload_len);
  valid_token[payload_len] = '\0';

  size_t decoded_payload_len;
  unsigned char* decoded_payload = crypto_base64_decode(valid_token, &decoded_payload_len);
  if (!decoded_payload) {
    free(message);
    free(valid_token);
    return JWT_ERROR_BASE64_DECODING;
  }

  result = jwt_parse_payload((char*)decoded_payload, p);
  free(decoded_payload);
  free(message);
  free(valid_token);

  if (result != JWT_SUCCESS) {
    return result;
  }

  if (p->exp <= (unsigned long)time(NULL)) {
    return JWT_ERROR_TOKEN_EXPIRED;
  }

  return JWT_SUCCESS;
}
