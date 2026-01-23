// For strdup
#define _POSIX_C_SOURCE 200809L

#include "../include/jwt.h"
#include "../include/crypto.h"

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <yyjson.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Configuration */
#define JWT_ALG "HS256"
#define JWT_TYP "JWT"
#define CLOCK_SKEW_SEC 60
#define MIN_SECRET_LEN 32
#define JWT_MAX_TOKEN_LEN 4096
#define JWT_PAYLOAD_BUFFER_SIZE 2048

static const char JWT_HEADER_JSON[] = "{\"alg\":\"" JWT_ALG "\",\"typ\":\"" JWT_TYP "\"}";

const char* jwt_error_string(jwt_error_t error) {
    switch (error) {
        case JWT_SUCCESS:
            return "Success";
        case JWT_ERROR_INVALID_INPUT:
            return "Invalid input parameter";
        case JWT_ERROR_MEMORY_ALLOCATION:
            return "Memory allocation failed";
        case JWT_ERROR_HMAC_CREATION:
            return "HMAC generation failed";
        case JWT_ERROR_BASE64_ENCODING:
            return "Base64 encoding failed";
        case JWT_ERROR_BASE64_DECODING:
            return "Base64 decoding failed";
        case JWT_ERROR_JSON_GENERATION:
            return "JSON generation failed";
        case JWT_ERROR_JSON_PARSING:
            return "JSON parsing failed";
        case JWT_ERROR_INVALID_FORMAT:
            return "Invalid token format";
        case JWT_ERROR_INVALID_ALGORITHM:
            return "Unsupported algorithm";
        case JWT_ERROR_WEAK_SECRET:
            return "Secret is too weak";
        case JWT_ERROR_SIGNATURE_MISMATCH:
            return "Signature verification failed";
        case JWT_ERROR_TOKEN_EXPIRED:
            return "Token has expired";
        default:
            return "Unknown error";
    }
}

/**
 * @brief Converts standard Base64 string to Base64URL in-place.
 * Replaces '+' with '-', '/' with '_', and strips trailing '='.
 */
static void base64_to_base64url(char* str) {
    if (!str)
        return;

    char* p = str;
    while (*p) {
        if (*p == '+')
            *p = '-';
        else if (*p == '/')
            *p = '_';
        p++;
    }

    // Strip padding
    while (p > str && *(p - 1) == '=') {
        *(--p) = '\0';
    }
}

/**
 * @brief Converts Base64URL to standard Base64.
 * Allocates new buffer that must be freed.
 */
static char* base64url_to_base64(const char* src, size_t src_len) {
    if (!src)
        return NULL;

    size_t padding = (4 - (src_len % 4)) % 4;
    size_t new_len = src_len + padding;

    char* dst = (char*)malloc(new_len + 1);
    if (!dst)
        return NULL;

    memcpy(dst, src, src_len);

    for (size_t i = 0; i < src_len; i++) {
        if (dst[i] == '-')
            dst[i] = '+';
        else if (dst[i] == '_')
            dst[i] = '/';
    }

    for (size_t i = 0; i < padding; i++) {
        dst[src_len + i] = '=';
    }
    dst[new_len] = '\0';

    return dst;
}

static jwt_error_t validate_secret(const char* secret) {
    if (!secret || strlen(secret) < MIN_SECRET_LEN) {
        return JWT_ERROR_WEAK_SECRET;
    }
    return JWT_SUCCESS;
}

static jwt_error_t hmac_sha256(const char* key, const char* data, unsigned char* out_md,
                               unsigned int* out_len) {
    if (!key || !data || !out_md || !out_len)
        return JWT_ERROR_INVALID_INPUT;

    if (!HMAC(EVP_sha256(), key, strlen(key), (const unsigned char*)data, strlen(data), out_md,
              out_len)) {
        return JWT_ERROR_HMAC_CREATION;
    }
    return JWT_SUCCESS;
}

jwt_error_t jwt_parse_payload_json(const char* raw_payload, jwt_payload_t* out_payload) {
    if (!raw_payload || !out_payload)
        return JWT_ERROR_INVALID_INPUT;

    yyjson_doc* doc = yyjson_read(raw_payload, strlen(raw_payload), 0);
    if (!doc)
        return JWT_ERROR_JSON_PARSING;

    yyjson_val* root = yyjson_doc_get_root(doc);
    if (!yyjson_is_obj(root)) {
        yyjson_doc_free(doc);
        return JWT_ERROR_JSON_PARSING;
    }

    jwt_error_t result = JWT_SUCCESS;

    // Extract "sub"
    yyjson_val* sub = yyjson_obj_get(root, "sub");
    if (yyjson_is_str(sub)) {
        const char* sub_str = yyjson_get_str(sub);
        strncpy(out_payload->sub, sub_str, sizeof(out_payload->sub) - 1);
        out_payload->sub[sizeof(out_payload->sub) - 1] = '\0';
    } else {
        result = JWT_ERROR_JSON_PARSING;
        goto cleanup;
    }

    // Extract "exp"
    yyjson_val* exp = yyjson_obj_get(root, "exp");
    if (yyjson_is_num(exp)) {
        out_payload->exp = (int64_t)yyjson_get_num(exp);
    } else {
        result = JWT_ERROR_JSON_PARSING;
        goto cleanup;
    }

    // Extract "data"
    yyjson_val* data = yyjson_obj_get(root, "data");
    if (yyjson_is_str(data)) {
        const char* data_str = yyjson_get_str(data);
        strncpy(out_payload->data, data_str, sizeof(out_payload->data) - 1);
        out_payload->data[sizeof(out_payload->data) - 1] = '\0';
    } else {
        result = JWT_ERROR_JSON_PARSING;
        goto cleanup;
    }

cleanup:
    yyjson_doc_free(doc);
    return result;
}

jwt_error_t jwt_token_create(const jwt_payload_t* payload, const char* secret, char** out_token) {
    if (!payload || !secret || !out_token)
        return JWT_ERROR_INVALID_INPUT;

    if (strlen(payload->sub) == 0 || strlen(payload->data) == 0) {
        return JWT_ERROR_INVALID_INPUT;
    }

    jwt_error_t err = validate_secret(secret);
    if (err != JWT_SUCCESS)
        return err;

    *out_token = NULL;
    char* b64_header = NULL;
    char* b64_payload = NULL;
    char* b64_sig = NULL;
    char* signing_input = NULL;

    // Stack-allocated buffer for JSON payload
    char payload_buffer[JWT_PAYLOAD_BUFFER_SIZE];

    err = JWT_ERROR_UNKNOWN;

    // Encode Header
    static const size_t json_header_len = sizeof(JWT_HEADER_JSON) - 1;
    b64_header = crypto_base64_encode((const unsigned char*)JWT_HEADER_JSON, json_header_len);
    if (!b64_header) {
        err = JWT_ERROR_BASE64_ENCODING;
        goto cleanup;
    }

    base64_to_base64url(b64_header);

    // Generate Payload JSON using yyjson with mutable doc
    yyjson_mut_doc* doc = yyjson_mut_doc_new(NULL);
    if (!doc) {
        err = JWT_ERROR_MEMORY_ALLOCATION;
        goto cleanup;
    }

    yyjson_mut_val* root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);

    yyjson_mut_obj_add_str(doc, root, "sub", payload->sub);
    yyjson_mut_obj_add_int(doc, root, "exp", payload->exp);
    yyjson_mut_obj_add_int(doc, root, "iat", (int64_t)time(NULL));
    yyjson_mut_obj_add_str(doc, root, "data", payload->data);

    // Write JSON to buffer
    size_t json_len;
    char* json_str = yyjson_mut_write_opts(doc, YYJSON_WRITE_NOFLAG, NULL, &json_len, NULL);

    if (!json_str || json_len >= JWT_PAYLOAD_BUFFER_SIZE) {
        yyjson_mut_doc_free(doc);
        if (json_str)
            free(json_str);
        err = JWT_ERROR_JSON_GENERATION;
        goto cleanup;
    }

    memcpy(payload_buffer, json_str, json_len);
    payload_buffer[json_len] = '\0';

    free(json_str);
    yyjson_mut_doc_free(doc);

    // Encode Payload
    b64_payload = crypto_base64_encode((const uint8_t*)payload_buffer, json_len);
    if (!b64_payload) {
        err = JWT_ERROR_BASE64_ENCODING;
        goto cleanup;
    }
    base64_to_base64url(b64_payload);

    // Construct Signing Input (header.payload)
    size_t input_len = strlen(b64_header) + 1 + strlen(b64_payload) + 1;
    signing_input = (char*)malloc(input_len);
    if (!signing_input) {
        err = JWT_ERROR_MEMORY_ALLOCATION;
        goto cleanup;
    }
    snprintf(signing_input, input_len, "%s.%s", b64_header, b64_payload);

    // Calculate HMAC
    unsigned char hmac[EVP_MAX_MD_SIZE];
    unsigned int hmac_len = 0;
    err = hmac_sha256(secret, signing_input, hmac, &hmac_len);
    if (err != JWT_SUCCESS)
        goto cleanup;

    // Encode Signature
    b64_sig = crypto_base64_encode(hmac, hmac_len);
    if (!b64_sig) {
        err = JWT_ERROR_BASE64_ENCODING;
        goto cleanup;
    }
    base64_to_base64url(b64_sig);

    // Assemble Final Token
    size_t token_len = strlen(signing_input) + 1 + strlen(b64_sig) + 1;
    if (token_len > JWT_MAX_TOKEN_LEN) {
        err = JWT_ERROR_INVALID_INPUT;
        goto cleanup;
    }

    *out_token = (char*)malloc(token_len);
    if (!*out_token) {
        err = JWT_ERROR_MEMORY_ALLOCATION;
        goto cleanup;
    }

    snprintf(*out_token, token_len, "%s.%s", signing_input, b64_sig);
    err = JWT_SUCCESS;

cleanup:
    free(b64_header);
    free(b64_payload);
    free(b64_sig);
    free(signing_input);

    return err;
}

jwt_error_t jwt_token_verify(const char* token, const char* secret, jwt_payload_t* out_payload) {
    if (!token || !secret || !out_payload)
        return JWT_ERROR_INVALID_INPUT;

    jwt_error_t err = validate_secret(secret);
    if (err != JWT_SUCCESS)
        return err;

    if (strlen(token) > JWT_MAX_TOKEN_LEN)
        return JWT_ERROR_INVALID_INPUT;

    char* header_b64 = NULL;
    char* payload_b64 = NULL;
    char* signature_b64 = NULL;
    char* decoded_header = NULL;
    unsigned char* decoded_payload = NULL;
    char* calc_sig_b64 = NULL;
    char* signing_input = NULL;

    // We make a copy of the token to split it safely
    char* token_copy = strdup(token);
    if (!token_copy)
        return JWT_ERROR_MEMORY_ALLOCATION;

    // Split Token
    char* part1 = strtok(token_copy, ".");
    char* part2 = strtok(NULL, ".");
    char* part3 = strtok(NULL, ".");

    if (!part1 || !part2 || !part3 || strtok(NULL, ".")) {
        err = JWT_ERROR_INVALID_FORMAT;
        goto cleanup;
    }

    header_b64 = part1;
    payload_b64 = part2;
    signature_b64 = part3;

    // Verify Header
    char* std_header_b64 = base64url_to_base64(header_b64, strlen(header_b64));
    if (!std_header_b64) {
        err = JWT_ERROR_MEMORY_ALLOCATION;
        goto cleanup;
    }

    size_t dec_len = 0;
    decoded_header = (char*)crypto_base64_decode(std_header_b64, &dec_len);
    free(std_header_b64);

    if (!decoded_header) {
        err = JWT_ERROR_BASE64_DECODING;
        goto cleanup;
    }

    yyjson_doc* header_doc = yyjson_read(decoded_header, dec_len, 0);
    if (!header_doc) {
        err = JWT_ERROR_JSON_PARSING;
        goto cleanup;
    }

    yyjson_val* header_root = yyjson_doc_get_root(header_doc);
    yyjson_val* alg = yyjson_obj_get(header_root, "alg");

    if (!yyjson_is_str(alg) || strcmp(yyjson_get_str(alg), JWT_ALG) != 0) {
        yyjson_doc_free(header_doc);
        err = JWT_ERROR_INVALID_ALGORITHM;
        goto cleanup;
    }

    yyjson_doc_free(header_doc);

    // Verify Signature
    // Reconstruct "header.payload" from the original parts
    size_t sig_input_len = strlen(header_b64) + 1 + strlen(payload_b64) + 1;
    signing_input = (char*)malloc(sig_input_len);
    if (!signing_input) {
        err = JWT_ERROR_MEMORY_ALLOCATION;
        goto cleanup;
    }
    snprintf(signing_input, sig_input_len, "%s.%s", header_b64, payload_b64);

    unsigned char hmac[EVP_MAX_MD_SIZE];
    unsigned int hmac_len = 0;
    err = hmac_sha256(secret, signing_input, hmac, &hmac_len);
    if (err != JWT_SUCCESS)
        goto cleanup;

    char* temp_sig = crypto_base64_encode(hmac, hmac_len);
    if (!temp_sig) {
        err = JWT_ERROR_BASE64_ENCODING;
        goto cleanup;
    }

    calc_sig_b64 = strdup(temp_sig);
    free(temp_sig);

    if (!calc_sig_b64) {
        err = JWT_ERROR_MEMORY_ALLOCATION;
        goto cleanup;
    }
    base64_to_base64url(calc_sig_b64);

    // Constant time comparison
    if (CRYPTO_memcmp(calc_sig_b64, signature_b64, strlen(signature_b64)) != 0) {
        err = JWT_ERROR_SIGNATURE_MISMATCH;
        goto cleanup;
    }

    // Decode and Parse Payload
    char* std_payload_b64 = base64url_to_base64(payload_b64, strlen(payload_b64));
    if (!std_payload_b64) {
        err = JWT_ERROR_MEMORY_ALLOCATION;
        goto cleanup;
    }

    decoded_payload = crypto_base64_decode(std_payload_b64, &dec_len);
    free(std_payload_b64);

    if (!decoded_payload) {
        err = JWT_ERROR_BASE64_DECODING;
        goto cleanup;
    }

    err = jwt_parse_payload_json((char*)decoded_payload, out_payload);
    if (err != JWT_SUCCESS)
        goto cleanup;

    // Check Expiration
    int64_t now = (int64_t)time(NULL);
    if (out_payload->exp < (now - CLOCK_SKEW_SEC)) {
        err = JWT_ERROR_TOKEN_EXPIRED;
        goto cleanup;
    }

    err = JWT_SUCCESS;

cleanup:
    free(token_copy);
    free(decoded_header);
    free(decoded_payload);
    free(signing_input);
    free(calc_sig_b64);

    return err;
}
