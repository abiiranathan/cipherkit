#ifndef A308B9B1_4C38_4C7E_888F_0EFEA346C0CF
#define A308B9B1_4C38_4C7E_888F_0EFEA346C0CF

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>

// If clang is used, use the below pragma to disable the warning about zero variadic arguments.
// This is supported in gcc and clang but in clang we have to disable the warning.
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
#endif

#define LOG_BASE(stream, level, fmt, ...)                                                          \
    fprintf(stream, "[" level "]: %s:%d:%s(): " fmt "\n", __FILE__, __LINE__, __func__,            \
            ##__VA_ARGS__)

#define LOG_ERROR(fmt, ...) LOG_BASE(stderr, "ERROR", fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...) LOG_BASE(stderr, "WARN", fmt, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) LOG_BASE(stdout, "DEBUG", fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...) LOG_BASE(stdout, "INFO", fmt, ##__VA_ARGS__)

// Log fatal errors and exit the program.
#define LOG_FATAL(fmt, ...)                                                                        \
    do {                                                                                           \
        LOG_ERROR(fmt, ##__VA_ARGS__);                                                             \
        exit(EXIT_FAILURE);                                                                        \
    } while (0)

// Verbose ASSERT macro.
#define LOG_ASSERT(condition, fmt, ...)                                                            \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            LOG_FATAL("Assertion failed: " #condition " " fmt, ##__VA_ARGS__);                     \
        }                                                                                          \
    } while (0)

#ifdef __clang__
#pragma clang diagnostic pop
#endif

#ifdef __cplusplus
}
#endif

#endif /* A308B9B1_4C38_4C7E_888F_0EFEA346C0CF */
