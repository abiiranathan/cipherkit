# ===============================================================================
# Project: CipherKit
# File: CMakeLists.txt
# Author: Dr. Abiira Nathan <nabiira2by2@gmail.com>
# Created on: 2025-11-30
# ===============================================================================
cmake_minimum_required(VERSION 3.10)
project(cipherkit VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED OFF)
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror -pedantic")
set(CMAKE_C_FLAGS_RELEASE "-O3")
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Source files
set(SOURCES
    src/crypto.c
    src/gzip.c
    src/jwt.c
)

# Header files for installation
set(HEADERS
    include/cipherkit.h
    include/crypto.h
    include/gzip.h
    include/jwt.h
    include/logging.h
)

# Find required dependencies
find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)
find_package(Threads REQUIRED)

# Find libsodium (no native CMake module, use pkg-config)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

# Find cJSON
pkg_check_modules(CJSON REQUIRED libcjson)

# Create static library
add_library(cipherkit_static STATIC ${SOURCES})
set_target_properties(cipherkit_static PROPERTIES OUTPUT_NAME cipherkit)

target_include_directories(cipherkit_static PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include/cipherkit>
)

target_link_libraries(cipherkit_static PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
    ZLIB::ZLIB
    Threads::Threads
    m # math library
    ${SODIUM_LIBRARIES}
    ${CJSON_LIBRARIES}
)

target_include_directories(cipherkit_static PUBLIC
    ${SODIUM_INCLUDE_DIRS}
    ${CJSON_INCLUDE_DIRS}
)

# Create shared library
add_library(cipherkit SHARED ${SOURCES})
set_target_properties(cipherkit PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
)

target_include_directories(cipherkit PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include/cipherkit>
)

target_link_libraries(cipherkit PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
    ZLIB::ZLIB
    Threads::Threads
    m
    ${SODIUM_LIBRARIES}
    ${CJSON_LIBRARIES}
)

target_include_directories(cipherkit PUBLIC
    ${SODIUM_INCLUDE_DIRS}
    ${CJSON_INCLUDE_DIRS}
)

# Enable testing
enable_testing()

# Helper macro for creating test executables
macro(add_cipherkit_test test_name)
    add_executable(${test_name} tests/${test_name}.c)
    target_link_libraries(${test_name} PRIVATE cipherkit_static)
    add_test(NAME ${test_name} COMMAND ${test_name})
endmacro()

# Define test executables
add_cipherkit_test(gzip_test)
add_cipherkit_test(crypto_test)
add_cipherkit_test(jwt_test)

# Custom target to run all tests (alternative to ctest)
add_custom_target(run_tests
    COMMAND gzip_test
    COMMAND crypto_test
    COMMAND jwt_test
    DEPENDS gzip_test crypto_test jwt_test
    COMMENT "Running all tests..."
)

# Installation configuration
include(GNUInstallDirs)

# Install libraries
install(TARGETS cipherkit cipherkit_static
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

# Install headers
install(FILES ${HEADERS}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/cipherkit
)

# Generate and install pkg-config file
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cipherkit.pc.in
    ${CMAKE_CURRENT_BINARY_DIR}/cipherkit.pc @ONLY)
    
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/cipherkit.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)

# Print configuration summary
message(STATUS "=== CipherKit Configuration ===")
message(STATUS "Version: ${PROJECT_VERSION}")
message(STATUS "C Standard: C${CMAKE_C_STANDARD}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "OpenSSL: ${OPENSSL_VERSION}")
message(STATUS "ZLIB: ${ZLIB_VERSION_STRING}")
message(STATUS "libsodium: ${SODIUM_VERSION}")
message(STATUS "cJSON: ${CJSON_VERSION}")

