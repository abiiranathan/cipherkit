# ===============================================================================
# Project: CipherKit
# File: Makefile
# Author: Dr. Abiira Nathan <nabiira2by2@gmail.com>
# Created on: 2024-09-29
#
# Install dependencies using:
# `sudo apt-get install build-essential libssl-dev libsodium-dev libz-dev libcjson-dev`
#
# Install the library using `sudo make install`
# Uninstall the library using `sudo make uninstall`
# Run tests using `make test`
# Run memory checks using `make memcheck`
# NB: You need to have `valgrind` installed to run memory checks.
# ===============================================================================

CC = clang
AR = ar
CFLAGS = -Wall -Wextra -Werror -pedantic -Wno-format-truncation -std=c23 -O3 -fPIC
LDFLAGS = -lm -lssl -lcrypto -lsodium -lz -lcjson -lpthread
NAME = cipherkit
LIB = lib$(NAME)
SRC = crypto.c gzip.c jwt.c
HEADERS = cipherkit.h crypto.h gzip.h jwt.h logging.h
OBJ_DIR = obj
OBJ = $(addprefix $(OBJ_DIR)/, $(SRC:.c=.o))
DEPS = $(OBJ:.o=.d)

# Installation paths
INSTALL_PREFIX = /usr/local
HEADER_DIR = $(INSTALL_PREFIX)/include/$(NAME)
LIB_DIR = $(INSTALL_PREFIX)/lib
PKG_CONFIG_DIR = $(LIB_DIR)/pkgconfig

CLEANFILES = $(LIB).a $(LIB).so gzip_test crypto_test jwt_test $(OBJ_DIR)

# Default target
all: $(LIB).a $(LIB).so

# Static library
$(LIB).a: $(OBJ)
	$(AR) rcs $@ $^

# Shared library
$(LIB).so: $(OBJ)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# Ensure object directory exists
$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

# Compile object files with dependency generation
$(OBJ_DIR)/%.o: %.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

# Include dependencies if they exist
-include $(DEPS)

install: $(LIB).a $(LIB).so
	sudo mkdir -p $(LIB_DIR) $(HEADER_DIR) $(PKG_CONFIG_DIR)
	sudo cp $(LIB).a $(LIB_DIR)
	sudo cp $(LIB).so $(LIB_DIR)
	sudo cp $(HEADERS) $(HEADER_DIR)
	sudo cp $(NAME).pc $(PKG_CONFIG_DIR)

uninstall:
	sudo rm -rf $(LIB_DIR)/$(LIB).a $(LIB_DIR)/$(LIB).so $(HEADER_DIR) $(PKG_CONFIG_DIR)/$(NAME).pc

test: $(LIB).a $(LIB).so
	$(CC) -o gzip_test tests/gzip_test.c $(LIB).a $(LDFLAGS)
	$(CC) -o crypto_test tests/crypto_test.c $(LIB).a $(LDFLAGS)
	$(CC) -o jwt_test tests/jwt_test.c $(LIB).a $(LDFLAGS)
	./gzip_test
	./crypto_test
	./jwt_test

memcheck: test
	valgrind --leak-check=full ./gzip_test
	valgrind --leak-check=full ./crypto_test
	valgrind --leak-check=full ./jwt_test

clean:
	rm -rf $(CLEANFILES)

.PHONY: all install uninstall test memcheck clean
