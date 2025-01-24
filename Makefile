# ===============================================================================
# Project: CipherKit
# File: Makefile
# Author: Dr. Abiira Nathan <nabiira2by2@gmail.com>
# Created on: 2024-09-29
#
# Install dependencies using 
# `sudo apt-get install build-essential libssl-dev libsodium-dev libz-dev libssl-dev libssl-dev libssl-dev libcjson-dev`
#
#
# Install the library using `sudo make install`
# Uninstall the library using `sudo make uninstall`
# Run tests using `make test`
# Run memory checks using `make memcheck`
# NB: You need to have `valgrind` installed to run memory checks
# ===============================================================================

CC=clang
CFLAGS=-Wall -Wextra -Werror -pedantic -Wno-format-truncation -std=c23 -O3 
LDFLAGS=-lm -lssl -lcrypto -lsodium -lz -lcjson -lpthread
NAME=cipherkit
LIB=lib$(NAME)

SRC=crypto.c gzip.c jwt.c
HEADERS=cipherkit.h crypto.h gzip.h jwt.h logging.h
OBJ=$(addprefix obj/, $(SRC:.c=.o))

# Installation paths
INSTALL_PREFIX=/usr/local
HEADER_DIR=$(INSTALL_PREFIX)/include/$(NAME)
LIB_DIR=$(INSTALL_PREFIX)/lib
PKG_CONFIG_DIR=$(LIB_DIR)/pkgconfig

all: $(LIB).a $(LIB).so

$(LIB).a: $(OBJ)
	ar rcs $@ $^

$(LIB).so: $(OBJ)
	$(CC) -fPIC -shared -o $@ $^ $(CFLAGS) $(LDFLAGS)

OBJ_DIR:
	mkdir -p obj

obj/%.o: %.c OBJ_DIR
	$(CC) -fPIC -c -o $@ $< $(CFLAGS)

# May need to run `sudo make install` to install the library
install: $(LIB).a $(LIB).so
	mkdir -p $(LIB_DIR)
	mkdir -p $(HEADER_DIR)

	cp $(LIB).a $(LIB_DIR)
	cp $(LIB).so $(LIB_DIR)
	cp $(HEADERS) $(HEADER_DIR)

	# copy pkg-config file
	mkdir -p $(PKG_CONFIG_DIR)
	cp $(NAME).pc $(PKG_CONFIG_DIR)

uninstall:
	rm -rf $(LIB_DIR)/$(LIB).a
	rm -rf $(LIB_DIR)/$(LIB).so
	rm -rf $(HEADER_DIR)
	rm -rf $(PKG_CONFIG_DIR)/$(NAME).pc

test: $(LIB).a $(LIB).so
	$(CC) -o gzip_test tests/gzip_test.c $(LIB).a $(CFLAGS) $(LDFLAGS)
	$(CC) -o crypto_test tests/crypto_test.c $(LIB).a $(CFLAGS) $(LDFLAGS)
	$(CC) -o jwt_test tests/jwt_test.c $(LIB).a $(CFLAGS) $(LDFLAGS)
	./gzip_test
	./crypto_test
	./jwt_test

memcheck: test
	valgrind --leak-check=full ./gzip_test
	valgrind --leak-check=full ./crypto_test
	valgrind --leak-check=full ./jwt_test

clean:
	rm -rf obj $(LIB).a $(LIB).so gzip_test crypto_test jwt_test

.PHONY: all clean
