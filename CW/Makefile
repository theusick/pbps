CC = gcc
CFLAGS = -w -Wall -Wextra -O2 -Iinclude
LDFLAGS = -lldap -llber -lssl -lcrypto

SRC_DIR = src
OBJ_DIR = obj
INCLUDE_DIR = include

SRCS = ${SRC_DIR}/main.c \
		${SRC_DIR}/server.c \
		${SRC_DIR}/auth.c \
		${SRC_DIR}/request.c \
		${SRC_DIR}/response.c \
		${SRC_DIR}/utils.c \
		${SRC_DIR}/config.c \
		${SRC_DIR}/digest.c \
		${SRC_DIR}/htaccess.c \
		${SRC_DIR}/client.c
OBJS = $(patsubst ${SRC_DIR}/%.c,${OBJ_DIR}/%.o,$(SRCS))
DEPS = ${INCLUDE_DIR}/config.h \
		${INCLUDE_DIR}/server.h \
		${INCLUDE_DIR}/auth.h \
		${INCLUDE_DIR}/request.h \
		${INCLUDE_DIR}/response.h \
		${INCLUDE_DIR}/utils.h \
		${INCLUDE_DIR}/digest.h \
		${INCLUDE_DIR}/http_responses.h \
		${INCLUDE_DIR}/htaccess.h \
		${INCLUDE_DIR}/client.h

TARGET = server

all: ldap_install clean server

.PHONY: ldap_install
ldap_install:
	/bin/bash scripts/init_ldap.sh

.PHONY: ldap_remove
ldap_remove:
	/bin/bash scripts/rm_ldap.sh

.PHONY: clean
clean:
	@rm -rf $(OBJ_DIR) $(TARGET)

.PHONY: $(TARGET)
$(TARGET): clean $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

${OBJ_DIR}/%.o: ${SRC_DIR}/%.c $(DEPS)
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<
