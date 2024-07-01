#ifndef CLIENT_H
#define CLIENT_H

#include <openssl/sha.h>

typedef struct
{
  char ip[16];
  char opaque[SHA256_DIGEST_LENGTH * 2 + 1];
  char nonce[SHA256_DIGEST_LENGTH * 2 + 1];
  unsigned int nc;
} client_info_t;

#endif // CLIENT_H
