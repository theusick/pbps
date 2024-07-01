#ifndef CLIENT_H
#define CLIENT_H

#include <time.h>
#include <openssl/sha.h>

typedef struct
{
  char ip[16];
  char opaque[SHA256_DIGEST_LENGTH * 2 + 1];
  char nonce[SHA256_DIGEST_LENGTH * 2 + 1];
  unsigned int nc;
  time_t nonce_generation_time;
} client_info_t;

#endif // CLIENT_H
