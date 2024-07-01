#ifndef DIGEST_H
#define DIGEST_H

#include <stddef.h>

typedef struct
{
  char *username;
  char *response;
  char *realm;
  char *nonce;
  char *cnonce;
  char *opaque;
  char *uri;
  unsigned int method;
  char algorithm;
  unsigned int qop;
  unsigned int nc;
} digest_s;

typedef digest_s digest_t;

typedef enum
{
  D_ATTR_USERNAME,   // char *
  D_ATTR_RESPONSE,   // char *
  D_ATTR_REALM,      // char *
  D_ATTR_NONCE,      // char *
  D_ATTR_CNONCE,     // char *
  D_ATTR_OPAQUE,     // char *
  D_ATTR_URI,        // char *
  D_ATTR_METHOD,     // int
  D_ATTR_ALGORITHM,  // int
  D_ATTR_QOP,        // int
  D_ATTR_NONCE_COUNT // int
} digest_attr_t;

typedef union
{
  int number;
  char *string;
  const char *const_str;
} digest_attr_value_t;

// Supported hashing algorithms
#define DIGEST_ALGORITHM_NOT_SET 0
#define DIGEST_ALGORITHM_MD5 1
#define DIGEST_ALGORITHM_SHA256 2

// Quality of Protection (qop) values
#define DIGEST_QOP_NOT_SET 0
#define DIGEST_QOP_AUTH 1
#define DIGEST_QOP_AUTH_INT 2

const int digest_init(digest_t *digest);

void generate_nonce(char *nonce, size_t size);

size_t generate_digest_header(digest_t *digest, char *result, size_t max_length);
const int parse_digest(digest_t *digest, const char *digest_string);

const char *get_qop_value(digest_t *digest);

void *digest_get_attr(digest_t *digest, digest_attr_t attr);
int digest_set_attr(digest_t *digest, digest_attr_t attr, const digest_attr_value_t value);

#endif // DIGEST_H
