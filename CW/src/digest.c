#include "digest.h"
#include "utils.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
#include <openssl/md5.h>

const int digest_init(digest_t *digest)
{
  digest_s *dig = (digest_s *)digest;

  /* Clear */
  memset(dig, 0, sizeof(digest_s));

  dig->algorithm = DIGEST_ALGORITHM_MD5;

  return 0;
}

void generate_nonce(char *nonce, size_t size)
{
  snprintf(nonce, size, "%x", (unsigned int)time(NULL));
}

size_t generate_digest_header(digest_t *digest, char *result, size_t max_length)
{
  digest_s *dig = (digest_s *)digest;
  char *qop_value, *algorithm_value;
  size_t result_size = 0; // The size of the result string
  int sz;

  // Quality of Protection - qop
  if (DIGEST_QOP_AUTH == (DIGEST_QOP_AUTH & dig->qop))
  {
    qop_value = "auth";
  }
  else if (DIGEST_QOP_AUTH_INT == (DIGEST_QOP_AUTH_INT & dig->qop))
  {
    return (size_t)-1;
  }

  // Set algorithm
  algorithm_value = NULL;
  if (DIGEST_ALGORITHM_MD5 == dig->algorithm)
  {
    algorithm_value = "MD5";
  }
  else if (DIGEST_ALGORITHM_SHA256 == dig->algorithm)
  {
    algorithm_value = "SHA-256";
  }

  // Generate the minimum digest header string
  sz = snprintf(result, max_length, "Digest realm=\"%s\"", dig->realm);
  if ((sz < 0) || ((size_t)sz >= max_length))
  {
    return (size_t)-1;
  }
  result_size += (size_t)sz;

  // Add opaque
  if (dig->opaque != NULL)
  {
    sz = snprintf(result + result_size, max_length - result_size, ", opaque=\"%s\"", dig->opaque);
    if ((sz < 0) || ((size_t)sz >= max_length - result_size))
    {
      return (size_t)-1;
    }
    result_size += (size_t)sz;
  }

  // Add algorithm
  if (DIGEST_ALGORITHM_NOT_SET != dig->algorithm)
  {
    sz = snprintf(result + result_size, max_length - result_size, ", algorithm=\"%s\"",
                  algorithm_value);
    if ((sz < 0) || ((size_t)sz >= max_length))
    {
      return (size_t)-1;
    }
    result_size += (size_t)sz;
  }

  // If qop is supplied, add nonce, cnonce, nc and qop
  if (DIGEST_QOP_NOT_SET != dig->qop)
  {
    sz = snprintf(result + result_size, max_length - result_size, ", qop=%s, nonce=\"%s\", cnonce=\"%s\", nc=%08x",
                  qop_value,
                  dig->nonce,
                  dig->cnonce,
                  dig->nc);
    if ((sz < 0) || ((size_t)sz >= max_length - result_size))
    {
      return (size_t)-1;
    }
    result_size += (size_t)sz;
  }

  return result_size;
}

const int parse_digest(digest_t *digest, const char *digest_string)
{
  digest_s *dig = (digest_s *)digest;

  int n, i = 0;
  char *val, *parameters;
  char *values[12];

  parameters = crop_sentence(digest_string);
  n = tokenize_sentence(parameters, values, (sizeof values / sizeof(values[0])));

  while (i < n)
  {
    if ((val = values[i++]) == NULL)
    {
      continue;
    }

    if (strncmp("username=", val, strlen("username=")) == 0)
    {
      dig->username = dgst_get_val(val);
    }
    else if (strncmp("realm=", val, strlen("realm=")) == 0)
    {
      dig->realm = dgst_get_val(val);
    }
    else if (strncmp("nonce=", val, strlen("nonce=")) == 0)
    {
      dig->nonce = dgst_get_val(val);
    }
    else if (strncmp("uri=", val, strlen("uri=")) == 0)
    {
      dig->uri = dgst_get_val(val);
    }
    else if (strncmp("response=", val, strlen("response=")) == 0)
    {
      dig->response = dgst_get_val(val);
    }
    else if (strncmp("opaque=", val, strlen("opaque=")) == 0)
    {
      dig->opaque = dgst_get_val(val);
    }
    else if (strncmp("qop=", val, strlen("qop=")) == 0)
    {
      char *qop_options = dgst_get_val(val);
      char *qop_values[2];
      int n_qops = split_string_by_comma(qop_options, qop_values, (sizeof qop_values / sizeof(qop_values[0])));
      while (n_qops-- > 0)
      {
        if (strncmp(qop_values[n_qops], "auth", strlen("auth")) == 0)
        {
          dig->qop |= DIGEST_QOP_AUTH;
          continue;
        }
        if (strncmp(qop_values[n_qops], "auth-int", strlen("auth-int")) == 0)
        {
          dig->qop |= DIGEST_QOP_AUTH_INT;
        }
      }
    }
    else if (strncmp("algorithm=", val, strlen("algorithm=")) == 0)
    {
      char *algorithm = dgst_get_val(val);
      if (strncmp(algorithm, "MD5", strlen("MD5")) == 0)
      {
        dig->algorithm = DIGEST_ALGORITHM_MD5;
      }
    }
    else if (strncmp("cnonce=", val, strlen("cnonce=")) == 0)
    {
      dig->cnonce = dgst_get_val(val);
    }
    else if (strncmp("nc=", val, strlen("nc=")) == 0)
    {
      dig->nc = str_to_int_hex(dgst_get_val(val));
    }
  }

  return i;
}

const char *get_qop_value(digest_t *digest)
{
  digest_s *dig = (digest_s *)digest;
  const char *qop_str;

  switch (dig->qop)
  {
  case DIGEST_QOP_NOT_SET:
    qop_str = "notset";
    break;
  case DIGEST_QOP_AUTH:
    qop_str = "auth";
    break;
  case DIGEST_QOP_AUTH_INT:
    qop_str = "auth-int";
    break;
  default:
    qop_str = "unknown";
    break;
  }

  return qop_str;
}

void *digest_get_attr(digest_t *digest, digest_attr_t attr)
{
  digest_s *dig = (digest_s *)digest;

  switch (attr)
  {
  case D_ATTR_USERNAME:
    return dig->username;
  case D_ATTR_RESPONSE:
    return dig->response;
  case D_ATTR_REALM:
    return dig->realm;
  case D_ATTR_NONCE:
    return dig->nonce;
  case D_ATTR_CNONCE:
    return &(dig->cnonce);
  case D_ATTR_OPAQUE:
    return dig->opaque;
  case D_ATTR_URI:
    return dig->uri;
  case D_ATTR_METHOD:
    return &(dig->method);
  case D_ATTR_ALGORITHM:
    return &(dig->algorithm);
  case D_ATTR_QOP:
    return &(dig->qop);
  case D_ATTR_NONCE_COUNT:
    return &(dig->nc);
  default:
    return NULL;
  }
}

int digest_set_attr(digest_t *digest, digest_attr_t attr, const digest_attr_value_t value)
{
  digest_s *dig = (digest_s *)digest;

  switch (attr)
  {
  case D_ATTR_USERNAME:
    dig->username = value.string;
    break;
  case D_ATTR_RESPONSE:
    dig->response = value.string;
    break;
  case D_ATTR_REALM:
    dig->realm = value.string;
    break;
  case D_ATTR_NONCE:
    dig->nonce = value.string;
    break;
  case D_ATTR_CNONCE:
    dig->cnonce = value.number;
    break;
  case D_ATTR_OPAQUE:
    dig->opaque = value.string;
    break;
  case D_ATTR_URI:
    dig->uri = value.string;
    break;
  case D_ATTR_METHOD:
    dig->method = value.number;
    break;
  case D_ATTR_ALGORITHM:
    dig->algorithm = value.number;
    break;
  case D_ATTR_QOP:
    dig->qop = value.number;
    break;
  case D_ATTR_NONCE_COUNT:
    dig->nc = value.number;
    break;
  default:
    return -1;
  }

  return 0;
}
