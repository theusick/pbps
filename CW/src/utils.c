#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/buffer.h>

static const unsigned char base64_table[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

unsigned int hash_ip(const char *ip)
{
  unsigned int hash = 0;
  while (*ip)
  {
    hash = (hash << 5) + hash + *ip++;
  }
  return hash % CONNMAX;
}

unsigned char *base64_decode(const unsigned char *src, size_t len, size_t *out_len)
{
  unsigned char dtable[256], *out, *pos, block[4], tmp;
  size_t i, count, olen;
  int pad = 0;

  memset(dtable, 0x80, 256);
  for (i = 0; i < sizeof(base64_table) - 1; i++)
    dtable[base64_table[i]] = (unsigned char)i;
  dtable['='] = 0;

  count = 0;
  for (i = 0; i < len; i++)
  {
    if (dtable[src[i]] != 0x80)
      count++;
  }

  if (count == 0 || count % 4)
    return NULL;

  olen = count / 4 * 3;
  pos = out = (unsigned char *)malloc(olen);
  if (out == NULL)
    return NULL;

  count = 0;
  for (i = 0; i < len; i++)
  {
    tmp = dtable[src[i]];
    if (tmp == 0x80)
      continue;

    if (src[i] == '=')
      pad++;
    block[count] = tmp;
    count++;
    if (count == 4)
    {
      *pos++ = (block[0] << 2) | (block[1] >> 4);
      *pos++ = (block[1] << 4) | (block[2] >> 2);
      *pos++ = (block[2] << 6) | block[3];
      count = 0;
      if (pad)
      {
        if (pad == 1)
          pos--;
        else if (pad == 2)
          pos -= 2;
        else
        {
          /* Invalid padding */
          free(out);
          return NULL;
        }
        break;
      }
    }
  }

  *out_len = pos - out;
  return out;
}

unsigned char *base64_encode(const unsigned char *src, size_t len, size_t *out_len)
{
  unsigned char *out, *pos;
  const unsigned char *end, *in;
  size_t olen;
  int line_len;

  olen = len * 4 / 3 + 4; /* 3-byte blocks to 4-byte */
  olen += olen / 72;      /* line feeds */
  olen++;                 /* nul termination */
  if (olen < len)
    return NULL; /* integer overflow */
  out = (unsigned char *)malloc(olen);
  if (out == NULL)
    return NULL;

  end = src + len;
  in = src;
  pos = out;
  line_len = 0;
  while (end - in >= 3)
  {
    *pos++ = base64_table[in[0] >> 2];
    *pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
    *pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
    *pos++ = base64_table[in[2] & 0x3f];
    in += 3;
    line_len += 4;
    if (line_len >= 72)
    {
      *pos++ = '\n';
      line_len = 0;
    }
  }

  if (end - in)
  {
    *pos++ = base64_table[in[0] >> 2];
    if (end - in == 1)
    {
      *pos++ = base64_table[(in[0] & 0x03) << 4];
      *pos++ = '=';
    }
    else
    {
      *pos++ = base64_table[((in[0] & 0x03) << 4) |
                            (in[1] >> 4)];
      *pos++ = base64_table[(in[1] & 0x0f) << 2];
    }
    *pos++ = '=';
    line_len += 4;
  }

  if (line_len)
    *pos++ = '\n';

  *pos = '\0';
  if (out_len)
    *out_len = pos - out;
  return out;
}

void generate_sha256(char *result, size_t size)
{
  unsigned char random_bytes[SHA256_DIGEST_LENGTH];
  RAND_bytes(random_bytes, sizeof(random_bytes));
  for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
  {
    sprintf(&result[i * 2], "%02x", random_bytes[i]);
  }
}

const int str_to_int_hex(const char *str)
{
  char *endptr;
  long value = strtol(str, &endptr, 16);

  if (endptr == str)
  {
    perror("Error: No digits were found");
    return 0;
  }

  if (value > INT_MAX || value < INT_MIN)
  {
    perror("Error: Value out of range for int");
    return 0;
  }

  return (int)value;
}

char *crop_sentence(const char *header_value)
{
  return strdup(header_value + 15);
}

int split_string_by_comma(char *sentence, char **values, int max_values)
{
  int i = 0;

  while ((i < max_values) && (*sentence != '\0'))
  {
    // Rewind to after spaces
    while ((*sentence == ' ') || (*sentence == ','))
    {
      sentence++;
    }

    // Check for end of string
    if (*sentence == '\0')
    {
      break;
    }

    values[i++] = sentence;

    // Find comma
    if ((sentence = strchr(sentence, ',')) == NULL)
    {
      // End of string
      break;
    }

    *(sentence++) = '\0';
  }

  return i;
}

unsigned int tokenize_sentence(char *sentence, char **values, unsigned int max_values)
{
  unsigned int i = 0;
  char *cursor = sentence;

  if (strncmp(cursor, "Digest ", 7) == 0)
  {
    cursor += 7;
  }

  while ((i < max_values) && (*cursor != '\0'))
  {
    // Rewind to after spaces
    while ((*cursor == ' ') || (*cursor == ','))
    {
      cursor++;
    }

    // Check for end of string
    if (*cursor == '\0')
    {
      break;
    }

    values[i++] = cursor;

    // Find equal sign (=)
    if ((cursor = strchr(cursor, '=')) == NULL)
    {
      // End of string
      break;
    }

    // Check if a quotation mark follows the =
    if (*(cursor) == '\"')
    {
      cursor++;
      // Find next quotation mark
      char *quote_end = strchr(cursor, '\"');
      if (quote_end == NULL)
      {
        // End of string
        break;
      }
      // Comma should be after
      cursor = quote_end + 1;
    }
    else
    {
      // Find comma
      if ((cursor = strchr(cursor, ',')) == NULL)
      {
        // End of string
        break;
      }
    }

    *(cursor++) = '\0';
  }

  return i;
}

char *dgst_get_val(char *parameter)
{
  char *cursor, *q;

  // Find start of value
  if ((cursor = strchr(parameter, '=')) == NULL)
  {
    return (char *)NULL;
  }

  if (*(++cursor) != '"')
  {
    return cursor;
  }

  cursor++;
  if ((q = strchr(cursor, '"')) == NULL)
  {
    return (char *)NULL;
  }
  *q = '\0';

  return cursor;
}
