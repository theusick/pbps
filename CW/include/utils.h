#ifndef UTILS_H
#define UTILS_H

#include <time.h>

typedef struct
{
  int attempts;
  time_t last_attempt;
} auth_status_t;

unsigned int hash_ip(const char *ip);
unsigned char *base64_decode(const unsigned char *src, size_t len,
                             size_t *out_len);
unsigned char *base64_encode(const unsigned char *src, size_t len,
                             size_t *out_len);

const int str_to_int_hex(const char *str);

char *crop_sentence(const char *header_value);
int split_string_by_comma(char *sentence, char **values, int max_values);
unsigned int tokenize_sentence(char *sentence, char **values, unsigned int max_values);

char *dgst_get_val(char *parameter);

#endif // UTILS_H
