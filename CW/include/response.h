#ifndef RESPONSE_H
#define RESPONSE_H

#include <stddef.h>

void send_file(int client, const char *path);

void send_response(int client, const char *header, const char *body);

void serve_directory(int client, const char *path);

void get_auth_response(const char *auth_type, char *result, size_t result_max_digest);
const char *get_digest(char *result, size_t max_length);

const char *get_mime_type(const char *file_name);
const int is_allowed_file_type(const char *file_name);

#endif // RESPONSE_H
