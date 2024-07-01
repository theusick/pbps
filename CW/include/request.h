#ifndef REQUEST_H
#define REQUEST_H

#include "config.h"

typedef struct
{
  char method[16];
  char path[MAX_PATH];
  char protocol[16];
  char *auth_data;
} HttpRequest;

void handle_request(int client);

void handle_message(HttpRequest *request, int client);

void process_get(HttpRequest *request, int client);
void process_post(HttpRequest *request, int client);

void get_req_resource(const char *path, int client, char *auth_data);
void serve_directory(int client, const char *path);

void parse_request(char *message, HttpRequest *request);

char *get_client_ip(int client);
const int get_uniq_client_id(const char *client_ip);

#endif // REQUEST_H
