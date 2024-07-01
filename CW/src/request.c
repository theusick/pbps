#include "request.h"
#include "auth.h"
#include "response.h"
#include "digest.h"
#include "config.h"
#include "http_responses.h"
#include "htaccess.h"
#include "digest.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>

void handle_request(int client)
{
  char buffer[MAX_MESSAGE];
  memset((void *)buffer, (int)'\0', MAX_MESSAGE);

  int rcvd = recv(client, buffer, MAX_MESSAGE, 0);

  if (rcvd < 0) // receive error
  {
    fprintf(stderr, "recv() error\n");
  }
  else if (rcvd == 0) // receive socket closed
  {
    fprintf(stderr, "Client disconnected unexpectedly.\n");
  }
  else // message received
  {
    printf("%s", buffer);

    HttpRequest request;
    parse_request(buffer, &request);
    handle_message(&request, client);
  }
}

void handle_message(HttpRequest *request, int client)
{
  if (strcmp(request->method, "GET") == 0)
  {
    process_get(request, client);
  }
  else if (strcmp(request->method, "POST") == 0)
  {
    process_post(request, client);
  }
  else
  {
    send_response(client, HTTP_501, "");
  }
}

void process_get(HttpRequest *request, int client)
{
  if ((strncmp(request->protocol, "HTTP/1.0", 8) != 0) &&
      (strncmp(request->protocol, "HTTP/1.1", 8) != 0))
  {
    send_response(client, HTTP_400, "");
    return;
  }

  if (strncmp(request->path, "/\0", 2) == 0)
  {
    // Because if no file is specified, index.html will be
    // opened by default (like it happens in APACHE...)
    strcpy(request->path, "/index.html");
  }

  char temp_path[MAX_PATH];
  snprintf(temp_path, sizeof(temp_path), "%s%s", ROOT, request->path);
  strcpy(request->path, temp_path);

  get_req_resource(request->path, client, request->auth_data);
}

void process_post(HttpRequest *request, int client)
{
  send_response(client, HTTP_501, "501 Not Implemented\r\n");
}

void get_req_resource(const char *path, int client, char *auth_data)
{
  int client_ip = get_client_ip(client);
  int client_id = get_uniq_client_id(client_ip);

  strcpy(client_info[client_id].ip, &client_ip);

  char auth_type[AUTH_TYPE_LEN] = "Basic";
  read_htaccess(path, auth_type);

  // Initialize attempts and last_attempt if it's the first request from this client
  if (auth_status[client_id].last_attempt == 0)
  {
    auth_status[client_id].attempts = 0;
    auth_status[client_id].last_attempt = time(NULL);
  }

  int needAuth = has_dir_htaccess(path);
  if (needAuth && handle_auth(client, auth_data, client_id, auth_type))
  {
    printf("Client '%d' Successfully authorized!\n", client_id);
    serve_directory(client, path);
  }
  else if (!needAuth)
  {
    serve_directory(client, path);
  }
}

void serve_directory(int client, const char *path)
{
  struct stat path_stat;
  if (stat(path, &path_stat) == 0)
  {
    if (S_ISDIR(path_stat.st_mode))
    {
      char index_path[MAX_PATH];
      snprintf(index_path, sizeof(index_path), "%s/index.html", path);
      if (access(index_path, F_OK) != -1)
      {
        send_file(client, index_path);
      }
      else
      {
        send_response(client, HTTP_403, "403 Forbidden\r\n");
      }
    }
    else
    {
      if (is_allowed_file_type(path))
      {
        send_file(client, path);
      }
      else
      {
        send_response(client, HTTP_403, "403 Forbidden\r\n");
      }
    }
  }
  else
  {
    send_response(client, HTTP_404, "404 Not Found\r\n");
  }
}

void parse_request(char *message, HttpRequest *request)
{
  char *line, *save_ptr;
  sscanf(message, "%15s %255s %15s", request->method, request->path, request->protocol);

  line = strtok_r(message, "\r\n", &save_ptr);
  while (line)
  {
    request->auth_data = strstr(line, "Authorization");
    if (request->auth_data)
      break;
    line = strtok_r(NULL, "\r\n", &save_ptr);
  }
}

char *get_client_ip(int client)
{
  struct sockaddr_in addr;
  socklen_t addr_size = sizeof(struct sockaddr_in);
  getpeername(client, (struct sockaddr *)&addr, &addr_size);

  return inet_ntoa(addr.sin_addr);
}

const int get_uniq_client_id(const char *client_ip)
{
  return hash_ip(&client_ip);
}
