#include "response.h"
#include "config.h"
#include "digest.h"
#include "auth.h"
#include "http_responses.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <netinet/in.h>

void send_file(int client, const char *path)
{
  int file_fd;
  struct stat st;
  if ((stat(path, &st) == 0) && S_ISREG(st.st_mode) &&
      ((file_fd = open(path, O_RDONLY)) != -1))
  {
    if (fstat(file_fd, &st) < 0)
    {
      perror("Error getting file stats");
      close(file_fd);
      return;
    }

    ssize_t bytes_read;
    char response_body[BYTES], data_to_send[BYTES];

    snprintf(response_body, sizeof(response_body),
             "Content-Type: %s\r\n"
             "Content-Length: %ld\r\n",
             get_mime_type(path),
             st.st_size);
    send_response(client, HTTP_200, response_body);

    while ((bytes_read = read(file_fd, data_to_send, BYTES)) > 0)
    {
      if (send(client, data_to_send, bytes_read, 0) < 0)
      {
        perror("Error sending file data");
        break;
      }
    }
    close(file_fd);
  }
  else
  {
    send_response(client, HTTP_404, "");
  }
}

void send_response(int client, const char *header, const char *body)
{
  printf("===================\n");
  printf("%s%s\r\n", header, body);

  send(client, header, strlen(header), 0);
  send(client, body, strlen(body), 0);
  send(client, "\r\n", 2, 0);
}

void get_auth_response(const char *auth_type,
                       char *result,
                       size_t result_max_digest,
                       const int client_id,
                       int stale)
{
  if (strcmp(auth_type, "Digest") == 0)
  {
    char digest[MAX_DIGEST];
    get_digest(digest, MAX_DIGEST, client_id);

    snprintf(result, result_max_digest, "WWW-Authenticate: %s, stale=%s\r\n", digest, stale ? "true" : "false");
  }
  else
  {
    strcpy(result, "WWW-Authenticate: Basic realm=\"Realm\"\r\n");
  }
}

const char *get_digest(char *result,
                       size_t max_length,
                       const int client_id)
{
  digest_t digest;
  if (digest_init(&digest) == -1)
  {
    perror("Could not init digest context");
    exit(EXIT_FAILURE);
  }

  digest_set_attr(&digest, D_ATTR_REALM, (digest_attr_value_t)AUTH_REALM);
  digest_set_attr(&digest, D_ATTR_ALGORITHM, (digest_attr_value_t)DIGEST_ALGORITHM_MD5);

  digest_set_attr(&digest, D_ATTR_NONCE, (digest_attr_value_t)client_info[client_id].nonce);
  digest_set_attr(&digest, D_ATTR_QOP, (digest_attr_value_t)DIGEST_QOP_AUTH);
  digest_set_attr(&digest, D_ATTR_OPAQUE, (digest_attr_value_t)client_info[client_id].opaque);

  generate_digest_header(&digest, result, max_length);

  return result;
}

const char *get_mime_type(const char *file_name)
{
  if (strstr(file_name, ".html"))
    return "text/html";
  if (strstr(file_name, ".css"))
    return "text/css";
  if (strstr(file_name, ".js"))
    return "application/javascript";
  if (strstr(file_name, ".jpg"))
    return "image/jpeg";
  if (strstr(file_name, ".jpeg"))
    return "image/jpeg";
  if (strstr(file_name, ".png"))
    return "image/png";
  if (strstr(file_name, ".gif"))
    return "image/gif";
  if (strstr(file_name, ".gif"))
    return "image/ico";
  return "text/plain";
}

const int is_allowed_file_type(const char *file_name)
{
  return (strstr(file_name, ".html") ||
          strstr(file_name, ".css") ||
          strstr(file_name, ".js") ||
          strstr(file_name, ".jpg") ||
          strstr(file_name, ".jpeg") ||
          strstr(file_name, ".png") ||
          strstr(file_name, ".gif") ||
          strstr(file_name, ".ico"));
}
