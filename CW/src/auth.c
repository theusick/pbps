#include "auth.h"
#include "digest.h"
#include "config.h"
#include "response.h"
#include "http_responses.h"

#include <ldap.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int authenticate_digest(const char *auth_header)
{
  digest_t digest;
  digest_init(&digest);

  int parse_length = parse_digest(&digest, auth_header);

  if (parse_length <= 0)
  {
    perror("Invalid parse Digest header");
    return 0;
  }

  LDAP *ld;
  LDAPMessage *result, *entry;
  int ldap_version = LDAP_VERSION3;
  char *attrs[] = {"userPasswordMD5", "authRealm", NULL};
  char filter[128];
  int rc;
  char *dn;
  struct berval **values;
  unsigned char md5_hash[MD5_DIGEST_LENGTH];
  const char *qop_value = get_qop_value(&digest);
  char md5_base64[33];

  char nc_str[9];
  snprintf(nc_str, sizeof(nc_str), "%08x", digest.nc);

  rc = ldap_initialize(&ld, LDAP_URI);
  if (rc != LDAP_SUCCESS)
  {
    fprintf(stderr, "ldap_initialize: %s\n", ldap_err2string(rc));
    return 0;
  }

  result = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &ldap_version);
  if (result != LDAP_OPT_SUCCESS)
  {
    fprintf(stderr, "ldap_set_option failed: %s\n", ldap_err2string(result));
    ldap_unbind_ext_s(ld, NULL, NULL);
    return 0;
  }

  rc = ldap_simple_bind_s(ld, LDAP_BIND_DN, LDAP_BIND_PASS);
  if (rc != LDAP_SUCCESS)
  {
    ldap_unbind_ext_s(ld, NULL, NULL);
    fprintf(stderr, "ldap_simple_bind_s: %s\n", ldap_err2string(rc));
    return 0;
  }

  snprintf(filter, sizeof(filter), "(uid=%s)", digest.username);
  rc = ldap_search_ext_s(ld, LDAP_BASE, LDAP_SCOPE_SUBTREE, filter, attrs, 0, NULL, NULL, NULL, 0, &result);
  if (rc != LDAP_SUCCESS)
  {
    fprintf(stderr, "ldap_search_ext_s: %s\n", ldap_err2string(rc));
    ldap_unbind_ext_s(ld, NULL, NULL);
    return 0;
  }

  entry = ldap_first_entry(ld, result);
  if (entry == NULL)
  {
    fprintf(stderr, "User not found\n");
    ldap_msgfree(result);
    ldap_unbind_ext_s(ld, NULL, NULL);
    return 0;
  }

  dn = ldap_get_dn(ld, entry);
  if (dn == NULL)
  {
    fprintf(stderr, "ldap_get_dn: %s\n", ldap_err2string(rc));
    ldap_msgfree(result);
    ldap_unbind_ext_s(ld, NULL, NULL);
    return 0;
  }

  values = ldap_get_values_len(ld, entry, "authRealm");
  if (values == NULL || strcmp(values[0]->bv_val, digest.realm) != 0)
  {
    fprintf(stderr, "Realm mismatch\n");
    ldap_value_free_len(values);
    ldap_memfree(dn);
    ldap_msgfree(result);
    ldap_unbind_ext_s(ld, NULL, NULL);
    return 0;
  }
  ldap_value_free_len(values);

  values = ldap_get_values_len(ld, entry, "userPasswordMD5");
  if (values == NULL)
  {
    fprintf(stderr, "Password not found\n");
    ldap_memfree(dn);
    ldap_msgfree(result);
    ldap_unbind_ext_s(ld, NULL, NULL);
    return 0;
  }

  size_t decoded_len;
  unsigned char *pwd = base64_decode(values[0]->bv_val, strlen(values[0]->bv_val), &decoded_len);
  if (pwd == NULL)
  {
    fprintf(stderr, "Error decoding base64\n");
    ldap_value_free_len(values);
    ldap_memfree(dn);
    ldap_msgfree(result);
    ldap_unbind_ext_s(ld, NULL, NULL);
    return 0;
  }

  unsigned char ha1[MD5_DIGEST_LENGTH];
  MD5_CTX md5_ctx;
  MD5_Init(&md5_ctx);
  MD5_Update(&md5_ctx, digest.username, strlen(digest.username));
  MD5_Update(&md5_ctx, ":", 1);
  MD5_Update(&md5_ctx, digest.realm, strlen(digest.realm));
  MD5_Update(&md5_ctx, ":", 1);
  MD5_Update(&md5_ctx, pwd, strlen(pwd));
  MD5_Final(ha1, &md5_ctx);

  unsigned char ha2[MD5_DIGEST_LENGTH];
  MD5_Init(&md5_ctx);
  MD5_Update(&md5_ctx, "GET", strlen("GET"));
  MD5_Update(&md5_ctx, ":", 1);
  MD5_Update(&md5_ctx, digest.uri, strlen(digest.uri));
  MD5_Final(ha2, &md5_ctx);

  char ha1_hex[2 * MD5_DIGEST_LENGTH + 1];
  for (size_t i = 0; i < MD5_DIGEST_LENGTH; ++i)
    sprintf(&ha1_hex[i * 2], "%02x", ha1[i]);

  char ha2_hex[2 * MD5_DIGEST_LENGTH + 1];
  for (size_t i = 0; i < MD5_DIGEST_LENGTH; ++i)
    sprintf(&ha2_hex[i * 2], "%02x", ha2[i]);

  char final_string[512];
  snprintf(final_string, sizeof(final_string), "%s:%s:%s:%s:%s:%s", ha1_hex, digest.nonce, nc_str, digest.cnonce, qop_value, ha2_hex);

  MD5_Init(&md5_ctx);
  MD5_Update(&md5_ctx, final_string, strlen(final_string));
  MD5_Final(md5_hash, &md5_ctx);

  char computed_response[2 * MD5_DIGEST_LENGTH + 1];
  for (size_t i = 0; i < MD5_DIGEST_LENGTH; ++i)
  {
    sprintf(&computed_response[i * 2], "%02x", md5_hash[i]);
  }

  printf("Computed response: %s\n", computed_response);
  printf("response: %s\n", digest.response);

  int auth_success = strcmp(digest.response, computed_response) == 0;

  free(pwd);
  ldap_value_free_len(values);
  ldap_memfree(dn);
  ldap_msgfree(result);
  ldap_unbind_ext_s(ld, NULL, NULL);
  return auth_success ? 1 : 0;
}

int authenticate_ldap(const char *username, const char *password)
{
  LDAP *ld;
  int ldap_version = LDAP_VERSION3;
  int result = -1;
  char binddn[256];

  const char *ldapUri = "ldap://localhost";
  const char *ldapBase = "dc=test-ldap,dc=ru";

  sprintf(binddn, "uid=%s,ou=people,%s", username, ldapBase);

  result = ldap_initialize(&ld, ldapUri);
  if (result != LDAP_SUCCESS)
  {
    fprintf(stderr, "ldap_initialize: %s\n", ldap_err2string(result));
    return 0;
  }

  result = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &ldap_version);
  if (result != LDAP_OPT_SUCCESS)
  {
    fprintf(stderr, "ldap_set_option failed: %s\n", ldap_err2string(result));
    ldap_unbind_ext_s(ld, NULL, NULL);
    return 0;
  }

  result = ldap_simple_bind_s(ld, binddn, password);

  ldap_unbind_ext_s(ld, NULL, NULL);

  if (result != LDAP_SUCCESS)
  {
    fprintf(stderr, "ldap_simple_bind_s: %s\n", ldap_err2string(result));
    return 0;
  }

  return 1;
}

const int handle_auth_timeout(int client, int client_id)
{
  time_t current_time = time(NULL);

  if ((auth_status[client_id].attempts >= MAX_ATTEMPTS) &&
      (current_time - auth_status[client_id].last_attempt < TIMEOUT))
  {
    send_response(client, HTTP_429, "");
    printf("Client '%d' 429 Too Many Requests. Attempt: %d\n", client_id, auth_status[client_id].attempts);
    return 0;
  }
  return 1;
}

const int handle_digest_auth(int client, const char *auth_data, int client_id, char *auth_type)
{
  if (handle_auth_timeout(client, client_id) == 0)
  {
    return 0;
  }

  if (authenticate_digest(auth_data) == 0)
  {
    auth_status[client_id].attempts++;
    auth_status[client_id].last_attempt = time(NULL);

    char auth_body[MAX_DIGEST + 18];
    get_auth_response(auth_type, auth_body, MAX_DIGEST + 18);
    send_response(client, HTTP_401, auth_body);

    printf("Client '%d' 401 Unauthorized. Attempt: %d\n", client_id, auth_status[client_id].attempts);
    return 0;
  }
  else
  {
    auth_status[client_id].attempts = 0;
  }
  return 1;
}

const int handle_basic_auth(int client, const char *auth_data, int client_id, char *auth_type)
{
  char *auth_str = auth_data + 21; // Skip "Authorization: Basic "
  unsigned char *decoded = NULL;

  size_t decoded_len;
  decoded = base64_decode((const unsigned char *)auth_str, strlen(auth_str), &decoded_len);
  if (decoded == NULL)
  {
    fprintf(stderr, "Error decoding base64\n");
    free(decoded);
    return 0;
  }

  char username[64], password[64];
  sscanf((const char *)decoded, "%63[^:]:%63s", username, password);
  time_t current_time = time(NULL);

  if (handle_auth_timeout(client, client_id) == 0)
  {
    free(decoded);
    return 0;
  }

  if (authenticate_ldap(username, password) == 0)
  {
    auth_status[client_id].attempts++;
    auth_status[client_id].last_attempt = current_time;

    char auth_body[MAX_DIGEST + 18];
    get_auth_response(auth_type, auth_body, MAX_DIGEST + 18);
    send_response(client, HTTP_401, auth_body);

    printf("Client '%d' 401 Unauthorized. Attempt: %d\n", client_id, auth_status[client_id].attempts);
    free(decoded);
    return 0;
  }

  auth_status[client_id].attempts = 0;
  free(decoded);
  return 1;
}

const int handle_auth(int client, const char *auth_data, int client_id, char *auth_type)
{
  if (auth_data == NULL)
  {
    char auth_body[MAX_DIGEST + 18];
    get_auth_response(auth_type, auth_body, MAX_DIGEST + 18);
    send_response(client, HTTP_401, auth_body);
    return 0;
  }

  if (strcmp(auth_type, "Digest") == 0)
  {
    return handle_digest_auth(client, auth_data, client_id, auth_type);
  }
  else
  {
    return handle_basic_auth(client, auth_data, client_id, auth_type);
  }
}

void generate_nonce_opaque(digest_t *digest, char *nonce, char *opaque)
{
  unsigned char hash[SHA256_DIGEST_LENGTH];
  char input[256];
  time_t t;

  // Generate a base input string
  srand((unsigned)time(&t));
  snprintf(input, sizeof(input), "%lu%lu", t, rand());

  if (digest->algorithm == DIGEST_ALGORITHM_MD5)
  {
    MD5((unsigned char *)input, strlen(input), hash);
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++)
    {
      snprintf(&(nonce[i * 2]), 16 * 2, "%02x", (unsigned int)hash[i]);
      snprintf(&(opaque[i * 2]), 16 * 2, "%02x", (unsigned int)hash[i]);
    }
  }
  else if (digest->algorithm == DIGEST_ALGORITHM_SHA256)
  {
    SHA256((unsigned char *)input, strlen(input), hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
      snprintf(&(nonce[i * 2]), 32 * 2, "%02x", (unsigned int)hash[i]);
      snprintf(&(opaque[i * 2]), 32 * 2, "%02x", (unsigned int)hash[i]);
    }
  }
}
