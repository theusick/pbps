#ifndef AUTH_H
#define AUTH_H

#include "digest.h"

int authenticate_digest(const char *auth_header);

int authenticate_ldap(const char *username, const char *password);

const int handle_auth_timeout(int client, int client_id);
const int handle_digest_auth(int client, const char *auth_data, int client_id, char *auth_type);
const int handle_basic_auth(int client, const char *auth_data, int client_id, char *auth_type);
const int handle_auth(int client, const char *auth_data, int client_id, char *auth_type);

void generate_nonce_opaque(digest_t *digest, char *nonce, char *opaque);

#endif // AUTH_H
