#ifndef CONFIG_H
#define CONFIG_H

#include "client.h"
#include "utils.h"

#define CONNMAX 1000
#define BYTES 1024
#define MAX_MESSAGE 99999
#define MAX_PATH 1024

#define MAX_DIGEST 4096

#define AUTH_REALM "people@test-ldap.ru"
#define AUTH_TYPE_LEN 64
#define DIGEST_NONCE_LIFETIME 30
#define MAX_ATTEMPTS 3
#define TIMEOUT 30

extern char *ROOT;
extern auth_status_t *auth_status;
extern client_info_t *client_info;

extern char *LDAP_URI;
extern char *LDAP_BASE;
extern char *LDAP_BIND_DN;
extern char *LDAP_BIND_PASS;

void load_config(const char *filename);

#endif // CONFIG_H
