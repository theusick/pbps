#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *ROOT;
char *LDAP_URI;
char *LDAP_BASE;
char *LDAP_BIND_DN;
char *LDAP_BIND_PASS;

void load_config(const char *filename)
{
  FILE *file = fopen(filename, "r");
  if (file == NULL)
  {
    fprintf(stderr, "Unable to open config file %s\n", filename);
    exit(EXIT_FAILURE);
  }

  char line[256];
  while (fgets(line, sizeof(line), file))
  {
    if (strncmp(line, "ROOT=", 5) == 0)
    {
      ROOT = strdup(line + 5);
      ROOT[strcspn(ROOT, "\n")] = '\0';
    }
    else if (strncmp(line, "LDAP_URI=", 9) == 0)
    {
      LDAP_URI = strdup(line + 9);
      LDAP_URI[strcspn(LDAP_URI, "\n")] = '\0';
    }
    else if (strncmp(line, "LDAP_BASE=", 10) == 0)
    {
      LDAP_BASE = strdup(line + 10);
      LDAP_BASE[strcspn(LDAP_BASE, "\n")] = '\0';
    }
    else if (strncmp(line, "LDAP_BIND_DN=", 13) == 0)
    {
      LDAP_BIND_DN = strdup(line + 13);
      LDAP_BIND_DN[strcspn(LDAP_BIND_DN, "\n")] = '\0';
    }
    else if (strncmp(line, "LDAP_BIND_PASS=", 15) == 0)
    {
      LDAP_BIND_PASS = strdup(line + 15);
      LDAP_BIND_PASS[strcspn(LDAP_BIND_PASS, "\n")] = '\0';
    }
  }

  fclose(file);
}
