#include "htaccess.h"
#include "config.h"

#include <dirent.h>
#include <unistd.h>
#include <stdio.h>

const int has_dir_htaccess(const char *path)
{
  DIR *dir;
  struct dirent *entry;
  char htaccess_path[MAX_PATH];

  if ((dir = opendir(path)) == NULL)
  {
    return 0;
  }

  while ((entry = readdir(dir)) != NULL)
  {
    if (strcmp(entry->d_name, ".htaccess") == 0)
    {
      snprintf(htaccess_path, sizeof(htaccess_path), "%s/.htaccess", path);
      closedir(dir);
      return access(htaccess_path, F_OK) == 0;
    }
  }

  closedir(dir);
  return 0;
}

const int read_htaccess(const char *path, char *auth_type)
{
  char htaccess_path[256];
  snprintf(htaccess_path, sizeof(htaccess_path), "%s/.htaccess", path);

  FILE *file = fopen(htaccess_path, "r");
  if (!file)
  {
    return 0;
  }

  char line[256];
  while (fgets(line, sizeof(line), file))
  {
    if (strncmp(line, "AuthType", 8) == 0)
    {
      sscanf(line, "AuthType %9s", auth_type);
      fclose(file);
      return 1;
    }
  }

  fclose(file);
  return 0;
}
