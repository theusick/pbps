#ifndef HTACCESS_H
#define HTACCESS_H

const int has_dir_htaccess(const char *path);
const int read_htaccess(const char *path, char *auth_type);

#endif // HTACCESS_H
