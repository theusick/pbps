#ifndef SERVER_H
#define SERVER_H

void start_server(const char *port);
void accept_connections();
void handle_sigint(int sig);

void handle_client(int slot);
void init_sharemem();

#endif // SERVER_H
