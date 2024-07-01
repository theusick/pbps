#include "server.h"
#include "client.h"
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

auth_status_t *auth_status = NULL;
client_info_t *client_info = NULL;

int set_sigint_handler();
void handle_sigint_main(int sig);

int main(int argc, char *argv[])
{
  // Default Values PATH = ~/ and PORT=10000
  char PORT[6] = "10000";
  ROOT = getenv("PWD");
  strcpy(PORT, "10000");

  // Parsing command-line arguments
  char opt;
  while ((opt = getopt(argc, argv, "p:r:")) != -1)
  {
    switch (opt)
    {
    case 'r':
      ROOT = malloc(strlen(optarg));
      strcpy(ROOT, optarg);
      break;
    case 'p':
      strcpy(PORT, optarg);
      break;
    default:
      fprintf(stderr, "Usage: %s [-p port] [-r root]\n", argv[0]);
      exit(EXIT_FAILURE);
    }
  }

  load_config("config/server.conf");

  int sigaction = set_sigint_handler();
  if (sigaction == -1)
  {
    perror("sigaction()");
    exit(EXIT_FAILURE);
  }

  printf("Server started at port no. %s%s%s"
         " with root directory as %s%s%s\n",
         "\033[92m", PORT, "\033[0m",
         "\033[92m", ROOT, "\033[0m");
  start_server(PORT);
  accept_connections();

  return 0;
}

int set_sigint_handler()
{
  struct sigaction sa_main;
  sa_main.sa_handler = &handle_sigint_main;
  sigemptyset(&sa_main.sa_mask);
  sa_main.sa_flags = 0;

  return sigaction(SIGINT, &sa_main, NULL);
}

void handle_sigint_main(int sig)
{
  printf("Received %d in main process. Cleaning up...\n", sig);

  free(ROOT);

  exit(EXIT_SUCCESS);
}
