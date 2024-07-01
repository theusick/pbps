#include "server.h"
#include "auth.h"
#include "request.h"
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netdb.h>

pid_t parent_pid;
int listenfd, clients[CONNMAX];

void start_server(const char *port)
{
  struct addrinfo hints, *res, *p;
  int opt = 1;

  init_sharemem();

  struct sigaction sa;
  sa.sa_handler = &handle_sigint;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;

  if (sigaction(SIGINT, &sa, NULL) == -1)
  {
    perror("sigaction");
    exit(EXIT_FAILURE);
  }

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  if (getaddrinfo(NULL, port, &hints, &res) != 0)
  {
    perror("getaddrinfo");
    exit(EXIT_FAILURE);
  }

  for (p = res; p != NULL; p = p->ai_next)
  {
    listenfd = socket(p->ai_family, p->ai_socktype, 0);
    if (listenfd == -1)
      continue;
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) != 0)
    {
      perror("setsockopt");
      close(listenfd);
      exit(EXIT_FAILURE);
    }
    if (bind(listenfd, p->ai_addr, p->ai_addrlen) == 0)
      break;
  }
  if (p == NULL)
  {
    perror("socket() or bind()");
    exit(EXIT_FAILURE);
  }
  freeaddrinfo(res);

  // listen for incoming connections
  if (listen(listenfd, 1000000) != 0)
  {
    perror("listen() error");
    exit(EXIT_FAILURE);
  }
}

void accept_connections()
{
  struct sockaddr_in clientaddr;
  socklen_t addrlen = sizeof(clientaddr);

  int slot = 0;

  while (1)
  {
    clients[slot] = accept(listenfd, (struct sockaddr *)&clientaddr, &addrlen);
    if (clients[slot] < 0)
    {
      perror("accept() error");
    }
    else
    {
      if (fork() == 0)
      {
        // Child process: ignore SIGINT
        signal(SIGINT, SIG_IGN);
        handle_client(slot);
        exit(EXIT_SUCCESS);
      }
    }
    while (clients[slot] != -1)
      slot = (slot + 1) % CONNMAX;
  }

  shm_unlink("/auth_status");
  shm_unlink("/client_info");
}

void handle_sigint(int sig)
{
  printf("Received %d in server process. Cleaning up...\n", sig);

  // Send SIGTERM to all forks
  for (int i = 0; i < CONNMAX; i++)
  {
    if (clients[i] != -1)
    {
      kill(clients[i], SIGTERM);
    }
  }

  while (waitpid(-1, NULL, WNOHANG) > 0)
  {
  };

  memset(auth_status, 0, sizeof(auth_status_t));
  memset(client_info, 0, sizeof(client_info_t));

  // Unlink shared memory
  shm_unlink("/auth_status");
  shm_unlink("/client_info");

  // Close server socket
  close(listenfd);
  printf("Server shut down.\n");

  exit(0);
}

void handle_client(int slot)
{
  handle_request(clients[slot]);
  shutdown(clients[slot], SHUT_RDWR);
  close(clients[slot]);
  clients[slot] = -1;
}

void init_sharemem()
{
  // Setting all elements to -1: signifies there is no client connected
  for (int i = 0; i < CONNMAX; i++)
  {
    clients[i] = -1;
  }

  int shm_fd = shm_open("/auth_status", O_CREAT | O_RDWR, 0666);
  ftruncate(shm_fd, CONNMAX * sizeof(auth_status_t));
  auth_status = mmap(0, CONNMAX * sizeof(auth_status_t), PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
  if (auth_status == MAP_FAILED)
  {
    perror("mmap");
    exit(EXIT_FAILURE);
  }

  shm_fd = shm_open("/client_info", O_CREAT | O_RDWR, 0666);
  ftruncate(shm_fd, CONNMAX * sizeof(client_info_t));
  client_info = mmap(0, CONNMAX * sizeof(client_info_t), PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
  if (client_info == MAP_FAILED)
  {
    perror("mmap");
    exit(EXIT_FAILURE);
  }
}
