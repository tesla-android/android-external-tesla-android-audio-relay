#include <cutils/sockets.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "ws.h"

#define AUDIO_SOCKET_PATH "/dev/socket/ws_audio"
#define WS_PORT 8080

void webSocketOnConnectionOpened(ws_cli_conn_t *client) {
  char *cli;
  cli = ws_getaddress(client);
  printf("Connection opened, addr: %s\n", cli);
}

void webSocketOnConnectionClosed(ws_cli_conn_t *client) {
  char *cli;
  cli = ws_getaddress(client);
  printf("Connection closed, addr: %s\n", cli);
}

void webSocketOnMessage(__attribute__ ((unused)) ws_cli_conn_t *client,
       __attribute__ ((unused)) const unsigned char *msg, __attribute__ ((unused)) uint64_t size, __attribute__ ((unused)) int type) {}

void* relayThread(void* arg) {
    int listen_fd, client_fd;
    (void)arg;

    listen_fd = android_get_control_socket("ws_audio");
    if (listen_fd < 0) {
        perror("android_get_control_socket");
        return NULL;
    }

    if (listen(listen_fd, 4) < 0) {
        perror("listen");
        return NULL;
    }

    for (;;) {
        client_fd = accept(listen_fd, NULL, NULL);
        if (client_fd < 0) continue;

        for (;;) {
            uint32_t len_be;
            ssize_t r = recv(client_fd, &len_be, sizeof(len_be), MSG_WAITALL);
            if (r <= 0) break;

            uint32_t len = ntohl(len_be);
            if (len == 0) continue;

            char* buf = (char*)malloc(len);
            if (!buf) break;

            ssize_t got = recv(client_fd, buf, len, MSG_WAITALL);
            if (got != (ssize_t)len) { free(buf); break; }

            ws_sendframe_bin(NULL, buf, len);

            free(buf);
        }

        close(client_fd);
    }

    close(listen_fd);
    unlink(AUDIO_SOCKET_PATH);
    return NULL;
}

void *pingThread(__attribute__ ((unused)) void *arg) {
  while(1) {
    sleep(1);
    ws_ping(NULL, 5);
  }
  return NULL;
}

int main(void)
{
  pthread_t ping_thread;
  pthread_create(&ping_thread, NULL, pingThread, NULL);

  pthread_t relay_thread;
  pthread_create(&relay_thread, NULL, relayThread, NULL);

  struct ws_events evs;
  evs.onopen    = &webSocketOnConnectionOpened;
  evs.onclose   = &webSocketOnConnectionClosed;
  evs.onmessage = &webSocketOnMessage;
  ws_socket(&evs, WS_PORT, 0, 1000);

  pthread_join(ping_thread, NULL);
  pthread_join(relay_thread, NULL);

  return (0);
}
