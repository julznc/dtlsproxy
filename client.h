#ifndef CLIENT_H
#define CLIENT_H

#include <tinydtls.h>
#include <dtls.h>
#include <ev.h>

struct proxy_context;

typedef struct client_context {
    struct client_context *next;
    dtls_context_t *dtls;
    dtls_peer_t peer;
    uint32_t index;
    int client_fd;
    int backend_fd;
    ev_io client_rd_watcher;
    ev_io backend_rd_watcher;
} client_context_t;


client_context_t *new_client(struct proxy_context *ctx,
                             const dtls_peer_t *peer);

void free_client(struct proxy_context *ctx,
                 client_context_t *client);

client_context_t *find_client(struct proxy_context *ctx,
                              const session_t *addr);

int start_client(struct proxy_context *ctx,
                 client_context_t *client);

void stop_client(struct proxy_context *ctx,
                 client_context_t *client);

#endif // CLIENT_H
