#ifndef SESSION_H
#define SESSION_H

#include <tinydtls.h>
#include <dtls.h>
#include <ev.h>

struct proxy_context;

typedef struct session_context {
    struct session_context *next;
    dtls_context_t *dtls;
    dtls_peer_t peer;
    int client_fd;
    int backend_fd;
    ev_io backend_rd_watcher;
} session_context_t;


session_context_t *new_session(struct proxy_context *ctx,
                               const dtls_peer_t *peer);

void free_session(struct proxy_context *ctx,
                  session_context_t *session);

session_context_t *find_session(struct proxy_context *ctx,
                                const session_t *addr);

int start_session(struct proxy_context *ctx,
                  session_context_t *session);

void stop_session(struct proxy_context *ctx,
                  session_context_t *session);

#endif // SESSION_H
