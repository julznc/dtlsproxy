#ifndef SESSION_H
#define SESSION_H

#include <tinydtls.h>
#include <dtls.h>
#include <ev.h>

#include "address.h"


typedef struct session_context {
    struct session_context *next;
    session_t dtls_session;
    int client_fd;
    int backend_fd;
    ev_io backend_rd_watcher;
} session_context_t;

struct proxy_context;

session_context_t *new_session(struct proxy_context *ctx,
                               int sockfd, const address_t *remote);

session_context_t *find_session(struct proxy_context *ctx,
                                int sockfd, const address_t *dst);

void free_session(struct proxy_context *ctx,
                  session_context_t *session);

#endif // SESSION_H
