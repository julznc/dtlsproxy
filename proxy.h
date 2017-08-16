#ifndef PROXY_H
#define PROXY_H

#include "address.h"
#include "keystore.h"
#include "session.h"

typedef struct proxy_option {
    struct {
        const char *host;
        const char *port;
    } listen;
    struct {
        const char *host;
        const char *port;
    } backend;
} proxy_option_t;

typedef struct proxy_context {
    const proxy_option_t *option;
    dtls_context_t *dtls;
    keystore_t *psk;
    session_context_t *sessions;
    session_t listen_addr;
    session_t backend_addr;
    int listen_fd;
    struct ev_loop *loop;
    ev_io watcher;
} proxy_context_t;


int proxy_init(proxy_context_t *ctx,
               const proxy_option_t *opt,
               char *psk_buf);

int proxy_run(proxy_context_t *ctx);

void proxy_exit(proxy_context_t *ctx);

void proxy_deinit(proxy_context_t *ctx);

#endif // PROXY_H
