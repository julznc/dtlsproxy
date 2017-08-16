#ifndef PROXY_H
#define PROXY_H

#include "address.h"
#include "keystore.h"
#include "session.h"

typedef struct proxy_option {
    struct {
        const char *host;
        const char *port;
        session_t   addr;
    } listen;
    struct {
        const char *host;
        const char *port;
        session_t   addr;
    } backend;
} proxy_option_t;

typedef struct proxy_context {
    proxy_option_t *option;
    dtls_context_t *dtls;
    keystore_t *psk;
    session_context_t *sessions;
    int listen_fd;
    struct ev_loop *loop;
    ev_io watcher;
} proxy_context_t;


int proxy_init(proxy_context_t *ctx,
               proxy_option_t *opt,
               char *psk_buf);

int proxy_run(proxy_context_t *ctx);

void proxy_exit(proxy_context_t *ctx);

void proxy_deinit(proxy_context_t *ctx);

#endif // PROXY_H
