#ifndef PROXY_H
#define PROXY_H

#include "keystore.h"
#include "address.h"
#include "session.h"


typedef struct proxy_option {
    char *listen_host;
    char *listen_port;
    char *backend_host;
    char *backend_port;
} proxy_option_t;


typedef struct proxy_psk {
    char *id;
    char *key;
} proxy_psk_t;


typedef struct proxy_context {
    const proxy_option_t *options;
    keystore_t *keystore;
    dtls_context_t *dtls;
    session_context_t *sessions;
    address_t listen_addr;
    int listen_fd;
    struct ev_loop *loop;
    ev_io watcher;
} proxy_context_t;


int proxy_init(proxy_context_t *ctx,
               const proxy_option_t *opt,
               const proxy_psk_t *psk);

int proxy_run(proxy_context_t *ctx);

void proxy_exit(proxy_context_t *ctx);

void proxy_deinit(proxy_context_t *ctx);

#endif // PROXY_H

