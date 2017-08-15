#ifndef PROXY_H
#define PROXY_H

#include "address.h"
#include "keystore.h"

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
    dtls_context_t *dtls;
    const keystore_t *psk;
    const proxy_option_t *option;
    session_t listen_addr;
    int listen_fd;
} proxy_context_t;

int proxy_init(proxy_context_t *ctx,
               const proxy_option_t *opt,
               char *psk_buf);

#endif // PROXY_H
