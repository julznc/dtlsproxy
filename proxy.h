#ifndef PROXY_H
#define PROXY_H

#include "address.h"
#include "backend.h"
#include "client.h"
#include "keystore.h"

typedef struct proxy_context {
    dtls_context_t *dtls;
    keystore_t *psk;
    struct {
        session_t addr;
        int fd;
    } listen;
    struct {
        backend_context_t *addr;
        uint8_t count;
        uint8_t current;
    } backends;
    client_context_t *clients;
    struct ev_loop *loop;
    ev_io watcher;
} proxy_context_t;


int proxy_init(proxy_context_t *ctx,
               char *listen_addr_buf,
               char *backends_addr_buf,
               char *psk_buf);

int proxy_run(proxy_context_t *ctx);

void proxy_exit(proxy_context_t *ctx);

void proxy_deinit(proxy_context_t *ctx);

#endif // PROXY_H
