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
        backend_context_t *server;
        uint8_t count;
        uint8_t current;
    } backends;
    struct {
        client_context_t *client;
        uint32_t count;
        uint32_t index;
    } clients;
    struct ev_loop *loop;
    ev_io watcher;
} proxy_context_t;


int proxy_init(proxy_context_t *ctx,
               char *listen_addr_buf,
               char *backends_addr_buf,
               char *psk_buf);

int proxy_run(proxy_context_t *ctx);

void proxy_cb(EV_P_ ev_io *w, int revents);

void proxy_exit(proxy_context_t *ctx);

void proxy_deinit(proxy_context_t *ctx);

#endif // PROXY_H
