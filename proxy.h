#ifndef PROXY_H
#define PROXY_H

#include "address.h"
#include "keystore.h"

typedef struct proxy_context {
    keystore_t *psk;
    session_t listen_addr;
    int listen_fd;
} proxy_context_t;

#endif // PROXY_H
