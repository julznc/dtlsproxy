#ifndef PROXY_H
#define PROXY_H

#include "keystore.h"

typedef struct proxy_context {
    keystore_t *psk;
    int listen_fd;
} proxy_context_t;

#endif // PROXY_H
