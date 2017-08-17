#ifndef BACKEND_H
#define BACKEND_H

#include <tinydtls.h>
#include <dtls.h>

struct proxy_context;

typedef struct backend_context {
    struct backend_context *next;
    session_t address;
} backend_context_t;

backend_context_t *new_backend(struct proxy_context *ctx,
                               const char *host_port);

void free_backend(struct proxy_context *ctx,
                  backend_context_t *backend);

backend_context_t *next_backend(struct proxy_context *ctx);

#endif // BACKEND_H
