
#include <string.h>
#include <utlist.h>

#include "backend.h"
#include "proxy.h"
#include "utils.h"

backend_context_t *new_backend(struct proxy_context *ctx,
                               const char *host_port)
{
    //DBG("%s(%s)", __func__, host_port);

    char addrbuf[128];
    strncpy(addrbuf, host_port, sizeof(addrbuf)-1);

    char *sep = strrchr(addrbuf, ':');
    if (NULL==sep) {
        ERR("no specified port");
        return NULL;
    }

    *sep = '\0';

    backend_context_t *backend = (backend_context_t *)malloc(sizeof(backend_context_t));
    if (NULL==backend) {
        ERR("failed to allocate backend_context");
        return NULL;
    }
    memset(backend, 0, sizeof(backend_context_t));

    if (resolve_address(addrbuf, sep+1, &backend->address) < 0) {
        ERR("cannot resolve backend address");
        free(backend);
        return NULL;
    }

    backend->address.ifindex = ctx->backends.count++;

    memset(addrbuf, 0, sizeof(addrbuf));
    print_address(&backend->address, addrbuf, sizeof(addrbuf)-1);
    DBG("backend %u: %s", backend->address.ifindex, addrbuf);

    LL_PREPEND(ctx->backends.addr, backend);
    return backend;
}

void free_backend(struct proxy_context *ctx,
                  backend_context_t *backend)
{
    if (ctx && backend) {
        LL_DELETE(ctx->backends.addr, backend);
        ctx->backends.count--;
        free(backend);
    }
}

backend_context_t *next_backend(struct proxy_context *ctx)
{
    backend_context_t *backend = NULL;

    LL_FOREACH(ctx->backends.addr, backend)  {
        if (ctx->backends.current == backend->address.ifindex) {
            // next index
            if (++ctx->backends.current >= ctx->backends.count ) {
                ctx->backends.current = 0;
            }
            return backend;
        }
    }

    return backend;
}

