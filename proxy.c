
#include <assert.h>
#include <errno.h>

#include "proxy.h"
#include "utils.h"

// returns non-zero on error
int proxy_init(proxy_context_t *ctx,
               const proxy_option_t *opt,
               char *psk_buf)
{
    assert (ctx && opt && psk_buf);

    ctx->option = opt;

    if (resolve_address(ctx->option->listen.host,
                        ctx->option->listen.port, &ctx->listen_addr) < 0) {
        ERR("cannot resolve listen address");
        return -1;
    }

    /* init socket and set it to non-blocking */
    ctx->listen_fd = create_socket(&ctx->listen_addr);

    if (ctx->listen_fd < 0) {
        ERR("socket: %s", strerror(errno));
        return -1;
    }

    if (bind(ctx->listen_fd, (struct sockaddr*)&ctx->listen_addr.addr, sizeof(ctx->listen_addr.addr)) < 0) {
        ERR("bind: %s", strerror(errno));
        return -1;
    }

    dtls_init();

    ctx->dtls = dtls_new_context(ctx);
    if (NULL==ctx->dtls) {
        ERR("unable to allocate new dtl context");
        return -1;
    }

    return 0;
}
