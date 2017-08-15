
#include <assert.h>
#include <errno.h>
#include <unistd.h>

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

    if (ctx->listen_fd <= 0) {
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


// todo:
int dtls_handle_read(struct dtls_context_t *dtls_ctx);

int proxy_run(proxy_context_t *ctx)
{
    assert(NULL!=ctx);

    ctx->running = 1;
    while (ctx->running) {
        fd_set rfds;
        FD_ZERO(&rfds);

        FD_SET(ctx->listen_fd, &rfds);

        struct timeval timeout;
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;

        int result = select( ctx->listen_fd+1, &rfds, NULL, NULL, &timeout);
        if (result < 0) {
            perror("select");
            ERR("select() failed: %s", strerror(errno));
        } else if (0 == result) {
            // timeout
        } else {
            if (FD_ISSET(ctx->listen_fd, &rfds)) {
                dtls_handle_read(ctx->dtls);
            }
        }
    }

    return 0;
}

void proxy_exit(proxy_context_t *ctx)
{
    assert(NULL!=ctx);

    if (ctx->running) {
        ctx->running = 0;
    }
}

void proxy_deinit(proxy_context_t *ctx)
{
    assert(NULL!=ctx);

    if (ctx->listen_fd > 0) {
        close (ctx->listen_fd);
        ctx->listen_fd = -1;
    }

    dtls_free_context(ctx->dtls);
    free_keystore(ctx->psk);
}
