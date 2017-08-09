
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "tinydtls.h"
#include "dtls.h"

#include "proxy.h"
#include "utils.h"

static int resolve_address(const char *host, const char *port, struct sockaddr *dst)
{
    struct addrinfo *res, *ainfo;
    struct addrinfo hints;

    memset ((char *)&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_family = AF_UNSPEC;

    int error = getaddrinfo(host, port, &hints, &res);

    if (error != 0) {
        DBG("getaddrinfo: %s", gai_strerror(error));
        return error;
    }

    int len = -1;
    for (ainfo = res; ainfo != NULL; ainfo = ainfo->ai_next) {
        switch (ainfo->ai_family) {
        case AF_INET:
        // fall through
        case AF_INET6:
            len = ainfo->ai_addrlen;
            memcpy(dst, ainfo->ai_addr, len);
        }
        if (len > 0) break;
    }

    freeaddrinfo(res);
    return len;
}

int proxy_init(proxy_context_t *ctx,
               const proxy_option_t *opt,
               const proxy_psk_t *psk)
{
    DBG("%s", __func__);
    assert(NULL!=ctx);

    memset(ctx, 0, sizeof(proxy_context_t));
    ctx->options = opt;

    DBG("backend = %s:%s", ctx->options->backend_host, ctx->options->backend_port);
    DBG("listen = %s:%s", ctx->options->listen_host, ctx->options->listen_port);
    DBG("psk = %s:%s", psk->id, psk->key);

    struct sockaddr_in6 listen_addr;
    memset(&listen_addr, 0, sizeof(struct sockaddr_in6));

    if (resolve_address(opt->listen_host, opt->listen_port,
                        (struct sockaddr *)&listen_addr) < 0) {
        ERR("failed to resolve listen address");
        return -1;
    }

    ctx->listen_fd = socket(listen_addr.sin6_family, SOCK_DGRAM, 0);

    if (ctx->listen_fd <= 0) {
        ERR("socket: %s", strerror(errno));
        return -1;
    }

    if (fcntl(ctx->listen_fd, F_SETFL, O_NONBLOCK) < 0) {
        ERR("socket: %s", strerror(errno));
        return -1;
    }

    int on = 1;
    if (setsockopt(ctx->listen_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on) ) < 0) {
        ERR("setsockopt SO_REUSEADDR: %s", strerror(errno));
    }

    on = 1;
  #ifdef IPV6_RECVPKTINFO
    if (setsockopt(ctx->listen_fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on) ) < 0) {
  #else /* IPV6_RECVPKTINFO */
    if (setsockopt(ctx->listen_fd, IPPROTO_IPV6, IPV6_PKTINFO, &on, sizeof(on) ) < 0) {
  #endif /* IPV6_RECVPKTINFO */
      ERR("setsockopt IPV6_PKTINFO: %s", strerror(errno));
    }

    return 0;
}

void proxy_deinit(proxy_context_t *ctx)
{
    DBG("%s", __func__);
    assert(NULL!=ctx);
    if (ctx->listen_fd > 0) {
        close(ctx->listen_fd);
        ctx->listen_fd = 0;
    }
}
