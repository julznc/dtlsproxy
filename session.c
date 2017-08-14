
#include <string.h>
#include <unistd.h>

#include "session.h"
#include "proxy.h"
#include "utlist.h"
#include "utils.h"


#define COPY_ADDRESS(DST,SRC) do {                                 \
    (DST)->size = (SRC)->size;                                          \
    if ((SRC)->addr.sa.sa_family == AF_INET6) {                         \
      (DST)->addr.sin6.sin6_family = (SRC)->addr.sin6.sin6_family;      \
      (DST)->addr.sin6.sin6_addr = (SRC)->addr.sin6.sin6_addr;          \
      (DST)->addr.sin6.sin6_port = (SRC)->addr.sin6.sin6_port;          \
    } else {                                                            \
      (DST)->addr.st = (SRC)->addr.st;                                  \
    }                                                                   \
  } while (0);

session_context_t *new_session(struct proxy_context *ctx,
                               int sockfd, const address_t *remote)
{
    session_context_t *session = (session_context_t *)malloc(sizeof(session_context_t));
    if (NULL==session) {
        ERR("failed to allocate session_context");
        return NULL;
    }

    memset(session, 0, sizeof(session_context_t));
    dtls_session_init(&session->dtls_session);
    COPY_ADDRESS(&session->dtls_session, remote);
    session->dtls_session.ifindex = sockfd;

    LL_PREPEND(ctx->sessions, session);
    return session;
}

session_context_t *find_session(struct proxy_context *ctx,
                                int sockfd, const address_t *dst)
{
    session_context_t *session = NULL;

    LL_FOREACH(ctx->sessions, session) {
        if ((session->dtls_session.ifindex == sockfd) &&
            address_equals((address_t *)&session->dtls_session, dst)) {
            return session;
        }
    }

    return session;
}

void free_session(struct proxy_context *ctx,
                  session_context_t *session)
{
    if (ctx && session) {

        struct ev_loop *loop = ctx->loop;
        ev_io_stop(EV_A_ &session->backend_rd_watcher);

        if (session->client_fd > 0) {
            close(session->client_fd);
            session->client_fd = -1;
        }

        if (session->backend_fd > 0) {
            close(session->backend_fd);
            session->backend_fd = -1;
        }

        LL_DELETE(ctx->sessions, session);
        free(session);
    }
}

static void session_dispatch(EV_P_ ev_io *w, int revents)
{
    DBG("%s revents=%X", __func__, revents);
    address_t address;
    unsigned char packet[DTLS_MAX_BUF];
    size_t packet_len = 0;

    memset(&address, 0, sizeof(address_t));
    address.size = sizeof(address.addr);

    proxy_context_t *ctx = (proxy_context_t *)w->data;
    //session_context_t *sc = find_session(ctx, ctx->listen_fd, (address_t*)dtls_session);
    session_context_t *sc = ctx->sessions;
    while (NULL!=sc) {
        if (w->fd == sc->backend_fd) { // fix me
            break;
        }
        sc = sc->next;
    }
    if (NULL==sc) {
        ERR("session not found");
        return;
    }

    if ((w->fd == sc->backend_fd) && (revents & EV_READ)) {
        DBG("session_receive_from_backend");
        int res = recvfrom(w->fd, packet, sizeof(packet), 0,
                       &address.addr.sa, &address.size);
        if (res <= 0) {
            ERR("recv() failed");
            return;
        }
        packet_len = res;
        DBG("relay to client, len=%lu", packet_len);
        dumpbytes(packet, packet_len);
        dtls_write(ctx->dtls, &sc->dtls_session, packet, packet_len);
    }
}

static void listen_session_io(EV_P_ ev_io *w, int fd, proxy_context_t *ctx)
{
    DBG("%s", __func__);
    loop = ctx->loop;
    ev_io_init(w, session_dispatch, fd, EV_READ);
    w->data = ctx;
    ev_io_start(EV_A_ w);
}

void start_session(struct proxy_context *ctx, session_context_t *sc)
{
    DBG("%s", __func__);
    struct ev_loop *loop = ctx->loop;
    listen_session_io(EV_A_ &sc->backend_rd_watcher, sc->backend_fd, ctx);
}

