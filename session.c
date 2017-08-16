
#include <assert.h>
#include <unistd.h>
#include <utlist.h>

#include "session.h"
#include "proxy.h"
#include "utils.h"

session_context_t *new_session(struct proxy_context *ctx,
                               const dtls_peer_t *peer)
{
    assert(ctx && peer && ctx->dtls);
    session_context_t *session = (session_context_t *)malloc(sizeof(session_context_t));
    if (NULL==session) {
        ERR("failed to allocate session_context");
        return NULL;
    }

    memset(session, 0, sizeof(session_context_t));
    memcpy(&session->peer, peer, sizeof(dtls_peer_t));
    session->dtls = ctx->dtls;

    session->client_fd = create_socket(&peer->session);
    if (session->client_fd <=0) {
        ERR("unable to create socket to client");
        free(session);
        return NULL;
    }

    if (0!=connect(session->client_fd,
                   &peer->session.addr.sa,
                   peer->session.size)) {
        ERR("connect to client failed");
        close(session->client_fd);
        return NULL;
    }

    session->backend_fd = create_socket(&ctx->backend_addr);
    if (session->backend_fd <=0) {
        ERR("unable to create socket to backend");
        close(session->client_fd);
        free(session);
        return NULL;
    }

    if (0!=connect(session->backend_fd,
                   &ctx->backend_addr.addr.sa,
                   ctx->backend_addr.size)) {
        ERR("connect to backend failed");
        close(session->client_fd);
        close(session->backend_fd);
        return NULL;
    }

    LL_PREPEND(ctx->sessions, session);
    return session;
}

void free_session(struct proxy_context *ctx,
                  session_context_t *session)
{
    if (ctx && session) {
        LL_DELETE(ctx->sessions, session);
        if (session->client_fd > 0) {
            close(session->client_fd);
        }
        if (session->backend_fd > 0) {
            close(session->backend_fd);
        }
        free(session);
    }
}

session_context_t *find_session(struct proxy_context *ctx,
                                const session_t *addr)
{
    assert(ctx && addr);
    session_context_t *session = NULL;

    LL_FOREACH(ctx->sessions, session) {
        if (dtls_session_equals(addr, &session->peer.session)) {
            return session;
        }
    }

    return session;
}

int
dtls_prepare_record(dtls_peer_t *peer, dtls_security_parameters_t *security,
            unsigned char type,
            uint8 *data_array[], size_t data_len_array[],
            size_t data_array_len,
            uint8 *sendbuf, size_t *rlen);

int send_client_data(dtls_context_t *dtls_ctx, dtls_peer_t *peer,
        dtls_security_parameters_t *security , session_t *addr,
        uint8 *buf_array[], size_t buf_len_array[], size_t buf_array_len)
{
    unsigned char sendbuf[DTLS_MAX_BUF];
    size_t len = sizeof(sendbuf);
    int res;
    unsigned int i;
    size_t overall_len = 0;

    res = dtls_prepare_record(peer, security, DTLS_CT_APPLICATION_DATA,
                              buf_array, buf_len_array, buf_array_len, sendbuf, &len);

    if (res < 0)
      return res;

    for (i = 0; i < buf_array_len; i++) {
      overall_len += buf_len_array[i];
    }

    proxy_context_t *ctx = (proxy_context_t *)dtls_ctx->app;
    session_context_t *sc = find_session(ctx, addr);
    //res = CALL(ctx, write, session, sendbuf, len);
    //DBG("%s session_context = %lx", __func__, (unsigned long)sc);
    if (NULL!=sc) {
        //res = sendto(sc->client_fd, sendbuf, len, MSG_DONTWAIT,
        //             &sc->peer.session.addr.sa, sc->peer.session.size);
                     //&addr->addr.sa, addr->size);
        res = sendto(ctx->listen_fd, sendbuf, len, MSG_DONTWAIT,
                     &sc->peer.session.addr.sa, sc->peer.session.size);
    }
    //DBG("%s res = %d", __func__, res);

    return res <= 0 ? res : overall_len - (len - res);
}

static int relay_to_client(struct dtls_context_t *dtls_ctx,
                           session_t *addr, uint8 *buf, size_t len)
{
    dtls_peer_t *peer = dtls_get_peer(dtls_ctx, addr);

    if (!peer) {
        int res;
        res = dtls_connect(dtls_ctx, addr);
        return (res >= 0) ? 0 : res;
    } else {
        if (peer->state != DTLS_STATE_CONNECTED) {
            return 0;
        } else {
            return send_client_data(dtls_ctx, peer, dtls_security_params(peer),
                                    &peer->session, &buf, &len, 1);
        }
    }
}

static void session_cb(EV_P_ ev_io *w, int revents)
{
    DBG("%s revents=%04X", __func__, revents);

    unsigned char packet[DTLS_MAX_BUF];
    size_t packet_len = 0;

    session_context_t *sc = (session_context_t *)w->data;
    if (w->fd == sc->backend_fd) {
        if (revents & EV_READ) {
            //DBG("receive from backend");
            int res = recv(w->fd, packet, sizeof(packet), 0);
            if (res <= 0) {
                ERR("recv() failed (res=%d)", res);
                return;
            }
            packet_len = res;
            //DBG("relay to client, len=%lu", packet_len);
            //dumpbytes(packet, packet_len);
            relay_to_client(sc->dtls, &sc->peer.session, packet, packet_len);
        }
    }
}

static void listen_session_io(EV_P_ ev_io *w,
                              proxy_context_t *ctx,
                              session_context_t *sc)
{
    DBG("%s fd=%d", __func__, sc->backend_fd);
    loop = ctx->loop;
    ev_io_init(w, session_cb, sc->backend_fd, EV_READ);
    w->data = sc;
    ev_io_start(EV_A_ w);
}

int start_session(struct proxy_context *ctx,
                  session_context_t *session)
{
    assert(ctx && session);
    DBG("%s", __func__);

    struct ev_loop *loop = ctx->loop;
    listen_session_io(EV_A_ &session->backend_rd_watcher, ctx, session);

    return 0;
}

void stop_session(struct proxy_context *ctx,
                  session_context_t *session)
{
    assert(ctx && session);
    DBG("%s", __func__);

    struct ev_loop *loop = ctx->loop;
    ev_io_stop(EV_A_ &session->backend_rd_watcher);
}

