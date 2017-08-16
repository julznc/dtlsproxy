
#include <assert.h>
#include <errno.h>
#include <unistd.h>

#include "proxy.h"
#include "utils.h"

#ifdef DTLS_PSK

static int get_psk_info(struct dtls_context_t *dtls_ctx,
                        const session_t *session, dtls_credentials_type_t type,
                        const unsigned char *id, size_t id_len,
                        unsigned char *result, size_t result_length)
{
    if (type != DTLS_PSK_KEY) {
        return 0;
    }

    proxy_context_t *ctx = (proxy_context_t *)dtls_get_app_data(dtls_ctx);
    if (id && ctx) {
        for (keystore_t *psk=ctx->psk; psk && psk->id; psk=psk->next) {
            //DBG("psk=%s\n", psk->id);
            if (id_len == psk->id_length && memcmp(id, psk->id, id_len) == 0) {
                if (result_length < psk->key_length) {
                    ERR("buffer too small for PSK");
                    return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
                }
                memcpy(result, psk->key, psk->key_length);
                return psk->key_length;
            }
        }
    }

    return dtls_alert_fatal_create(DTLS_ALERT_DECRYPT_ERROR);
}

#endif /* DTLS_PSK */

static int dtls_send_to_peer(struct dtls_context_t *dtls_ctx,
                             session_t *session, uint8 *data, size_t len)
{
    proxy_context_t *ctx = (proxy_context_t *)dtls_get_app_data(dtls_ctx);
    int fd = ctx->listen_fd;
    return sendto(fd, data, len, MSG_DONTWAIT,
                  &session->addr.sa, session->size);
}

static int dtls_read_from_peer(struct dtls_context_t *dtls_ctx,
                               session_t *dtls_session, uint8 *data, size_t len)
{
    proxy_context_t *ctx = (proxy_context_t *)dtls_get_app_data(dtls_ctx);
    //dtls_peer_t *peer = dtls_get_peer(dtls_ctx, dtls_session);

    //DBG("%s: peer=%lx", __func__, (unsigned long)peer);
    //dumpbytes(data, len);

#if 0 // echo
    return dtls_write(dtls_ctx, session, data, len);
#else
    session_context_t *sc = find_session(ctx, dtls_session);
    if (NULL!=sc) {
        //DBG("forward to backend=%d", sc->backend_fd);
        return send(sc->backend_fd, data, len, 0);
    }
    return -1;
#endif
}

static int dtls_event(struct dtls_context_t *dtls_ctx, session_t *dtls_session,
                      dtls_alert_level_t level, unsigned short code)
{
    proxy_context_t *ctx = (proxy_context_t *)dtls_get_app_data(dtls_ctx);
    dtls_peer_t *peer = dtls_get_peer(dtls_ctx, dtls_session);
    session_context_t *sc = NULL;

    DBG("%s: peer=%lx", __func__, (unsigned long)peer);

    switch (code)
    {
    case DTLS_ALERT_CLOSE_NOTIFY:
        DBG("%s: close notify", __func__);
        sc = find_session(ctx, dtls_session);
        if (NULL!=sc) {
            DBG("delete session %lx", (unsigned long)sc);
            stop_session(ctx, sc);
            free_session(ctx, sc);
        }
        break;
    case DTLS_EVENT_CONNECT:
        DBG("%s: connect", __func__);
        break;
    case DTLS_EVENT_CONNECTED:
        sc = new_session(ctx, peer);
        if (NULL==sc) {
            return -1;
        }
        DBG("%s: connected session %lx", __func__, (unsigned long)sc);
        if (0 != start_session(ctx, sc)) {
            free_session(ctx, sc);
            return -1;
        }
        return 0;
    case DTLS_EVENT_RENEGOTIATE:
        DBG("%s: renegotiate", __func__);
        break;
    default:
        DBG("%s: unknown event=%u (alert=%d)", __func__, code, level);
        break;
    }
    return 0;
}

static int dtls_handle_read(struct dtls_context_t *dtls_ctx)
{
    proxy_context_t *ctx = (proxy_context_t *)dtls_get_app_data(dtls_ctx);

    session_t session;
    static uint8 buf[DTLS_MAX_BUF];
    int len;

    memset(&session, 0, sizeof(session_t));
    session.size = sizeof(session.addr);
    len = recvfrom(ctx->listen_fd, buf, sizeof(buf), MSG_TRUNC,
                   &session.addr.sa, &session.size);

    if (len < 0) {
        perror("recvfrom");
        return -1;
    } else {
        //DBG("got %d bytes from port %u", len, ntohs(session.addr.sin6.sin6_port));
        if (sizeof(buf) < len) {
            ERR("packet was truncated (%lu bytes lost)", len - sizeof(buf));
        }
    }

    return dtls_handle_message(dtls_ctx, &session, buf, len);
}

static dtls_handler_t cb = {
    .write = dtls_send_to_peer,
    .read  = dtls_read_from_peer,
    .event = dtls_event,
#ifdef DTLS_PSK
    .get_psk_info = get_psk_info,
#endif
#ifdef DTLS_ECC
    .get_ecdsa_key = NULL,
    .verify_ecdsa_key = NULL
#endif
};

// returns non-zero on error
int proxy_init(proxy_context_t *ctx,
               proxy_option_t *opt,
               char *psk_buf)
{
    assert (ctx && opt && psk_buf);

    ctx->option = opt;

    ctx->psk = new_keystore(psk_buf);
    if (NULL==ctx->psk) {
        return -1;
    }

    if (resolve_address(ctx->option->listen.host,
                        ctx->option->listen.port,
                        &ctx->option->listen.addr) < 0) {
        ERR("cannot resolve listen address");
        return -1;
    }

    if (resolve_address(ctx->option->backend.host,
                        ctx->option->backend.port,
                        &ctx->option->backend.addr) < 0) {
        ERR("cannot resolve backend address");
        return -1;
    }

    /* init socket and set it to non-blocking */
    ctx->listen_fd = create_socket(&ctx->option->listen.addr);

    if (ctx->listen_fd <= 0) {
        ERR("socket: %s", strerror(errno));
        return -1;
    }

    if (bind(ctx->listen_fd, (struct sockaddr*)&ctx->option->listen.addr.addr,
             sizeof(ctx->option->listen.addr.addr)) < 0) {
        ERR("bind: %s", strerror(errno));
        return -1;
    }

    dtls_init();

    ctx->dtls = dtls_new_context(ctx);
    if (NULL==ctx->dtls) {
        ERR("unable to allocate new dtl context");
        return -1;
    }

    dtls_set_handler(ctx->dtls, &cb);

    return 0;
}

static void proxy_cb(EV_P_ ev_io *w, int revents)
{
    DBG("%s revents=%04X", __func__, revents);
    proxy_context_t *ctx = (proxy_context_t *)w->data;
    dtls_handle_read(ctx->dtls);
}

static void start_listen_io(EV_P_ ev_io *w, proxy_context_t *ctx)
{
    DBG("%s fd=%d", __func__, ctx->listen_fd);
    loop = ctx->loop;
    ev_io_init(w, proxy_cb, ctx->listen_fd, EV_READ);
    w->data = ctx;
    ev_io_start(EV_A_ w);
}

int proxy_run(proxy_context_t *ctx)
{
    assert(NULL!=ctx);

    struct ev_loop *loop = ev_default_loop(0);
    ctx->loop = loop;
    start_listen_io(EV_A_ &ctx->watcher, ctx);

    return ev_run(EV_A_ 0);
}

void proxy_exit(proxy_context_t *ctx)
{
    assert(NULL!=ctx);

    struct ev_loop *loop = ctx->loop;

    session_context_t *sc = ctx->sessions;
    while(sc) {
        stop_session(ctx, sc);
        sc = sc->next;
    }
    ev_io_stop(EV_A_ &ctx->watcher);

    //DBG("call libev break()");
    ev_break(EV_A_ EVBREAK_ALL);
}

void proxy_deinit(proxy_context_t *ctx)
{
    assert(NULL!=ctx);

    if (ctx->listen_fd > 0) {
        close (ctx->listen_fd);
        ctx->listen_fd = -1;
    }

    while(ctx->sessions) {
        DBG("delete session %lx", (unsigned long)ctx->sessions);
        free_session(ctx, ctx->sessions);
    }

    dtls_free_context(ctx->dtls);
    free_keystore(ctx->psk);
}
