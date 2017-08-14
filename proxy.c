
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>

#include "utlist.h"
#include "proxy.h"
#include "utils.h"

static struct ev_loop *loop = NULL;

static int connect_to_new_client(const address_t *client, const address_t *local)
{
    int fd = create_socket(client, local);
    if (fd < 0) {
        ERR("client socket() failed");
        return -1;
    }

    int err = connect(fd, &client->addr.sa, client->size);
    if (0!=err) {
        ERR("connect client failed");
        close(fd);
        return -1;
    }

    DBG("%s: fd=%d", __func__, fd);
    return fd;
}

static int connect_to_backend(const proxy_context_t *ctx)
{

    address_t backend;
    memset(&backend, 0, sizeof(backend));

    int len = resolve_address(ctx->options->backend_host, ctx->options->backend_port, &backend);
    if (len < 1) {
        ERR("unable to resolve backend address");
        return -1;
    }
#if 0
    int fd = create_socket(&backend, &backend);
    if (fd < 0) {
        ERR("backend socket() failed");
        return -1;
    }
#else
    int fd = socket(backend.addr.sa.sa_family, SOCK_DGRAM, 0);
    if (fd < 0) {
        ERR("failed to create socket");
        return -1;
    }

    if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
        ERR("set nonblock failed: %s", strerror(errno));
        close (fd);
        return -1;
    }
#endif
    int err = connect(fd, &backend.addr.sa, backend.size);
    if (0!=err) {
        ERR("connect backend failed");
        close(fd);
        return -1;
    }

    DBG("%s: fd=%d", __func__, fd);
    return fd;
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
        if (w->fd == sc->backend_fd) {
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

static void listen_session_io(EV_P_ ev_io *w, int fd, void *d)
{
    DBG("%s", __func__);
    ev_io_init(w, session_dispatch, fd, EV_READ);
    w->data = d;
    ev_io_start(EV_A_ w);
}

void start_session(session_context_t *sc, proxy_context_t *ctx)
{
    DBG("%s", __func__);
    listen_session_io(EV_A_ &sc->backend_rd_watcher, sc->backend_fd, ctx);
}

static int dtls_send_to_peer(struct dtls_context_t *dtls_ctx,
                             session_t *dtls_session, uint8 *data, size_t len)
{
    //DBG("%s: len=%lu", __func__, len);
    proxy_context_t *ctx = (proxy_context_t *)dtls_get_app_data(dtls_ctx);

    //dumpbytes(data, len);
    return sendto(ctx->listen_fd, data, len, MSG_DONTWAIT,
                  &dtls_session->addr.sa, dtls_session->size);
}

static int dtls_read_from_peer(struct dtls_context_t *dtls_ctx,
                          session_t *dtls_session, uint8 *data, size_t len)
{

    proxy_context_t *ctx = (proxy_context_t *)dtls_get_app_data(dtls_ctx);
    session_context_t *sc = find_session(ctx, ctx->listen_fd, (address_t*)dtls_session);
    DBG("%s: session_context=%lx", __func__, (unsigned long)sc);
    if (sc) {
        DBG("forward to fd=%d", sc->backend_fd);
        dumpbytes(data, len);
        //return sendto(sc->backend_fd, data, len, MSG_DONTWAIT,
        //              &dtls_session->addr.sa, dtls_session->size);
        //return sendto(sc->backend_fd, data, len, 0,
        //              &ctx->listen_addr.addr.sa, ctx->listen_addr.size);
        //dumpbytes(&dtls_session->addr.sa, dtls_session->size);
        //dumpbytes(&ctx->listen_addr.addr.sa,  ctx->listen_addr.size);
        return send(sc->backend_fd, data, len, 0);
    }
    return 0;
}

static int dtls_event(struct dtls_context_t *dtls_ctx, session_t *dtls_session,
                      dtls_alert_level_t level, unsigned short code)
{
    //DBG("%s: alert=%d, code=%u", __func__, level, code);

    proxy_context_t *ctx = (proxy_context_t *)dtls_get_app_data(dtls_ctx);
    session_context_t *sc = find_session(ctx, ctx->listen_fd, (address_t*)dtls_session);

    switch (code)
    {
    case DTLS_EVENT_CONNECT:
        DBG("%s: connect", __func__);
        break;
    case DTLS_EVENT_CONNECTED:
        if (NULL==sc) {
            sc = new_session(ctx, ctx->listen_fd, (address_t*)dtls_session);
            if (NULL==sc) {
                ERR("cannot allocate new session");
                return -1;
            }
            sc->client_fd = connect_to_new_client((address_t*)dtls_session, &ctx->listen_addr);
            if (sc->client_fd <= 0) {
                free_session(ctx, sc);
                return -1;
            }
            sc->backend_fd = connect_to_backend(ctx);
            if (sc->backend_fd <= 0) {
                free_session(ctx, sc);
                return -1;
            }
            start_session(sc, ctx);
        }
        DBG("%s: connected session=%lX", __func__, (unsigned long)sc);
        return 0;
    case DTLS_EVENT_RENEGOTIATE:
        DBG("%s: renegotiate", __func__);
        break;
    default:
        DBG("%s: unknown event=%u (alert=%d)", __func__, code, level);
        if ((DTLS_ALERT_LEVEL_FATAL==level) && (NULL!=sc)) {
            //free_session(ctx, sc);
            //return -1;
        }
        break;
    }

    return 0;
}

static int get_psk_info(struct dtls_context_t *dtls_ctx, const session_t *session,
                        dtls_credentials_type_t type, const unsigned char *id, size_t id_len,
                        unsigned char *result, size_t result_length)
{
    proxy_context_t *ctx = (proxy_context_t *)dtls_get_app_data(dtls_ctx);
    keystore_item_t *psk;
    ssize_t length;

    //DBG("%s: type=%d", __func__, type);
    switch(type)
    {
    case DTLS_PSK_HINT:
        //DBG("type=HINT");
        return 0;
    case DTLS_PSK_IDENTITY:
        //DBG("type=IDENTITY, id=%s", id);
        if (id_len) {
            DBG("got psk_identity_hint: '%.*s'", (int)id_len, id);
        }

        psk = keystore_find_psk(ctx->keystore, id, id_len, NULL, 0);
        if (!psk) {
            ERR("no PSK identity");
            return dtls_alert_fatal_create(DTLS_ALERT_CLOSE_NOTIFY);
        }

        length = psk_set_identity(psk, result, result_length);
        if (length < 0) {
            ERR("cannot set psk_identity -- buffer too small");
            return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
        }
        return length;
    case DTLS_PSK_KEY:
        //DBG("type=KEY");
        psk = keystore_find_psk(ctx->keystore, NULL, 0, id, id_len);
        if (!psk) {
            ERR("PSK for unknown id requested");
            return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
        }

        length = psk_set_key(psk, result, result_length);
        if (length < 0) {
            ERR("cannot set psk -- buffer too small");
            return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
        }
        //DBG("psk = '%s'", (char*)psk->entry.psk.key);
        return length;
    }
    return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
}

static dtls_handler_t dtls_cb = {
  .write = dtls_send_to_peer,
  .read  = dtls_read_from_peer,
  .event = dtls_event,
  .get_psk_info = get_psk_info,
#ifdef DTLS_ECC
  .get_ecdsa_key = NULL,
  .verify_ecdsa_key = NULL
#endif /* DTLS_ECC */
};

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

    memset(&ctx->listen_addr, 0, sizeof(address_t));
    int len = resolve_address(ctx->options->listen_host,
                              ctx->options->listen_port,
                              &ctx->listen_addr);
    if (len < 1) {
        ERR("failed to resolve listen host");
        return -1;
    }

    ctx->listen_fd = create_socket(&ctx->listen_addr, &ctx->listen_addr);
    if (ctx->listen_fd < 0) {
        ERR("failed to create listen socket");
        return -1;
    }

    dtls_init();
    ctx->dtls = dtls_new_context(ctx);
    if(NULL == ctx->dtls) {
        ERR("failed to create dtls context");
        return -1;
    }

    ctx->keystore = new_keystore();
    keystore_item_t *item = keystore_new_psk(NULL, 0, psk->id, strlen(psk->id),
                                             psk->key, strlen(psk->key), 0);
    if ((NULL==ctx->keystore) || (NULL==item)) {
        ERR("failed to create psk keystore");
        return -1;
    }

    keystore_store_item(ctx->keystore, item);
    dtls_set_handler(ctx->dtls, &dtls_cb);

    return 0;
}

static void proxy_cb(EV_P_ ev_io *w, int revents)
{
    //DBG("%s revents=%X", __func__, revents);
    proxy_context_t *ctx = (proxy_context_t *)w->data;
    static int count = 0;

    DBG("%s fds: %d,%d revents: 0x%02x count: %d",
        __func__, w->fd, ctx->listen_fd, revents, count);
    count++;

    session_t local;
    memset(&local, 0, sizeof(session_t));
    local.size = sizeof(local.addr);
    int ret = getsockname(ctx->listen_fd, &local.addr.sa, &local.size);
    if (ret < 0) {
        ERR("getsockname()=%d errno=%d", ret, errno);
        return;
    }

    session_t client;
    unsigned char packet[DTLS_MAX_BUF];
    size_t packet_len = 0;

    memset(&client, 0, sizeof(session_t));
    client.size = sizeof(client.addr);
    ret = recvfrom(ctx->listen_fd, packet, sizeof(packet), 0,
                   &client.addr.sa, &client.size);
    if (ret < 0) {
        ERR("recvfrom() failed, errno = %d", errno);
        return;
    } else if (0 == ret) {
        ERR("recvfrom() returned 0");
        //continue;
        return;
    }

    packet_len = ret;

    //handle_message(ctx, (address_t*)&client, packet, packet_len);
    dtls_handle_message(ctx->dtls, &client, packet, packet_len);
}

static void start_listen_io(EV_P_ ev_io *w, proxy_context_t *ctx)
{
    DBG("%s fd=%d", __func__, ctx->listen_fd);
    ev_io_init(w, proxy_cb, ctx->listen_fd, EV_READ);
    w->data = ctx;
    ev_io_start(EV_A_ w);
}

int proxy_run(proxy_context_t *ctx)
{
    DBG("%s", __func__);

    loop = ev_default_loop(0);
    start_listen_io(EV_A_ &ctx->watcher, ctx);

    //DBG("call libev run()");
    ev_run(EV_A_ 0);

    return 0;
}

void proxy_exit(proxy_context_t *ctx)
{
    DBG("%s", __func__);

    session_context_t *sc = ctx->sessions;
    while(sc) {
        ev_io_stop(EV_A_ &sc->backend_rd_watcher);
        sc = sc->next;
    }

    ev_io_stop(EV_A_ &ctx->watcher);

    //DBG("call libev break()");
    ev_break(EV_A_ EVBREAK_ALL);
}

void proxy_deinit(proxy_context_t *ctx)
{
    DBG("%s", __func__);
    assert(NULL!=ctx);

    while(ctx->sessions) {
        free_session(ctx, ctx->sessions);
    }

    if(NULL != ctx->dtls) {
        dtls_free_context(ctx->dtls);
        ctx->dtls = NULL;
    }

    if(NULL != ctx->keystore) {
        free_keystore(ctx->keystore);
        ctx->keystore = NULL;
    }

    if(ctx->listen_fd > 0) {
        close(ctx->listen_fd);
        ctx->listen_fd = 0;
    }
}
