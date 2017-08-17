
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

    backend_context_t *backend = next_backend(ctx);
    if (NULL==backend) {
        ERR("no available backend");
        free(session);
        return NULL;
    }

    session->client_fd = create_socket(&peer->session);
    if (session->client_fd <=0) {
        ERR("unable to create socket to client");
        free(session);
        return NULL;
    }

    if (0!=bind(session->client_fd,
                   &ctx->listen.addr.addr.sa,
                   ctx->listen.addr.size)) {
        ERR("bind client failed");
        close(session->client_fd);
        return NULL;
    }

    if (0!=connect(session->client_fd,
                   &peer->session.addr.sa,
                   peer->session.size)) {
        ERR("connect to client failed");
        close(session->client_fd);
        return NULL;
    }

    session->backend_fd = create_socket(&backend->address);
    if (session->backend_fd <=0) {
        ERR("unable to create socket to backend");
        close(session->client_fd);
        free(session);
        return NULL;
    }

    if (0!=connect(session->backend_fd,
                   &backend->address.addr.sa,
                   backend->address.size)) {
        ERR("connect to backend failed");
        close(session->client_fd);
        close(session->backend_fd);
        return NULL;
    }

    DBG("linked to backend %u", backend->address.ifindex);
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

/* copied form tinydtls' dtls_set_record_header() */
static inline uint8 *set_data_header(dtls_security_parameters_t *security, uint8 *buf)
{
    if (NULL==security) {
        return NULL;
    }

    dtls_int_to_uint8(buf, DTLS_CT_APPLICATION_DATA);
    buf += sizeof(uint8);

    dtls_int_to_uint16(buf, DTLS_VERSION);
    buf += sizeof(uint16);

    dtls_int_to_uint16(buf, security->epoch);
    buf += sizeof(uint16);

    dtls_int_to_uint48(buf, security->rseq);
    buf += sizeof(uint48);

    /* increment record sequence counter by 1 */
    security->rseq++;

    memset(buf, 0, sizeof(uint16));
    return buf + sizeof(uint16);
}

/* copied form tinydtls' dtls_prepare_record() */
static int prepare_data_record(dtls_peer_t *peer, uint8 *data, size_t data_len,
                               uint8 *sendbuf, size_t *rlen)
{
    dtls_security_parameters_t *security = dtls_security_params(peer);

  #define DTLS_RH_LENGTH sizeof(dtls_record_header_t)
  #define DTLS_RECORD_HEADER(M) ((dtls_record_header_t *)(M))

    if (*rlen < DTLS_RH_LENGTH) {
        ERR("The sendbuf (%zu bytes) is too small", *rlen);
        return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
    }

    if (!security || security->cipher == TLS_NULL_WITH_NULL_NULL) {
        return -1; // not supported
    }

    uint8 *p = set_data_header(security, sendbuf);
    uint8 *start = p;

    // TLS_PSK_WITH_AES_128_CCM_8 or TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8
  #define A_DATA_LEN 13
    unsigned char nonce[DTLS_CCM_BLOCKSIZE];
    unsigned char A_DATA[A_DATA_LEN];

    memcpy(p, &DTLS_RECORD_HEADER(sendbuf)->epoch, 8);
    p += 8;
    int res = 8;

    // check the minimum that we need for packets that are not encrypted
    if (*rlen < res + DTLS_RH_LENGTH + data_len) {
        ERR("%s: send buffer too small", __func__);
        return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
    }

    memcpy(p, data, data_len);
  //p += data_len;
    res += data_len;

    memset(nonce, 0, DTLS_CCM_BLOCKSIZE);
    memcpy(nonce, dtls_kb_local_iv(security, peer->role), dtls_kb_iv_size(security, peer->role));
    memcpy(nonce + dtls_kb_iv_size(security, peer->role), start, 8); // epoch + seq_num


    memcpy(A_DATA, &DTLS_RECORD_HEADER(sendbuf)->epoch, 8); /* epoch and seq_num */
    memcpy(A_DATA + 8,  &DTLS_RECORD_HEADER(sendbuf)->content_type, 3); // type and version
    dtls_int_to_uint16(A_DATA + 11, res - 8); // length

    res = dtls_encrypt(start + 8, res - 8, start + 8, nonce,
                       dtls_kb_local_write_key(security, peer->role),
                       dtls_kb_key_size(security, peer->role),
                       A_DATA, A_DATA_LEN);

    if (res < 0) {
        ERR("dtls_encrypt()=%d failed", res);
        return res;
    }

    res += 8;   // increment res by size of nonce_explicit

    // fix length of fragment in sendbuf
    dtls_int_to_uint16(sendbuf + 11, res);

    *rlen = DTLS_RH_LENGTH + res;
    return 0;
}

static int relay_to_client(session_context_t *session, uint8 *buf, size_t buf_len)
{
    dtls_peer_t *peer = dtls_get_peer(session->dtls, &session->peer.session);

    if (!peer) {
        return dtls_connect(session->dtls, &session->peer.session);
    }

    if (peer->state != DTLS_STATE_CONNECTED) {
        return 0;
    }

    unsigned char sendbuf[DTLS_MAX_BUF];
    size_t len = sizeof(sendbuf);

    int res = prepare_data_record(peer, buf, buf_len, sendbuf, &len);

    if (res < 0) {
        ERR("prepare_data_record()=%d failed", res);
        return res;
    }

    //DBG("message (len=%zu):", buf_len);
    //dumpbytes(buf, buf_len);
    //DBG("encrypted (len=%zu):", len);
    //dumpbytes(sendbuf, len);

    return sendto(session->client_fd, sendbuf, len, MSG_DONTWAIT,
                  &session->peer.session.addr.sa, session->peer.session.size);
}

static void session_cb(EV_P_ ev_io *w, int revents)
{
    //DBG("%s revents=%04X", __func__, revents);

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
            relay_to_client(sc, packet, packet_len);
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

