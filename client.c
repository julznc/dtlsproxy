
#include <assert.h>
#include <unistd.h>
#include <utlist.h>

#include "client.h"
#include "proxy.h"
#include "utils.h"

client_context_t *new_client(struct proxy_context *ctx,
                             const session_t *addr)
{
    assert(ctx && addr);
    client_context_t *client = (client_context_t *)malloc(sizeof(client_context_t));
    if (NULL==client) {
        ERR("failed to allocate client_context");
        return NULL;
    }

    memset(client, 0, sizeof(client_context_t));
    memcpy(&client->address, addr, sizeof(session_t));
    client->dtls = ctx->dtls;

    backend_context_t *backend = next_backend(ctx);
    if (NULL==backend) {
        ERR("no available backend");
        free(client);
        return NULL;
    }

    client->client_fd = create_socket(addr);
    if (client->client_fd <=0) {
        ERR("unable to create socket to client");
        free(client);
        return NULL;
    }

    if (0!=bind(client->client_fd,
                   &ctx->listen.addr.addr.sa,
                   ctx->listen.addr.size)) {
        ERR("bind client failed");
        close(client->client_fd);
        return NULL;
    }

    if (0!=connect(client->client_fd,
                   &addr->addr.sa,
                   addr->size)) {
        ERR("connect to client failed");
        close(client->client_fd);
        return NULL;
    }

    client->backend_fd = create_socket(&backend->address);
    if (client->backend_fd <=0) {
        ERR("unable to create socket to backend");
        close(client->client_fd);
        free(client);
        return NULL;
    }

    if (0!=connect(client->backend_fd,
                   &backend->address.addr.sa,
                   backend->address.size)) {
        ERR("connect to backend failed");
        close(client->client_fd);
        close(client->backend_fd);
        free(client);
        return NULL;
    }

    client->index = ctx->clients.index++;
    DBG("client %u linked to backend %u",
        client->index,
        backend->address.ifindex);

    LL_PREPEND(ctx->clients.client, client);
    ctx->clients.count++;
    return client;
}

void free_client(struct proxy_context *ctx,
                 client_context_t *client)
{
    if (ctx && client) {
        LL_DELETE(ctx->clients.client, client);
        if (client->client_fd > 0) {
            close(client->client_fd);
        }
        if (client->backend_fd > 0) {
            close(client->backend_fd);
        }
        ctx->clients.count--;
        free(client);
    }
}

client_context_t *find_client(struct proxy_context *ctx,
                              const session_t *addr)
{
    assert(ctx && addr);
    client_context_t *client = NULL;

    LL_FOREACH(ctx->clients.client, client) {
        if (dtls_session_equals(addr, &client->address)) {
            return client;
        }
    }

    return client;
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

static int relay_to_client(client_context_t *client, uint8 *buf, size_t buf_len)
{
    dtls_peer_t *peer = dtls_get_peer(client->dtls, &client->address);

    if (!peer) {
        return dtls_connect(client->dtls, &client->address);
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

    return sendto(client->client_fd, sendbuf, len, MSG_DONTWAIT,
                  &client->address.addr.sa, client->address.size);
}

static void client_cb(EV_P_ ev_io *w, int revents)
{
    //DBG("%s revents=%04X", __func__, revents);
    client_context_t *client = (client_context_t *)w->data;

    session_t session;
    static uint8 buf[DTLS_MAX_BUF];
    int len;

    memset(&session, 0, sizeof(session_t));
    session.size = sizeof(session.addr);
    len = recvfrom(client->client_fd, buf, sizeof(buf), MSG_TRUNC,
                   &session.addr.sa, &session.size);

    if (len < 0) {
        perror("client recvfrom");
        return;
    } else {
        //DBG("got %d bytes from port %u", len, ntohs(session.addr.sin6.sin6_port));
        if (sizeof(buf) < len) {
            ERR("packet was truncated (%lu bytes lost)", len - sizeof(buf));
        }
    }

    dtls_handle_message(client->dtls, &session, buf, len);
}

static void backend_cb(EV_P_ ev_io *w, int revents)
{
    //DBG("%s revents=%04X", __func__, revents);

    unsigned char packet[DTLS_MAX_BUF];
    size_t packet_len = 0;

    client_context_t *sc = (client_context_t *)w->data;
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

void start_client_watcher(EV_P_ ev_io *w,
                          proxy_context_t *ctx,
                          client_context_t *sc)
{
    DBG("client %u client fd=%d", sc->index, sc->client_fd);
    loop = ctx->loop;
    ev_io_init(w, client_cb, sc->client_fd, EV_READ);
    w->data = sc;
    ev_io_start(EV_A_ w);
}

static void start_backend_watcher(EV_P_ ev_io *w,
                                  proxy_context_t *ctx,
                                  client_context_t *sc)
{
    DBG("client %u backend fd=%d", sc->index, sc->backend_fd);
    loop = ctx->loop;
    ev_io_init(w, backend_cb, sc->backend_fd, EV_READ);
    w->data = sc;
    ev_io_start(EV_A_ w);
}

int start_client(struct proxy_context *ctx,
                 client_context_t *client)
{
    assert(ctx && client);
    //DBG("%s", __func__);

    struct ev_loop *loop = ctx->loop;
    start_client_watcher(EV_A_ &client->client_rd_watcher, ctx, client);
    start_backend_watcher(EV_A_ &client->backend_rd_watcher, ctx, client);

    return 0;
}

void stop_client(struct proxy_context *ctx,
                 client_context_t *client)
{
    assert(ctx && client);
    //DBG("%s", __func__);

    struct ev_loop *loop = ctx->loop;
    ev_io_stop(EV_A_ &client->client_rd_watcher);
    ev_io_stop(EV_A_ &client->backend_rd_watcher);
}

