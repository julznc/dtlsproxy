

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <signal.h>

#include "proxy.h"
#include "utils.h"

#ifdef DTLS_PSK

/* This function is the "key store" for tinyDTLS. It is called to
 * retrieve a key for the given identity within this particular
 * session. */
static int
get_psk_info(struct dtls_context_t *dtls_ctx, const session_t *session,
             dtls_credentials_type_t type,
             const unsigned char *id, size_t id_len,
             unsigned char *result, size_t result_length) {

  proxy_context_t *ctx = (proxy_context_t *)dtls_get_app_data(dtls_ctx);

  if (type != DTLS_PSK_KEY) {
    return 0;
  }

  if (id) {
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

static int
read_from_peer(struct dtls_context_t *dtls_ctx,
               session_t *session, uint8 *data, size_t len) {
  dumpbytes(data, len);
  return dtls_write(dtls_ctx, session, data, len);
}

static int
send_to_peer(struct dtls_context_t *dtls_ctx,
             session_t *session, uint8 *data, size_t len) {
  proxy_context_t *ctx = (proxy_context_t *)dtls_get_app_data(dtls_ctx);
  int fd = ctx->listen_fd;
  return sendto(fd, data, len, MSG_DONTWAIT,
                &session->addr.sa, session->size);
}

static int
dtls_handle_read(struct dtls_context_t *dtls_ctx) {
  proxy_context_t *ctx = (proxy_context_t *)dtls_get_app_data(dtls_ctx);
  int fd = ctx->listen_fd;
  session_t session;
  static uint8 buf[DTLS_MAX_BUF];
  int len;

  memset(&session, 0, sizeof(session_t));
  session.size = sizeof(session.addr);
  len = recvfrom(fd, buf, sizeof(buf), MSG_TRUNC,
                 &session.addr.sa, &session.size);

  if (len < 0) {
    perror("recvfrom");
    return -1;
  } else {
    DBG("got %d bytes from port %u", len,
             ntohs(session.addr.sin6.sin6_port));
    if (sizeof(buf) < len) {
      ERR("packet was truncated (%lu bytes lost)", len - sizeof(buf));
    }
  }

  return dtls_handle_message(dtls_ctx, &session, buf, len);
}

static void usage(const char *program) {
  const char *p = strrchr( program, '/' );
  if ( p )
    program = ++p;

  printf("DTLS server (c) 2017 yus\n\n"
         "usage: %s [-l listen host:port] [-i psk]\n"
         "\t-l listen address\t\tlisten on specified host and port\n"
         "\t-i num\t\tpsk identities\n", program);
  exit(1);
}

static dtls_handler_t cb = {
  .write = send_to_peer,
  .read  = read_from_peer,
  .event = NULL,
#ifdef DTLS_PSK
  .get_psk_info = get_psk_info,
#endif /* DTLS_PSK */
#ifdef DTLS_ECC
  .get_ecdsa_key = NULL,
  .verify_ecdsa_key = NULL
#endif /* DTLS_ECC */
};

int
main(int argc, char **argv) {

  proxy_context_t context;
  char psk_buf[1024];
  memset(&context, 0, sizeof(proxy_context_t));
  memset(psk_buf, 0, sizeof(psk_buf));

  int opt;
  while ((opt = getopt(argc, argv, "l:i:")) != -1) {
    char *sep = NULL;
    switch (opt) {
    case 'l' :
      sep = strrchr(optarg, ':');
      if (!sep) {
        usage(argv[0]);
      }
      *sep = '\0';
      if (resolve_address(optarg, sep+1, &context.listen_addr) < 0) {
        ERR("cannot resolve address");
        exit(-1);
      }
      break;
    case 'i' :
      strncpy(psk_buf, optarg, sizeof(psk_buf)-1);
      context.psk = new_keystore(psk_buf);
      if (NULL==context.psk) {
        exit(1);
      }
      break;
    default:
      usage(argv[0]);
    }
  }

  /* init socket and set it to non-blocking */
  int fd = create_socket(&context.listen_addr);

  if (fd < 0) {
    ERR("socket: %s", strerror(errno));
    return 0;
  }

  if (bind(fd, (struct sockaddr*)&context.listen_addr.addr, sizeof(context.listen_addr.addr)) < 0) {
    ERR("bind: %s", strerror(errno));
    goto error;
  }

  context.listen_fd = fd;

  dtls_init();

  context.dtls = dtls_new_context(&context);

  dtls_set_handler(context.dtls, &cb);

  while (1) {
    fd_set rfds, wfds;
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);

    FD_SET(fd, &rfds);
    /* FD_SET(fd, &wfds); */

    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    int result = select( fd+1, &rfds, &wfds, 0, &timeout);

    if (result < 0) {                /* error */
      if (errno != EINTR)
        perror("select");
    } else if (result == 0) {        /* timeout */
    } else {                        /* ok */
      if (FD_ISSET(fd, &wfds))
        ;
      else if (FD_ISSET(fd, &rfds)) {
        dtls_handle_read(context.dtls);
      }
    }
  }

 error:
  dtls_free_context(context.dtls);
  exit(0);
}
