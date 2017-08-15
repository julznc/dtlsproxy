

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

#include "tinydtls.h"
#include "dtls.h"
#include "dtls_debug.h"

#include "proxy.h"
#include "utils.h"

#define DEFAULT_PORT 20220

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

static int
resolve_address(const char *server, struct sockaddr *dst) {

  struct addrinfo *res, *ainfo;
  struct addrinfo hints;
  static char addrstr[256];
  int error;

  memset(addrstr, 0, sizeof(addrstr));
  if (server && strlen(server) > 0)
    memcpy(addrstr, server, strlen(server));
  else
    memcpy(addrstr, "localhost", 9);

  memset ((char *)&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_family = AF_UNSPEC;

  error = getaddrinfo(addrstr, "", &hints, &res);

  if (error != 0) {
    ERR("getaddrinfo(%s) %s", server, gai_strerror(error));
    return error;
  }

  for (ainfo = res; ainfo != NULL; ainfo = ainfo->ai_next) {

    switch (ainfo->ai_family) {
    case AF_INET:
    case AF_INET6:

      memcpy(dst, ainfo->ai_addr, ainfo->ai_addrlen);
      return ainfo->ai_addrlen;
    default:
      ;
    }
  }

  freeaddrinfo(res);
  return -1;
}

static void
usage(const char *program, const char *version) {
  const char *p;

  p = strrchr( program, '/' );
  if ( p )
    program = ++p;

  ERR("%s v%s -- DTLS server implementation\n"
          "(c) 2011-2014 Olaf Bergmann <bergmann@tzi.org>\n\n"
          "usage: %s [-A address] [-p port] [-i psk]\n"
          "\t-A address\t\tlisten on specified address (default is ::)\n"
          "\t-p port\t\tlisten on specified port (default is %d)\n"
          "\t-i num\t\tpsk identities\n",
           program, version, program, DEFAULT_PORT);
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
  dtls_context_t *dtls_ctx = NULL;
  fd_set rfds, wfds;
  struct timeval timeout;
  int fd, opt, result;
  int on = 1;
  struct sockaddr_in6 listen_addr;
  uint8_t psk_buf[1024];

  proxy_context_t context;
  memset(&context, 0, sizeof(proxy_context_t));

  memset(&listen_addr, 0, sizeof(struct sockaddr_in6));
  memset(psk_buf, 0, sizeof(psk_buf));

  listen_addr.sin6_port = htons(DEFAULT_PORT);
  listen_addr.sin6_addr = in6addr_any;

  while ((opt = getopt(argc, argv, "A:p:i:")) != -1) {
    switch (opt) {
    case 'A' :
      if (resolve_address(optarg, (struct sockaddr *)&listen_addr) < 0) {
        ERR("cannot resolve address");
        exit(-1);
      }
      break;
    case 'p' :
      listen_addr.sin6_port = htons(atoi(optarg));
      break;
    case 'i' :
      strncpy((char*)psk_buf, optarg, sizeof(psk_buf)-1);
      keystore_t *psk = (keystore_t *)malloc(sizeof(keystore_t));
      if (NULL==psk) {
        exit(1);
      }
      memset(psk, 0, sizeof(keystore_t));
      context.psk = psk; // first keymap pair
      char *ptr = (char*)psk_buf;
      char *psk_str = strtok_r((char*)psk_buf, ",", &ptr);
      while (psk_str) {
        char *sep = strchr(psk_str, ':');
        if (sep) {
          //DBG("psk_str=%s", psk_str);
          //sep = '\0';
          psk->id = (uint8_t*)psk_str;
          psk->id_length = sep-psk_str;
          psk->key = (uint8_t*)sep+1;
          psk->key_length = strlen(sep+1);
          psk->next = (keystore_t *)malloc(sizeof(keystore_t));
          if (NULL==psk->next) {
            exit(1);
          }
          psk = psk->next;
          memset(psk, 0, sizeof(keystore_t));
        }
        psk_str = strtok_r(NULL, ",", &ptr);
      }
      break;
    default:
      usage(argv[0], dtls_package_version());
      exit(1);
    }
  }

  /* init socket and set it to non-blocking */
  fd = socket(listen_addr.sin6_family, SOCK_DGRAM, 0);

  if (fd < 0) {
    ERR("socket: %s", strerror(errno));
    return 0;
  }

  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on) ) < 0) {
    ERR("setsockopt SO_REUSEADDR: %s", strerror(errno));
  }

  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    ERR("fcntl: %s", strerror(errno));
    goto error;
  }

  on = 1;
  switch (listen_addr.sin6_family)
  {
  case AF_INET:
    if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)) < 0) {
      ERR("setsockopt IP_PKTINFO: %s", strerror(errno));
    }
    break;
  case AF_INET6:
#ifdef IPV6_RECVPKTINFO
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on) ) < 0) {
#else /* IPV6_RECVPKTINFO */
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_PKTINFO, &on, sizeof(on) ) < 0) {
#endif /* IPV6_RECVPKTINFO */
      ERR("setsockopt IPV6_PKTINFO: %s", strerror(errno));
    }
    break;
  }

  if (bind(fd, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0) {
    ERR("bind: %s", strerror(errno));
    goto error;
  }

  context.listen_fd = fd;

  dtls_init();

  dtls_ctx = dtls_new_context(&context);

  dtls_set_handler(dtls_ctx, &cb);

  while (1) {
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);

    FD_SET(fd, &rfds);
    /* FD_SET(fd, &wfds); */

    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    result = select( fd+1, &rfds, &wfds, 0, &timeout);

    if (result < 0) {                /* error */
      if (errno != EINTR)
        perror("select");
    } else if (result == 0) {        /* timeout */
    } else {                        /* ok */
      if (FD_ISSET(fd, &wfds))
        ;
      else if (FD_ISSET(fd, &rfds)) {
        dtls_handle_read(dtls_ctx);
      }
    }
  }

 error:
  dtls_free_context(dtls_ctx);
  exit(0);
}
