

#include <assert.h>
#include <stdio.h>
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

#define DEFAULT_PORT 20220

#ifdef DTLS_PSK
/* This function is the "key store" for tinyDTLS. It is called to
 * retrieve a key for the given identity within this particular
 * session. */
static int
get_psk_info(struct dtls_context_t *ctx, const session_t *session,
             dtls_credentials_type_t type,
             const unsigned char *id, size_t id_len,
             unsigned char *result, size_t result_length) {

  struct keymap_t {
    unsigned char *id;
    size_t id_length;
    unsigned char *key;
    size_t key_length;
  } psk[3] = {
    { (unsigned char *)"Client_identity", 15,
      (unsigned char *)"secretPSK", 9 },
    { (unsigned char *)"default identity", 16,
      (unsigned char *)"\x11\x22\x33", 3 },
    { (unsigned char *)"\0", 2,
      (unsigned char *)"", 1 }
  };

  if (type != DTLS_PSK_KEY) {
    return 0;
  }

  if (id) {
    int i;
    for (i = 0; i < sizeof(psk)/sizeof(struct keymap_t); i++) {
      if (id_len == psk[i].id_length && memcmp(id, psk[i].id, id_len) == 0) {
        if (result_length < psk[i].key_length) {
          dtls_warn("buffer too small for PSK");
          return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
        }

        memcpy(result, psk[i].key, psk[i].key_length);
        return psk[i].key_length;
      }
    }
  }

  return dtls_alert_fatal_create(DTLS_ALERT_DECRYPT_ERROR);
}

#endif /* DTLS_PSK */

#define DTLS_SERVER_CMD_CLOSE "server:close"
#define DTLS_SERVER_CMD_RENEGOTIATE "server:renegotiate"

static int
read_from_peer(struct dtls_context_t *ctx, 
               session_t *session, uint8 *data, size_t len) {
  size_t i;
  for (i = 0; i < len; i++)
    printf("%c", data[i]);
  if (len >= strlen(DTLS_SERVER_CMD_CLOSE) &&
      !memcmp(data, DTLS_SERVER_CMD_CLOSE, strlen(DTLS_SERVER_CMD_CLOSE))) {
    printf("server: closing connection\n");
    dtls_close(ctx, session);
    return len;
  } else if (len >= strlen(DTLS_SERVER_CMD_RENEGOTIATE) &&
      !memcmp(data, DTLS_SERVER_CMD_RENEGOTIATE, strlen(DTLS_SERVER_CMD_RENEGOTIATE))) {
    printf("server: renegotiate connection\n");
    dtls_renegotiate(ctx, session);
    return len;
  }

  return dtls_write(ctx, session, data, len);
}

static int
send_to_peer(struct dtls_context_t *ctx, 
             session_t *session, uint8 *data, size_t len) {

  int fd = *(int *)dtls_get_app_data(ctx);
  return sendto(fd, data, len, MSG_DONTWAIT,
                &session->addr.sa, session->size);
}

static int
dtls_handle_read(struct dtls_context_t *ctx) {
  int *fd;
  session_t session;
  static uint8 buf[DTLS_MAX_BUF];
  int len;

  fd = dtls_get_app_data(ctx);

  assert(fd);

  memset(&session, 0, sizeof(session_t));
  session.size = sizeof(session.addr);
  len = recvfrom(*fd, buf, sizeof(buf), MSG_TRUNC,
                 &session.addr.sa, &session.size);

  if (len < 0) {
    perror("recvfrom");
    return -1;
  } else {
    dtls_debug("got %d bytes from port %d\n", len, 
             ntohs(session.addr.sin6.sin6_port));
    if (sizeof(buf) < len) {
      dtls_warn("packet was truncated (%d bytes lost)\n", len - sizeof(buf));
    }
  }

  return dtls_handle_message(ctx, &session, buf, len);
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
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(error));
    return error;
  }

  for (ainfo = res; ainfo != NULL; ainfo = ainfo->ai_next) {

    switch (ainfo->ai_family) {
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

  fprintf(stderr, "%s v%s -- DTLS server implementation\n"
          "(c) 2011-2014 Olaf Bergmann <bergmann@tzi.org>\n\n"
          "usage: %s [-A address] [-p port] [-v num]\n"
          "\t-A address\t\tlisten on specified address (default is ::)\n"
          "\t-p port\t\tlisten on specified port (default is %d)\n"
          "\t-v num\t\tverbosity level (default: 3)\n",
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
  dtls_context_t *the_context = NULL;
  log_t log_level = DTLS_LOG_WARN;
  fd_set rfds, wfds;
  struct timeval timeout;
  int fd, opt, result;
  int on = 1;
  struct sockaddr_in6 listen_addr;

  memset(&listen_addr, 0, sizeof(struct sockaddr_in6));

  /* fill extra field for 4.4BSD-based systems (see RFC 3493, section 3.4) */
#if defined(SIN6_LEN) || defined(HAVE_SOCKADDR_IN6_SIN6_LEN)
  listen_addr.sin6_len = sizeof(struct sockaddr_in6);
#endif

  listen_addr.sin6_family = AF_INET6;
  listen_addr.sin6_port = htons(DEFAULT_PORT);
  listen_addr.sin6_addr = in6addr_any;

  while ((opt = getopt(argc, argv, "A:p:v:")) != -1) {
    switch (opt) {
    case 'A' :
      if (resolve_address(optarg, (struct sockaddr *)&listen_addr) < 0) {
        fprintf(stderr, "cannot resolve address\n");
        exit(-1);
      }
      break;
    case 'p' :
      listen_addr.sin6_port = htons(atoi(optarg));
      break;
    case 'v' :
      log_level = strtol(optarg, NULL, 10);
      break;
    default:
      usage(argv[0], dtls_package_version());
      exit(1);
    }
  }

  dtls_set_log_level(log_level);

  /* init socket and set it to non-blocking */
  fd = socket(listen_addr.sin6_family, SOCK_DGRAM, 0);

  if (fd < 0) {
    dtls_alert("socket: %s\n", strerror(errno));
    return 0;
  }

  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on) ) < 0) {
    dtls_alert("setsockopt SO_REUSEADDR: %s\n", strerror(errno));
  }

  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    dtls_alert("fcntl: %s\n", strerror(errno));
    goto error;
  }

  on = 1;
#ifdef IPV6_RECVPKTINFO
  if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on) ) < 0) {
#else /* IPV6_RECVPKTINFO */
  if (setsockopt(fd, IPPROTO_IPV6, IPV6_PKTINFO, &on, sizeof(on) ) < 0) {
#endif /* IPV6_RECVPKTINFO */
    dtls_alert("setsockopt IPV6_PKTINFO: %s\n", strerror(errno));
  }

  if (bind(fd, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0) {
    dtls_alert("bind: %s\n", strerror(errno));
    goto error;
  }

  dtls_init();

  the_context = dtls_new_context(&fd);

  dtls_set_handler(the_context, &cb);

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
        dtls_handle_read(the_context);
      }
    }
  }
  
 error:
  dtls_free_context(the_context);
  exit(0);
}
