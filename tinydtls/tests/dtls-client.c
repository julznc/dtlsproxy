#include "tinydtls.h" 

/* This is needed for apple */
#define __APPLE_USE_RFC_3542

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>

#include "global.h" 
#include "dtls_debug.h"
#include "dtls.h" 

#define DEFAULT_PORT 20220

#define PSK_DEFAULT_IDENTITY "Client_identity"
#define PSK_DEFAULT_KEY      "secretPSK"

#ifdef __GNUC__
#define UNUSED_PARAM __attribute__((unused))
#else
#define UNUSED_PARAM
#endif /* __GNUC__ */

static char buf[200];
static size_t len = 0;

typedef struct {
  size_t length;               /* length of string */
  unsigned char *s;            /* string data */
} dtls_str;

static dtls_context_t *dtls_context = NULL;



#ifdef DTLS_PSK

/* The PSK information for DTLS */
#define PSK_ID_MAXLEN 256
#define PSK_MAXLEN 256
static unsigned char psk_id[PSK_ID_MAXLEN];
static size_t psk_id_length = 0;
static unsigned char psk_key[PSK_MAXLEN];
static size_t psk_key_length = 0;

/* This function is the "key store" for tinyDTLS. It is called to
 * retrieve a key for the given identity within this particular
 * session. */
static int
get_psk_info(struct dtls_context_t *ctx UNUSED_PARAM,
            const session_t *session UNUSED_PARAM,
            dtls_credentials_type_t type,
            const unsigned char *id, size_t id_len,
            unsigned char *result, size_t result_length) {

  switch (type) {
  case DTLS_PSK_IDENTITY:
    if (id_len) {
      dtls_debug("got psk_identity_hint: '%.*s'\n", id_len, id);
    }

    if (result_length < psk_id_length) {
      dtls_warn("cannot set psk_identity -- buffer too small\n");
      return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
    }

    memcpy(result, psk_id, psk_id_length);
    return psk_id_length;
  case DTLS_PSK_KEY:
    if (id_len != psk_id_length || memcmp(psk_id, id, id_len) != 0) {
      dtls_warn("PSK for unknown id requested, exiting\n");
      return dtls_alert_fatal_create(DTLS_ALERT_ILLEGAL_PARAMETER);
    } else if (result_length < psk_key_length) {
      dtls_warn("cannot set psk -- buffer too small\n");
      return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
    }

    memcpy(result, psk_key, psk_key_length);
    return psk_key_length;
  default:
    dtls_warn("unsupported request type: %d\n", type);
  }

  return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
}
#endif /* DTLS_PSK */


static void
try_send(struct dtls_context_t *ctx, session_t *dst) {
  int res;
  res = dtls_write(ctx, dst, (uint8 *)buf, len);
  if (res >= 0) {
    memmove(buf, buf + res, len - res);
    len -= res;
  }
}

static void
handle_stdin() {
  if (fgets(buf + len, sizeof(buf) - len, stdin))
    len += strlen(buf + len);
}

static int
read_from_peer(struct dtls_context_t *ctx, 
               session_t *session, uint8 *data, size_t len) {
  size_t i;
  for (i = 0; i < len; i++)
    printf("%c", data[i]);
  return 0;
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
  int fd;
  session_t session;
#define MAX_READ_BUF 2000
  static uint8 buf[MAX_READ_BUF];
  int len;

  fd = *(int *)dtls_get_app_data(ctx);
  
  if (!fd)
    return -1;

  memset(&session, 0, sizeof(session_t));
  session.size = sizeof(session.addr);
  len = recvfrom(fd, buf, MAX_READ_BUF, 0, 
                 &session.addr.sa, &session.size);
  
  if (len < 0) {
    perror("recvfrom");
    return -1;
  } else {
    dtls_dsrv_log_addr(DTLS_LOG_DEBUG, "peer", &session);
    dtls_debug_dump("bytes from peer", buf, len);
  }

  return dtls_handle_message(ctx, &session, buf, len);
}    

static void dtls_handle_signal(int sig)
{
  dtls_free_context(dtls_context);
  signal(sig, SIG_DFL);
  kill(getpid(), sig);
}

/* stolen from libcoap: */
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

/*---------------------------------------------------------------------------*/
static void
usage( const char *program, const char *version) {
  const char *p;

  p = strrchr( program, '/' );
  if ( p )
    program = ++p;

  fprintf(stderr, "%s v%s -- DTLS client implementation\n"
          "(c) 2011-2014 Olaf Bergmann <bergmann@tzi.org>\n\n"
#ifdef DTLS_PSK
          "usage: %s [-i file] [-k file] [-o file] [-p port] [-v num] addr [port]\n"
#else /*  DTLS_PSK */
          "usage: %s [-o file] [-p port] [-v num] addr [port]\n"
#endif /* DTLS_PSK */
#ifdef DTLS_PSK
          "\t-i file\t\tread PSK identity from file\n"
          "\t-k file\t\tread pre-shared key from file\n"
#endif /* DTLS_PSK */
          "\t-o file\t\toutput received data to this file (use '-' for STDOUT)\n"
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
  fd_set rfds, wfds;
  struct timeval timeout;
  unsigned short port = DEFAULT_PORT;
  char port_str[NI_MAXSERV] = "0";
  log_t log_level = DTLS_LOG_WARN;
  int fd, result;
  int on = 1;
  int opt, res;
  session_t dst;

  dtls_init();
  snprintf(port_str, sizeof(port_str), "%d", port);

#ifdef DTLS_PSK
  psk_id_length = strlen(PSK_DEFAULT_IDENTITY);
  psk_key_length = strlen(PSK_DEFAULT_KEY);
  memcpy(psk_id, PSK_DEFAULT_IDENTITY, psk_id_length);
  memcpy(psk_key, PSK_DEFAULT_KEY, psk_key_length);
#endif /* DTLS_PSK */

  while ((opt = getopt(argc, argv, "p:v:")) != -1) {
    switch (opt) {
    case 'p' :
      strncpy(port_str, optarg, NI_MAXSERV-1);
      port_str[NI_MAXSERV - 1] = '\0';
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
  
  if (argc <= optind) {
    usage(argv[0], dtls_package_version());
    exit(1);
  }
  
  memset(&dst, 0, sizeof(session_t));
  /* resolve destination address where server should be sent */
  res = resolve_address(argv[optind++], &dst.addr.sa);
  if (res < 0) {
    dtls_emerg("failed to resolve address\n");
    exit(-1);
  }
  dst.size = res;

  /* use port number from command line when specified or the listen
     port, otherwise */
  dst.addr.sin.sin_port = htons(atoi(optind < argc ? argv[optind++] : port_str));

  
  /* init socket and set it to non-blocking */
  fd = socket(dst.addr.sa.sa_family, SOCK_DGRAM, 0);

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
  switch (dst.addr.sa.sa_family)
  {
  case AF_INET:
    if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)) < 0) {
      dtls_alert("setsockopt IP_PKTINFO: %s\n", strerror(errno));
    }
    break;
  case AF_INET6:
#ifdef IPV6_RECVPKTINFO
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on) ) < 0) {
#else /* IPV6_RECVPKTINFO */
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_PKTINFO, &on, sizeof(on) ) < 0) {
#endif /* IPV6_RECVPKTINFO */
      dtls_alert("setsockopt IPV6_PKTINFO: %s\n", strerror(errno));
    }
    break;
  }

  if (signal(SIGINT, dtls_handle_signal) == SIG_ERR) {
    dtls_alert("An error occurred while setting a signal handler.\n");
    return EXIT_FAILURE;
  }

  dtls_context = dtls_new_context(&fd);
  if (!dtls_context) {
    dtls_emerg("cannot create context\n");
    exit(-1);
  }

  dtls_set_handler(dtls_context, &cb);

  dtls_connect(dtls_context, &dst);

  while (1) {
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);

    FD_SET(fileno(stdin), &rfds);
    FD_SET(fd, &rfds);
    /* FD_SET(fd, &wfds); */
    
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    
    result = select(fd+1, &rfds, &wfds, 0, &timeout);
    
    if (result < 0) {                /* error */
      if (errno != EINTR)
        perror("select");
    } else if (result == 0) {        /* timeout */
    } else {                        /* ok */
      if (FD_ISSET(fd, &wfds))
        /* FIXME */;
      else if (FD_ISSET(fd, &rfds))
        dtls_handle_read(dtls_context);
      else if (FD_ISSET(fileno(stdin), &rfds))
        handle_stdin();
    }

    if (len) {
      try_send(dtls_context, &dst);
    }
  }
 error:
  dtls_free_context(dtls_context);
  exit(0);
}

