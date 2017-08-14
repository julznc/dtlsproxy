
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

