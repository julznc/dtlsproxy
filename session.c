
#include <string.h>

#include "session.h"
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

session_context_t *new_session(proxy_dtls_context_t *dtls_ctx,
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

    LL_PREPEND(dtls_ctx->sessions, session);
    return session;
}

session_context_t *find_session(proxy_dtls_context_t *dtls_ctx,
                                int sockfd, const address_t *dst)
{
    session_context_t *session = NULL;

    LL_FOREACH(dtls_ctx->sessions, session) {
        if ((session->dtls_session.ifindex == sockfd) &&
            address_equals((address_t *)&session->dtls_session, dst)) {
            return session;
        }
    }

    return session;
}

void free_session(proxy_dtls_context_t *dtls_ctx,
                  session_context_t *session)
{
    if (dtls_ctx && session) {
        LL_DELETE(dtls_ctx->sessions, session);
        free(session);
    }
}

proxy_dtls_context_t *new_dtls_context(void *dtls_data)
{
    proxy_dtls_context_t *ctx = (proxy_dtls_context_t *)malloc(sizeof(proxy_dtls_context_t));
    if (NULL==ctx) {
        ERR("failed to allocate proxy_dtls_context");
        return NULL;
    }

    memset(ctx, 0, sizeof(proxy_dtls_context_t));
    ctx->dtls = dtls_new_context(dtls_data);
    if (NULL==ctx->dtls) {
        ERR("failed to allocate dtls_context");
        free(ctx);
        return NULL;
    }
    return ctx;
}

void free_dtls_context(proxy_dtls_context_t *dtls_ctx)
{
    while(dtls_ctx->sessions) {
        free_session(dtls_ctx, dtls_ctx->sessions);
    }
    dtls_free_context(dtls_ctx->dtls);
    free(dtls_ctx);
}

