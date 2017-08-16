
#include <utlist.h>

#include "session.h"
#include "proxy.h"
#include "utils.h"

session_context_t *new_session(struct proxy_context *ctx,
                               const dtls_peer_t *peer)
{
    session_context_t *session = (session_context_t *)malloc(sizeof(session_context_t));
    if (NULL==session) {
        ERR("failed to allocate session_context");
        return NULL;
    }

    memset(session, 0, sizeof(session_context_t));
    memcpy(&session->peer, peer, sizeof(dtls_peer_t));

    LL_PREPEND(ctx->sessions, session);
    return session;
}

void free_session(struct proxy_context *ctx,
                  session_context_t *session)
{
    if (ctx && session) {
        LL_DELETE(ctx->sessions, session);
        free(session);
    }
}

session_context_t *find_session(struct proxy_context *ctx,
                                const session_t *addr)
{
    session_context_t *session = NULL;

    LL_FOREACH(ctx->sessions, session) {
        if (dtls_session_equals(addr, &session->peer.session)) {
            return session;
        }
    }

    return session;
}

