#ifndef SESSION_H
#define SESSION_H

#include "tinydtls.h"
#include "dtls.h"

#include "address.h"


typedef struct session_context_t {
    session_t dtls_session;
    struct session_context_t *next;
} session_context_t;

/* encapsulates the tinydtls context object */
typedef struct proxy_dtls_context_t {
    dtls_context_t *dtls;
    session_context_t *sessions;
} proxy_dtls_context_t;


session_context_t *new_session(proxy_dtls_context_t *dtls_ctx,
                               int sockfd, const address_t *remote);

session_context_t *find_session(proxy_dtls_context_t *dtls_ctx,
                                int sockfd, const address_t *dst);

void free_session(proxy_dtls_context_t *dtls_ctx,
                  session_context_t *session);

proxy_dtls_context_t *new_dtls_context(void *dtls_data);
void free_dtls_context(proxy_dtls_context_t *dtls_ctx);

#endif // SESSION_H
