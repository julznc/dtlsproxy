#ifndef SESSION_H
#define SESSION_H

#include "tinydtls.h"
#include "dtls.h"

#include "address.h"


typedef struct session_context_t {
    session_t dtls_session;
    struct session_context_t *next;
} session_context_t;

struct proxy_context;

session_context_t *new_session(struct proxy_context *ctx,
                               int sockfd, const address_t *remote);

session_context_t *find_session(struct proxy_context *ctx,
                                int sockfd, const address_t *dst);

void free_session(struct proxy_context *ctx,
                  session_context_t *session);

#endif // SESSION_H
