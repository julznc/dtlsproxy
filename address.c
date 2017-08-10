
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "utlist.h"

#include "address.h"
#include "proxy.h"
#include "utils.h"


int address_equals(const address_t *a, const address_t *b)
{
    assert(a); assert(b);

    if (a->size != b->size || a->addr.sa.sa_family != b->addr.sa.sa_family) {
        return 0;
    }

   switch (a->addr.sa.sa_family)
   {
   case AF_INET:
       return ( (a->addr.sin.sin_port == b->addr.sin.sin_port) &&
                (memcmp(&a->addr.sin.sin_addr, &b->addr.sin.sin_addr,
                        sizeof(struct in_addr)) == 0));
   case AF_INET6:
       return ( (a->addr.sin6.sin6_port == b->addr.sin6.sin6_port) &&
                (memcmp(&a->addr.sin6.sin6_addr, &b->addr.sin6.sin6_addr,
                        sizeof(struct in6_addr)) == 0));
   }
   return 0;
}

int create_socket(const address_t *addr, const address_t *bind_addr)
{
    int sockfd = socket(addr->addr.sa.sa_family, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        ERR("failed to create socket");
        return -1;
    }

    if (fcntl(sockfd, F_SETFL, O_NONBLOCK) < 0) {
        ERR("set nonblock failed: %s", strerror(errno));
        close (sockfd);
        return -1;
    }

    int on = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
        ERR("new_endpoint: setsockopt SO_REUSEADDR");
    }

    on = 1;
    switch(addr->addr.sa.sa_family)
    {
    case AF_INET:
        if (setsockopt(sockfd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)) < 0) {
            ERR("setsockopt IP_PKTINFO failed");
        }
        break;
    case AF_INET6:
#ifdef IPV6_RECVPKTINFO
        if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)) < 0) {
            ERR("setsockopt IPV6_RECVPKTINFO failed");
        }
#else /* IPV6_RECVPKTINFO */
        if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_PKTINFO, &on, sizeof(on)) < 0) {
            ERR("setsockopt IPV6_PKTINFO failed");
        }
#endif /* IPV6_RECVPKTINFO */
        break;
    default:
        ERR("setsockopt: unsupported sa_family");
        break;
    }

    if (bind(sockfd, &bind_addr->addr.sa, bind_addr->size) < 0) {
        ERR("bind() failed: %s", strerror(errno));
        close (sockfd);
        return -1;
    }

    return sockfd;
}

endpoint_t *new_endpoint(const address_t *addr)
{
    int sockfd = create_socket(addr, addr);
    if (sockfd < 0) {
        ERR("new_endpoint: socket");
        return NULL;
    }

    endpoint_t *ep = (endpoint_t *)malloc(sizeof(endpoint_t));
    if (!ep) {
        ERR("new_endpoint: malloc failed");
        close (sockfd);
        return NULL;
    }

    memset(ep, 0, sizeof(endpoint_t));
    ep->handle.fd = sockfd;
    ep->flags = 0x0001; // fix me

    ep->addr.size = addr->size;
    if (getsockname(sockfd, &ep->addr.addr.sa, &ep->addr.size) < 0) {
        ERR("new_endpoint: cannot determine local address");
        close (sockfd);
        free(ep);
        return NULL;
    }

    return (endpoint_t *)ep;
}

void free_endpoint(endpoint_t *ep)
{
    if(ep) {
        if (ep->handle.fd >= 0) {
            close(ep->handle.fd);
        }
        free(ep);
    }
}

void detach_endpoint(endpoint_t *endpoint)
{
    if (endpoint->context != NULL) {
        LL_DELETE(endpoint->context->endpoint, endpoint);
        endpoint->context = NULL;
    }
}

void attach_endpoint(struct proxy_context *ctx, endpoint_t *endpoint)
{
    detach_endpoint(endpoint);
    endpoint->context = ctx;
    LL_PREPEND(ctx->endpoint, endpoint);
}

