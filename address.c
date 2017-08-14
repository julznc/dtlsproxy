
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "address.h"
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

int resolve_address(const char *host, const char *port, address_t *addr)
{
    DBG("%s(%s:%s)", __func__, host, port);

    struct addrinfo *res, *ainfo;
    struct addrinfo hints;

    memset ((char *)&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_family = AF_UNSPEC;

    int error = getaddrinfo(host, port, &hints, &res);

    if (error != 0) {
        ERR("getaddrinfo: %s", gai_strerror(error));
        return error;
    }

    int len = -1;
    for (ainfo = res; ainfo != NULL; ainfo = ainfo->ai_next) {
        switch (ainfo->ai_family) {
        case AF_INET:
        // fall through
        case AF_INET6:
            len = ainfo->ai_addrlen;
            memcpy(&addr->addr, ainfo->ai_addr, len);
            addr->size = len;
        }
        if (len > 0) break;
    }

    freeaddrinfo(res);
    return len;
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

