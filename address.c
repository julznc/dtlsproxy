
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "address.h"
#include "utils.h"

int resolve_address(const char *host, const char *port, session_t *addr)
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

int create_socket(const session_t *addr)
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
        return -1;
    }

    on = 1;
    switch(addr->addr.sa.sa_family)
    {
    case AF_INET:
        if (setsockopt(sockfd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)) < 0) {
            ERR("setsockopt IP_PKTINFO failed");
            return -1;
        }
        break;
    case AF_INET6:
#ifdef IPV6_RECVPKTINFO
        if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)) < 0) {
            ERR("setsockopt IPV6_RECVPKTINFO failed");
            return -1;
        }
#else /* IPV6_RECVPKTINFO */
        if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_PKTINFO, &on, sizeof(on)) < 0) {
            ERR("setsockopt IPV6_PKTINFO failed");
            return -1;
        }
#endif /* IPV6_RECVPKTINFO */
        break;
    default:
        ERR("setsockopt: unsupported sa_family");
        return -1;
    }

    return sockfd;
}

