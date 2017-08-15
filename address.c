
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

