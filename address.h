#ifndef ADDRESS_H
#define ADDRESS_H

#include <sys/socket.h>
#include <netinet/in.h>

typedef struct address_t {
    socklen_t size;
    union {
        struct sockaddr         sa;
        struct sockaddr_storage st;
        struct sockaddr_in      sin;
        struct sockaddr_in6     sin6;
    } addr;
} address_t;

struct proxy_context;

typedef struct endpoint_t {
    struct endpoint_t *next;
    union {
        int fd;
        void *conn;
    } handle;
    struct proxy_context *context;
    address_t addr;
    int ifindex;
    int flags;
} endpoint_t;

int resolve_address(const char *host, const char *port, struct sockaddr *dst);

#endif // ADDRESS_H
