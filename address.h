#ifndef ADDRESS_H
#define ADDRESS_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>


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


int address_equals(const address_t *a, const address_t *b);

endpoint_t *new_endpoint(const address_t *addr);
void detach_endpoint(endpoint_t *endpoint);
void attach_endpoint(struct proxy_context *ctx, endpoint_t *endpoint);


#endif // ADDRESS_H
