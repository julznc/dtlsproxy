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


int address_equals(const address_t *a, const address_t *b);
int resolve_address(const char *host, const char *port, address_t *addr);
int create_socket(const address_t *addr, const address_t *bind_addr);


#endif // ADDRESS_H
