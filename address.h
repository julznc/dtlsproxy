#ifndef ADDRESS_H
#define ADDRESS_H

#include <tinydtls.h>
#include <dtls.h>

void print_address(session_t *addr, char *buf, size_t buf_len);
int resolve_address(const char *host, const char *port, session_t *addr);
int create_socket(const session_t *addr);

#endif // ADDRESS_H
