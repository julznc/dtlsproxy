#ifndef ADDRESS_H
#define ADDRESS_H

#include <tinydtls.h>
#include <dtls.h>

int resolve_address(const char *host, const char *port, session_t *addr);

#endif // ADDRESS_H
