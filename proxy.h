#ifndef PROXY_H
#define PROXY_H


typedef struct proxy_option {
    char *listen_host;
    char *listen_port;
    char *backend_host;
    char *backend_port;
} proxy_option_t;


typedef struct proxy_psk {
    char *id;
    char *key;
} proxy_psk_t;


typedef struct proxy_context {
    const proxy_option_t *options;
    int listen_fd;
} proxy_context_t;


int proxy_init(proxy_context_t *ctx,
               const proxy_option_t *opt,
               const proxy_psk_t *psk);

#endif // PROXY_H

