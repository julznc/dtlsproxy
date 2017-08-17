
#include <string.h>
#include <getopt.h>
#include <signal.h>

#include "proxy.h"
#include "utils.h"

static proxy_context_t context;

static void usage(const char *program)
{
    const char *p = strrchr( program, '/' );
    if ( p )
        program = ++p;

    printf("\nDTLS reverse proxy server (c) 2017 yus\n\n"
        "usage: %s -l <host:port> -b <hosts:ports> -k <key maps>\n"
        "\t-l listen    listen on specified host and port\n"
        "\t-b backends  backend servers (host1:port1,host2:port2,...)\n"
        "\t-k keys      psk identities (id1:key1,id2:key2,...)\n", program);
    exit(1);
}

static void handle_sigint(int signum)
{
    static int done = 0;
    //DBG("%s done=%d", __func__, done);
    if (done) {
        return;
    }
    proxy_exit(&context);
    done = 1;
}

int main(int argc, char **argv)
{
    char listen_addr_buf[128];
    char backends_addr_buf[512];
    char psk_buf[512];

    DBG("%s started", argv[0]);

    memset(&context, 0, sizeof(proxy_context_t));
    memset(listen_addr_buf, 0, sizeof(listen_addr_buf));
    memset(backends_addr_buf, 0, sizeof(backends_addr_buf));
    memset(psk_buf, 0, sizeof(psk_buf));

    static const struct option lopts[] = {
        {"listen",   required_argument, 0, 'l'},
        {"backends", required_argument, 0, 'b'},
        {"key",      required_argument, 0, 'k'},
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "l:b:k:", lopts, NULL)) != -1) {
        switch (opt) {
        case 'l' :
            strncpy(listen_addr_buf, optarg, sizeof(listen_addr_buf)-1);
            break;
        case 'b' :
            strncpy(backends_addr_buf, optarg, sizeof(backends_addr_buf)-1);
            break;
        case 'k' :
            strncpy(psk_buf, optarg, sizeof(psk_buf)-1);
            break;
        default:
            usage(argv[0]);
        }
    }

    if (0!=proxy_init(&context,
                      listen_addr_buf,
                      backends_addr_buf,
                      psk_buf)) {
        ERR("proxy init failed");
        proxy_deinit(&context);
        usage(argv[0]);
    }

    signal(SIGINT, handle_sigint);
    proxy_run(&context);

    proxy_deinit(&context);
    DBG("%s exit", argv[0]);
    return 0;
}
