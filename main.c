
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

    printf("DTLS proxy server (c) 2017 yus\n\n"
        "usage: %s -l <host:port> -b <host:port> -k <psk>\n"
        "\t-l listen\tlisten on specified host and port\n"
        "\t-b backend\tbackend server host and port\n"
        "\t-k keys\t\tpsk identities (id1:key1,id2:key2,...,idN:keyN)\n", program);
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
    proxy_option_t option;
    char psk_buf[1024];

    DBG("%s started", argv[0]);

    memset(&context, 0, sizeof(proxy_context_t));
    memset(&option, 0, sizeof(proxy_option_t));
    memset(psk_buf, 0, sizeof(psk_buf));

    static const struct option lopts[] = {
        {"backend", required_argument, 0, 'b'},
        {"listen",  required_argument, 0, 'l'},
        {"key",     required_argument, 0, 'k'},
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "b:l:k:", lopts, NULL)) != -1) {
        char *sep = NULL;
        switch (opt) {
        case 'l' :
            if (NULL == (sep = strrchr(optarg, ':'))) {
                usage(argv[0]);
            }
            *sep = '\0';
            option.listen.host = optarg;
            option.listen.port = sep+1;
            break;
        case 'b' :
            if (NULL == (sep = strrchr(optarg, ':'))) {
                usage(argv[0]);
            }
            *sep = '\0';
            option.backend.host = optarg;
            option.backend.port = sep+1;
            break;
        case 'k' :
            strncpy(psk_buf, optarg, sizeof(psk_buf)-1);
            break;
        default:
            usage(argv[0]);
        }
    }

    if (0!=proxy_init(&context, &option, psk_buf)) {
        ERR("proxy init failed");
        proxy_deinit(&context);
        return -1;
    }

    signal(SIGINT, handle_sigint);
    proxy_run(&context);

    proxy_deinit(&context);
    DBG("%s exit", argv[0]);
    return 0;
}
