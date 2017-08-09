
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "proxy.h"
#include "utils.h"

static char *listen_host = NULL;
static char *listen_port = NULL;
static char *backend_host = NULL;
static char *backend_port = NULL;
static char *dtls_id = NULL;
static char *dtls_key = NULL;

static void print_usage(const char *prog)
{
    printf("Usage: %s [-blik]\n", prog);
    puts("  -b --backend    backend host:port\n"
         "  -l --listen     listen host:port\n"
         "  -i --id         dtls identity\n"
         "  -k --key        dtls key\n");
    exit(-1);
}

static void parse_opts(int argc, char *argv[])
{
    int c;
    static const struct option lopts[] = {
        {"backend", required_argument, 0, 'b'},
        {"listen",  required_argument, 0, 'l'},
        {"id",      required_argument, 0, 'i'},
        {"key",     required_argument, 0, 'k'},
    };
    while (-1 != (c = getopt_long(argc, argv, "b:l:i:k:", lopts, NULL)))
    {
        char *sep;
        switch (c)
        {
        case 'b':
            sep = strchr(optarg, ':');
            if (!sep) {
              print_usage(argv[0]);
            }
            *sep = '\0';
            backend_host = optarg;
            backend_port = sep + 1;
            break;
        case 'l':
            sep = strchr(optarg, ':');
            if (!sep) {
              print_usage(argv[0]);
            }
            *sep = '\0';
            listen_host = optarg;
            listen_port = sep + 1;
            break;
        case 'i':
            dtls_id = optarg;
            break;
        case 'k':
            dtls_key = optarg;
            break;
        default:
            print_usage(argv[0]);
            break;
        }
    }

    if (!backend_host || !backend_port ||
        !listen_host || !listen_port ||
        !dtls_id || !dtls_key) {
        print_usage(argv[0]);
    }
}

int main(int argc, char *argv[])
{
    DBG("%s started", argv[argc-argc]);

    parse_opts(argc, argv);

    proxy_option_t options = {
        listen_host, listen_port,
        backend_host, backend_port
    };

    proxy_psk_t psk = {
        dtls_id, dtls_key
    };

    proxy_context_t context;

    if (0!=proxy_init(&context, &options, &psk)) {
        ERR("proxy init failed");
        proxy_deinit(&context);
        return -1;
    }

    proxy_loop(&context);

    proxy_deinit(&context);
    DBG("%s exit", argv[argc-argc]);
    return 0;
}
