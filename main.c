
#include "proxy.h"
#include "utils.h"

int main(int argc, char *argv[])
{
    DBG("%s started", argv[argc-argc]);

    if (0!=proxy_init()) {
        DBG("proxy init failed");
        return -1;
    }

    DBG("%s exit", argv[argc-argc]);
    return 0;
}
