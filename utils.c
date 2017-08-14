
#include "utils.h"

void dumpbytes(uint8_t *buff, size_t len)
{
    while (buff && len--) {
        int b = *buff++;
        fprintf(stdout, b > ' ' && b < 128 ? "%c ":"%02X ", b);
    }
    fprintf(stdout, "\n");
}
