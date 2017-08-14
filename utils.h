#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <sys/types.h>

#define DBG(fmt, ...)  fprintf(stdout, "%s[%d] " fmt "\n", __FILE__, __LINE__, ## __VA_ARGS__)
#define ERR(fmt, ...)  fprintf(stderr, "%s[%d] ERR " fmt "\n", __FILE__, __LINE__, ## __VA_ARGS__)

void dumpbytes(uint8_t *buff, size_t len);

#endif // UTILS_H
