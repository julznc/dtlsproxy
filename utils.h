#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdarg.h>

#define DBG(fmt, ...)  fprintf(stdout, "%s[%d] " fmt "\n", __FILE__, __LINE__, ## __VA_ARGS__)
#define ERR(fmt, ...)  fprintf(stderr, "%s[%d] ERR " fmt "\n", __FILE__, __LINE__, ## __VA_ARGS__)

#endif // UTILS_H
