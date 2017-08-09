#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdarg.h>

#define DBG(fmt, ...)  printf("%s[%d] " fmt "\n", __FILE__, __LINE__, ## __VA_ARGS__)

#endif // UTILS_H
