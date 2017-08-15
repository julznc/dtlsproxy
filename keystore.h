#ifndef KEYSTORE_H
#define KEYSTORE_H

#include <stdint.h>
#include <sys/types.h>

typedef struct keystore {
    struct keystore *next;
    const uint8_t *id;
    size_t id_length;
    const uint8_t *key;
    size_t key_length;
} keystore_t;


#endif // KEYSTORE_H

