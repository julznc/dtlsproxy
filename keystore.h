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


// psk_buf = "id1:key1,id2:key2,...,idN:keyN"
keystore_t *new_keystore(char *psk_buf);

void free_keystore(keystore_t *keystore);

#endif // KEYSTORE_H

