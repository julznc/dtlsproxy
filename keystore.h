#ifndef KEYSTORE_H
#define KEYSTORE_H

#include <sys/types.h>

#define KEYSTORE_RELEASE_REALM 0x01
#define KEYSTORE_RELEASE_ID    0x02
#define KEYSTORE_RELEASE_KEY   0x04

typedef enum credentials_type_t {
    KEYSTORE_UNKNOWN=0,
    KEYSTORE_PSK
} credentials_type_t ;

typedef struct keystore_psk_t {
    void *realm;
    size_t realm_length;
    void *identity;
    size_t identity_length;
    void *key;
    size_t key_length;
    int flags;
} keystore_psk_t;

typedef struct keystore_item_t {
    credentials_type_t type;
    struct keystore_item_t *next;
    union {
        keystore_psk_t psk;
    } entry;
} keystore_item_t;

typedef struct keystore_t {
    struct keystore_item_t *store;
} keystore_t;


keystore_t *new_keystore(void);
void free_keystore(keystore_t *keystore);

void keystore_free_item(keystore_item_t *item);
int keystore_store_item(keystore_t *keystore,
                        keystore_item_t *item);
void keystore_remove_item(keystore_t *keystore,
                          keystore_item_t *item);

keystore_item_t *keystore_new_psk(void *realm, size_t realm_length,
                                  void *id, size_t id_length,
                                  void *key, size_t key_length,
                                  int flags);

keystore_item_t *keystore_find_psk(const keystore_t *keystore,
                                   const void *realm, size_t realm_length,
                                   const void *id, size_t identity_length);

ssize_t psk_set_identity(const keystore_item_t *psk,
                         uint8_t *buf, size_t max_len);

ssize_t psk_set_key(const keystore_item_t *psk,
                    uint8_t *buf, size_t max_len);


#endif // KEYSTORE_H

