
#include <stdlib.h>
#include <string.h>

#include "utlist.h"
#include "keystore.h"

keystore_t *new_keystore(void)
{
    keystore_t *ks;

    ks = (keystore_t *)malloc(sizeof(keystore_t));
    if (ks) {
      memset(ks, 0, sizeof(keystore_t));
    }
    return ks;
}

void free_keystore(keystore_t *keystore) {
    keystore_item_t *item, *tmp;

    if (keystore) {
        LL_FOREACH_SAFE(keystore->store, item, tmp) {
            keystore_free_item(item);
        }
        free(keystore);
    }
}

static void free_psk(keystore_psk_t *psk) {
    if (psk) {
        if ((psk->flags & KEYSTORE_RELEASE_REALM) != 0) {
            free(psk->realm);
        }
        if ((psk->flags & KEYSTORE_RELEASE_ID) != 0) {
            free(psk->identity);
        }
        if ((psk->flags & KEYSTORE_RELEASE_KEY) != 0) {
            free(psk->key);
        }
    }
}

void keystore_free_item(keystore_item_t *item) {
    if (item) {
        switch (item->type) {
        case KEYSTORE_PSK: free_psk(&item->entry.psk); break;
        case KEYSTORE_UNKNOWN:
        default:
            break;
        }
        free(item);
    }
}

int keystore_store_item(keystore_t *keystore,
                        keystore_item_t *item)
{
    LL_PREPEND(keystore->store, item);
    return 1;
}

void keystore_remove_item(keystore_t *keystore,
                          keystore_item_t *item)
{
    LL_DELETE(keystore->store, item);
    keystore_free_item(item);
}

keystore_item_t *keystore_new_psk(void *realm, size_t realm_length,
                                  void *id, size_t id_length,
                                  void *key, size_t key_length,
                                  int flags)
{
    keystore_item_t *item;
    item = (keystore_item_t *)malloc(sizeof(keystore_item_t));

    if (item) {
        memset(item, 0, sizeof(keystore_item_t));
        item->type = KEYSTORE_PSK;
        item->entry.psk.realm = realm;
        item->entry.psk.realm_length = realm_length;
        item->entry.psk.identity = id;
        item->entry.psk.identity_length = id_length;
        item->entry.psk.key = key;
        item->entry.psk.key_length = key_length;
        item->entry.psk.flags = flags;
    }

    return item;
}

static inline int match(const void *a, size_t alen, const void *b, size_t blen)
{
    return !a || !b || ((alen == blen) && (memcmp(a, b, alen) == 0));
}

keystore_item_t * keystore_find_psk(const keystore_t *keystore,
                                    const void *realm, size_t realm_length,
                                    const void *identity, size_t identity_length)
{
    keystore_item_t *item;
  #define MATCH_PSK_FIELD(Field, Object)          \
    match((Field),                                \
          Field##_length,                         \
          (Object)->entry.psk.Field,              \
          (Object)->entry.psk.Field##_length)

    LL_FOREACH(keystore->store, item) {
      if (item->type == KEYSTORE_PSK) {
        if (MATCH_PSK_FIELD(realm, item) &&
            MATCH_PSK_FIELD(identity, item)) {
          return item;
        }
      }
    }
    return NULL;
}

ssize_t
psk_set_identity(const keystore_item_t *psk,
                 uint8_t *buf, size_t max_len)
{
    if (psk->type != KEYSTORE_PSK ||
        max_len < psk->entry.psk.identity_length) {
        return -1;
    }

    memcpy(buf, psk->entry.psk.identity, psk->entry.psk.identity_length);
    return psk->entry.psk.identity_length;
}

ssize_t psk_set_key(const keystore_item_t *psk,
                    uint8_t *buf, size_t max_len)
{
    if (psk->type != KEYSTORE_PSK ||
        max_len < psk->entry.psk.key_length) {
        return -1;
    }

    memcpy(buf, psk->entry.psk.key, psk->entry.psk.key_length);
    return psk->entry.psk.key_length;
}
