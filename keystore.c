
#include <stdlib.h>
#include <string.h>

#include "keystore.h"
#include "utils.h"

keystore_t *new_keystore(char *psk_buf)
{
    keystore_t *head = (keystore_t *)malloc(sizeof(keystore_t));
    if (NULL==head) {
        ERR("failed to allocate keystore");
        return NULL;
    }
    memset(head, 0, sizeof(keystore_t));

    keystore_t *psk = head;
    char *ptr = (char*)psk_buf;
    char *psk_str = strtok_r((char*)psk_buf, ",", &ptr);
    while (psk_str) {
        char *sep = strchr(psk_str, ':');
        if (sep) {
            //DBG("psk_str=%s", psk_str);
            //sep = '\0';
            psk->id = (uint8_t*)psk_str;
            psk->id_length = sep-psk_str;
            psk->key = (uint8_t*)sep+1;
            psk->key_length = strlen(sep+1);
            psk->next = (keystore_t *)malloc(sizeof(keystore_t));
            if (NULL==psk->next) {
                ERR("failed to allocate keystore");
                return NULL;
            }
            psk = psk->next;
            memset(psk, 0, sizeof(keystore_t));
        }
        psk_str = strtok_r(NULL, ",", &ptr);
    }

    for (psk=head; psk && psk->id_length; psk=psk->next) {
        //psk->id[psk->id_length] = '\0';
        char *sep = strchr((char *)psk->id, ':');
        if (sep) {
            *sep = '\0';
        }
        //DBG("%s id=\"%s\", key=\"%s\"", __func__, psk->id, psk->key);
    }

    return head;
}

void free_keystore(keystore_t *keystore)
{
    while (keystore) {
        keystore_t *tmp = keystore;
        keystore = keystore->next;
        free(tmp);
    }
}
