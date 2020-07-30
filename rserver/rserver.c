#include "rserver.h"

#include <stdlib.h>
#include <string.h>

#include <p67/hash.h>

p67_err
p67rs_usermap_remove(
    p67rs_usermap_t * usermap,
    char * username)
{
    size_t usernamel = strlen(username);
    p67_hash_t hash = p67_hash_fn(
        (unsigned char *)username, usernamel, usermap->buffer_capacity);
    p67rs_usermap_entry_t * prev_entry = NULL, * entry;

    p67_spinlock_lock(&usermap->rwlock);

    for(entry = usermap->buffer[hash]; entry != NULL; entry=entry->next) {
        if(strlen(entry->username) == usernamel 
                    && (memcmp(username, entry->username, usernamel) == 0))
            break;
        prev_entry = entry;
    }

    if(entry == NULL) {
        p67_spinlock_unlock(&usermap->rwlock);
        return p67_err_enconn;
    }

    if(prev_entry == NULL) {
        usermap->buffer[hash] = NULL;
    } else {
        prev_entry->next = entry->next;
    }

    free(entry->username);
    free(entry);

    return 0;
}

const p67rs_usermap_entry_t *
p67rs_usermap_lookup(
    p67rs_usermap_t * usermap,
    char * username)
{
    size_t usernamel = strlen(username);
    p67_hash_t hash = p67_hash_fn(
        (unsigned char *)username, usernamel, usermap->buffer_capacity);
    p67rs_usermap_entry_t ** prev_entry, * entry;

    p67_spinlock_lock(&usermap->rwlock);

    for(prev_entry = usermap->buffer + hash; (entry = *prev_entry); prev_entry=&entry->next) {
        if(strlen(entry->username) == usernamel 
                    && (memcmp(username, entry->username, usernamel) == 0)) {
            p67_spinlock_unlock(&usermap->rwlock);
            return entry;
        }
    }
    
    p67_spinlock_unlock(&usermap->rwlock);
    return NULL;
}

p67rs_err
p67rs_usermap_add(
    p67rs_usermap_t * usermap,
    char * username, p67_sockaddr_t * saddr)
{
    if(usermap == NULL || usermap->buffer == NULL)
        return p67_err_einval;
    
    size_t usernamel = strlen(username);
    p67rs_usermap_entry_t ** prev_entry, * entry;

    p67_hash_t hash = p67_hash_fn(
        (unsigned char *)username, usernamel, usermap->buffer_capacity);

    p67_spinlock_lock(&usermap->rwlock);

    for(prev_entry = usermap->buffer + hash; (entry = *prev_entry); prev_entry=&entry->next) {
        if(strlen(entry->username) == usernamel 
                    && (memcmp(username, entry->username, usernamel) == 0)) {
            p67_spinlock_unlock(&usermap->rwlock);
            return p67_err_eaconn;
        }
    }
    
    if((*prev_entry = calloc(1, sizeof(**prev_entry))) == NULL) {
        p67_spinlock_unlock(&usermap->rwlock);
        return p67_err_eerrno;
    }

    entry = *prev_entry;

    if((entry->username = strdup(username)) == NULL) {
        free(*prev_entry);
        *prev_entry = NULL;
        p67_spinlock_unlock(&usermap->rwlock);
        return p67_err_eerrno;
    }

    entry->saddr = *saddr;
    entry->next = NULL;

    return 0;
}

void
p67rs_usermap_free(p67rs_usermap_t * usermap)
{
    if(usermap == NULL)
        free(usermap);

    free(usermap->buffer);
    free(usermap);
}

p67rs_err
p67rs_usermap_create(
    p67rs_usermap_t ** usermap,
    int usermap_capacity)
{
    p67rs_usermap_t * up;

    if(usermap == NULL)
        return p67_err_einval;

    if((up = calloc(1, sizeof(*up))) == NULL)
        return p67_err_eerrno;

    if(usermap_capacity <= 0)
        usermap_capacity = P67RS_DEFAULT_USERMAP_CAPACITY;

    up->buffer_capacity = usermap_capacity;

    if((up->buffer = calloc(
                usermap_capacity, 
                sizeof(*up->buffer))) == NULL) {
        free(up);
        return p67_err_eerrno;
    }

    *usermap = up;

    return 0;
}
