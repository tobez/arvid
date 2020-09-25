#ifndef _ATTRS_H
#define _ATTRS_H 1

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <Judy.h>

struct arvid_opaque_attrs
{
    size_t len;
    char data[0];
} __attribute__((packed));

struct arvid_opaque_attrs_container;

struct arvid_opaque_attrs_container {
    struct arvid_opaque_attrs_container *next;
    struct arvid_opaque_attrs attrs;
} __attribute__((packed));

/* all attrs, hashed */
extern void *arvid_opaque_attrs_container_hash;

/* all attrs, linked */
extern struct arvid_opaque_attrs_container *arvid_opaque_attrs_container_list;

extern int arvid_attrs_count;
extern int arvid_attrs_bytes;

struct arvid_opaque_attrs *
add_attrs(size_t len, void *attrs);

/* XXX debug printing, saving, loading */

#endif
