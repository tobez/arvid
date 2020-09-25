#include <stdlib.h>
#include <string.h>

#include <Judy.h>

#include "carp.h"
#include "attrs.h"

int arvid_attrs_count = 0;
int arvid_attrs_bytes = 0;
void *arvid_opaque_attrs_container_hash = NULL;
struct arvid_opaque_attrs_container *arvid_opaque_attrs_container_list = NULL;

struct arvid_opaque_attrs *
add_attrs(size_t len, void *oa)
{
    struct arvid_opaque_attrs_container **slot;
    struct arvid_opaque_attrs_container *container;

    JHSI(slot, arvid_opaque_attrs_container_hash, oa, len);
    if (slot == PJERR)
        croak(16, "add_attrs: JHSI failed");
    if (*slot)
        return &((*slot)->attrs);

    container = malloc(sizeof(*container) + len);
    if (!container)
        croak(16, "add_attrs: malloc(container)");

    container->attrs.len = len;
    memcpy(container->attrs.data, oa, len);
    container->next = arvid_opaque_attrs_container_list;
    arvid_opaque_attrs_container_list = container;

    *slot = container;
    arvid_attrs_count++;
    arvid_attrs_bytes += sizeof(*container) + len;

    return &container->attrs;
}
