#ifndef _RIB_H
#define _RIB_H 1

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <Judy.h>

#include "prefixes.h"

struct rib;

struct rib_stats {
    unsigned n_prefixes;
    unsigned n_strides;
    unsigned mem_strides;
    unsigned mem_info;
    unsigned mem_total;
};

struct rib_lookup_results
{
    int matches;
    struct prefix_info *results[32];
};

struct rib *rib_new(struct rib_stats *external_stats);
struct prefix_info *rib_add(struct rib *rib, struct cidr cidr);
void rib_lookup(struct rib *rib, struct cidr cidr, struct rib_lookup_results *r);

typedef int (*rib_traverse_callback)(struct cidr cidr, struct prefix_info *info, void *user_data);
void rib_traverse(struct rib *rib, rib_traverse_callback cb, void *user_data);

void
rib_debug_print(struct rib *rib);

#endif
