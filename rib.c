#include <string.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <netinet/in.h>

#include "carp.h"
#include "rib.h"

struct rib_stride
{
    uint32_t prefix_bitmap[512/32];  /* 512 bits (511, in reality) */
    uint32_t stride_bitmap[256/32];  /* 256 bits */
    /* Pointer to the information we chose to keep
     * for prefixes in this stride - up to 511.
     * It can be a next hop information, or geograpical destination,
     * or an AS number, or some more complicated structure. */
    struct prefix_info *info;
    /* array of pointers to child strides, up to 256 */
    struct rib_stride *children[1];
};

struct rib
{
    struct rib_stride *root;
    struct rib_stats *stats;
#ifdef RIB_DEBUG
    void *debug_prefixes;
#endif
};

/* does not copy children array! */
static struct rib_stride *
stride_copy(struct rib_stride *o, int children)
{
    int alloc_size = sizeof(struct rib_stride) + sizeof(struct rib_stride *)*(children - 1);
    struct rib_stride *s = malloc(alloc_size);
    if (!s)
        croak(18, "stride_copy: malloc(rib_stride)");
    memset(s, 0, alloc_size);
    if (o) {
        memcpy(&s->prefix_bitmap, &o->prefix_bitmap, 512/8);
        memcpy(&s->stride_bitmap, &o->stride_bitmap, 256/8);
        s->info = o->info;
    }
    return s;
}

#define BIT(ary, pos) \
    ary[(pos) >> 5] & (1 << ((pos) & 0x1F))
#define SET(ary, pos) \
    ary[(pos) >> 5] |= (1 << ((pos) & 0x1F))
#define CLEAR(ary, pos) \
    ary[(pos) >> 5] &= ~(1 << ((pos) & 0x1F))

static inline int
n_prefixes(struct rib_stride *s)
{
    int cnt = 0;
    int i;

    for (i = 0; i < 512/32; i++)
        cnt += __builtin_popcount(s->prefix_bitmap[i]);
    return cnt;
}

static inline int
prefix_index(struct rib_stride *s, uint32_t pos)
{
    int cnt = 0;
    uint32_t last_word = pos >> 5;
    uint32_t last_mask = 0xffffffff >> (31 - (pos & 0x1F));
    int i;

    for (i = 0; i < last_word; i++)
        cnt += __builtin_popcount(s->prefix_bitmap[i]);
    cnt += __builtin_popcount(s->prefix_bitmap[last_word] & last_mask);
    return cnt-1;
}

static inline int
n_children(struct rib_stride *s)
{
    int cnt = 0;
    int i;

    for (i = 0; i < 256/32; i++)
        cnt += __builtin_popcount(s->stride_bitmap[i]);
    return cnt;
}

static inline int
child_index(struct rib_stride *s, uint32_t pos)
{
    int cnt = 0;
    uint32_t last_word = pos >> 5;
    uint32_t last_mask = 0xffffffff >> (31 - (pos & 0x1F));
    int i;

    for (i = 0; i < last_word; i++)
        cnt += __builtin_popcount(s->stride_bitmap[i]);
    cnt += __builtin_popcount(s->stride_bitmap[last_word] & last_mask);
    return cnt-1;
}

static struct prefix_info *
add_prefix(struct rib *rib, struct rib_stride **strideptr, uint32_t ip, int bits)
{
    uint8_t mask = 0xff;
    int with_children = bits > 8;
    int l = 8;
    struct rib_stride *subtree = *strideptr;
	struct prefix_info *to_return = NULL;

    if (!with_children) {
        mask = ~(mask >> bits);
        l = bits;
    }
    uint8_t o = ((ip >> 24) & 0xff) & mask;
    uint32_t ppbase = (1 << l) - 1;
    uint32_t ppord = o >> (8-l);
    uint32_t pp = ppbase + ppord;

    if (BIT(subtree->prefix_bitmap, pp)) {
        if (!with_children) {
            to_return = &subtree->info[prefix_index(subtree, pp)];
        }
    } else {
        if (!with_children) {
            int n_info, idx;
            struct prefix_info *new_info;

            SET(subtree->prefix_bitmap, pp);
            n_info = n_prefixes(subtree);
            idx = prefix_index(subtree, pp);
            new_info = malloc(n_info*sizeof(struct prefix_info));
            if (!new_info)
                croak(18, "add_prefix: malloc(n * prefix_info)");
            memset(new_info, 0, n_info*sizeof(struct prefix_info));
            if (subtree->info) {
                if (idx > 0)
                    memcpy(new_info, subtree->info, idx*sizeof(struct prefix_info));
                if (idx + 1 < n_info)
                    memcpy(new_info+idx+1, subtree->info+idx, (n_info-idx-1)*sizeof(struct prefix_info));
            }
            to_return = &new_info[idx];
            free(subtree->info);
            subtree->info = new_info;

            rib->stats->mem_info += sizeof(struct prefix_info);
            rib->stats->mem_total = rib->stats->mem_strides + rib->stats->mem_info;
            rib->stats->n_prefixes++;
        }
    }

    if (with_children) {
        if (BIT(subtree->stride_bitmap, o)) {
            int idx;

            idx = child_index(subtree, o);

            /* recurse into children */
            to_return = add_prefix(rib, &(subtree->children[idx]), ip << 8, bits - 8);
        } else {
            struct rib_stride *child;
            int n_kids, idx;

            SET(subtree->stride_bitmap, o);
            n_kids = n_children(subtree);
            idx = child_index(subtree, o);
            child = stride_copy(NULL, 0);
            /* reallocating this stride to expand array of children */
            *strideptr = stride_copy(subtree, n_kids);
            if (idx > 0)
                memcpy(&((*strideptr)->children[0]), &(subtree->children[0]), idx*sizeof(struct rib_stride *));
            if (idx + 1 < n_kids)
                memcpy(&((*strideptr)->children[idx+1]), &(subtree->children[idx]), (n_kids-idx-1)*sizeof(struct rib_stride *));
            (*strideptr)->children[idx] = child;
            free(subtree);
            subtree = *strideptr;

            rib->stats->mem_strides += sizeof(struct rib_stride *);  /* new stride pointer in this stride */
            rib->stats->mem_strides += sizeof(struct rib_stride) - sizeof(struct rib_stride *); /* new empty stride */
            rib->stats->mem_total = rib->stats->mem_strides + rib->stats->mem_info;
            rib->stats->n_strides++;

            /* recurse into children */
            to_return = add_prefix(rib, &(subtree->children[idx]), ip << 8, bits - 8);
        }
    }

    if (!to_return)
        croak(18, "add_prefix: internal: info not set");

    return to_return;
}

struct prefix_info *
rib_add(struct rib *rib, struct cidr cidr)
{
#ifdef RIB_DEBUG
    int rc;
    Word_t index = cidr.bits;
    index <<= 32;
    index |= ntohl(cidr.ip);
    J1S(rc, rib->debug_prefixes, index);
#endif
    return add_prefix(rib, &rib->root, ntohl(cidr.ip), cidr.bits);
}

void
rib_debug_print(struct rib *rib)
{
    Word_t cnt;

    fprintf(stderr, "{ \"n_prefixes\":%u", rib->stats->n_prefixes);
#ifdef RIB_DEBUG
    J1C(cnt, rib->debug_prefixes, 0, -1);
    fprintf(stderr, ", \"n_debug_prefixes\":%lu", cnt);
#endif
    fprintf(stderr, ", \"n_strides\":%u", rib->stats->n_strides);
    fprintf(stderr, ", \"mem_strides\":%u", rib->stats->mem_strides);
    fprintf(stderr, ", \"mem_info\":%u", rib->stats->mem_info);
    fprintf(stderr, ", \"mem_total\":%u", rib->stats->mem_total);
    fprintf(stderr, " }\n");
}

struct rib *
rib_new(struct rib_stats *external_stats)
{
    struct rib *rib;

    rib = malloc(sizeof(*rib));
    if (!rib)
        croak(18, "rib_new: malloc(rib)");
    memset(rib, 0, sizeof(*rib));

    rib->root = stride_copy(NULL, 0);
    if (!external_stats) {
        rib->stats = malloc(sizeof(*rib->stats));
        if (!rib->stats)
            croak(18, "rib_new: malloc(stats)");
    } else {
        rib->stats = external_stats;
    }

    rib->stats->n_prefixes = 0;
    rib->stats->n_strides = 1;
    rib->stats->mem_strides =
        sizeof(struct rib_stride) - sizeof(struct rib_stride *);
    rib->stats->mem_info = 0;
    rib->stats->mem_total =
        rib->stats->mem_strides + rib->stats->mem_info;

    return rib;
}
