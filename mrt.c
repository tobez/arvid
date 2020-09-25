#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "carp.h"
#include "mempool.h"
#include "peers.h"
#include "attrs.h"
#include "prefixes.h"
#include "mrt.h"
#include "bgp.h"

#define TABLE_DUMP_V2 13
#define BGP4MP 16
#define PEER_INDEX_TABLE 1
#define RIB_IPV4_UNICAST 2
#define BGP4MP_MESSAGE_AS4 4
/*
Помимо всего прочего, поздравляю всех с тем, что вы дожили до материализации шутки "Не работает ларёк, потому что Рагнарёк".

            BGP4MP           16          See Section 4.4
            BGP4MP_ET        17          See Section 4.4

   This document defines the following message Subtype Codes for the
   BGP4MP Type:

            Name                     Value       Definition
            ----                     -----       ----------
            BGP4MP_STATE_CHANGE      0           See Section 4.4
            BGP4MP_MESSAGE           1           See Section 4.4
            BGP4MP_ENTRY             2           See Section 4.4
            BGP4MP_SNAPSHOT          3           See Section 4.4
            BGP4MP_MESSAGE_AS4       4           See Section 4.4
            BGP4MP_STATE_CHANGE_AS4  5           See Section 4.4
            BGP4MP_MESSAGE_LOCAL     6           See Section 4.4
            BGP4MP_MESSAGE_AS4_LOCAL 7           See Section 4.4
 */

/* htobe32() implementation for Mac stolen from https://gist.github.com/yinyin/2027912 */
/* Why oh why did not I just use htonl()?? */
#ifndef __APPLE__
#include <sys/endian.h>
#else
#include <libkern/OSByteOrder.h>
#define htobe16(x) OSSwapHostToBigInt16(x)
#define htole16(x) OSSwapHostToLittleInt16(x)
#define be16toh(x) OSSwapBigToHostInt16(x)
#define le16toh(x) OSSwapLittleToHostInt16(x)

#define htobe32(x) OSSwapHostToBigInt32(x)
#define htole32(x) OSSwapHostToLittleInt32(x)
#define be32toh(x) OSSwapBigToHostInt32(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)

#define htobe64(x) OSSwapHostToBigInt64(x)
#define htole64(x) OSSwapHostToLittleInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#define le64toh(x) OSSwapLittleToHostInt64(x)
#endif

struct input_buf
{
    char *input;
    char *ptr;
    size_t size;
    size_t len;
};

struct globals {
    FILE *file;
    char *file_name;
    struct input_buf file_buf;
};

/**** MRT records *****/

struct mrt_common_header {
    uint32_t ts;
    uint16_t type;
    uint16_t subtype;
    uint32_t length;
};

struct mrt_peer_entry {
    uint8_t is_ipv6;
    in_addr_t bgp_id;
    in_addr_t peer_ipv4;
    uint32_t peer_asn;
};

struct mrt_peer_index_table {
    struct mrt_common_header *ch;
    in_addr_t bgp_id;
    char    *view_name;
    uint16_t peer_count;
    struct mrt_peer_entry *peers;
};

struct mrt_rib_entry {
    uint16_t peer_index;
    uint32_t originated_time;
    uint16_t attr_len;
    char *attrs;
};

struct mrt_rib_ipv4_unicast {
    struct mrt_common_header *ch;
    uint32_t sequence_number;
    struct cidr nlri;
    uint16_t entry_count;
    struct mrt_rib_entry *entries;
};

struct globals G;

/************* Actual MRT code **********/

void
open_mrt(char *fname)
{
    FILE *f;

    if (current_arvid_peers) {
        free(current_arvid_peers);
        current_arvid_peers = NULL;
        current_arvid_peers_length = 0;
    }

    if (strcmp(fname, "-") == 0) {
        f = stdin;
        fname = "stdin";
    } else {
        f = fopen(fname, "r");
    }
    if (!f)
        croak(1, "open %s", fname);
    G.file = f;
    G.file_name = strdup(fname);

    G.file_buf.size = 300000;
    G.file_buf.input = malloc(G.file_buf.size);
    if (!G.file_buf.input)
        croak(1, "malloc file_buf");
    G.file_buf.ptr = G.file_buf.input;
    G.file_buf.len = 0;
}

static void
compactify_file_buf(void)
{
    size_t spent = G.file_buf.ptr - G.file_buf.input;
    if (!spent) return;
    memmove(G.file_buf.input, G.file_buf.ptr, G.file_buf.len - spent);
    G.file_buf.len -= spent;
    G.file_buf.ptr = G.file_buf.input;
}

static int
read_bytes(size_t n, void *dst)
{
    size_t spent = G.file_buf.ptr - G.file_buf.input;

    if (G.file_buf.len - spent < n) {
        /* need to read more bytes */
        compactify_file_buf();

        size_t nr = fread(G.file_buf.input + G.file_buf.len, 1, G.file_buf.size - G.file_buf.len, G.file);
        G.file_buf.len += nr;

        if (G.file_buf.len < n) {
            if (G.file_buf.len == 0 && feof(G.file))
                return 0;   /* nothing there and legitimate eof, so might not be an error */
            if (feof(G.file)) {
                errno = EFTYPE;
                return -1;
            }
            return -1;
        }
    }

    memcpy(dst, G.file_buf.ptr, n);
    G.file_buf.ptr += n;

    return n;
}

static int
read_uint8(uint8_t *r)
{
    uint8_t rr;
    int res;
    res = read_bytes(1, &rr);
    if (res <= 0)   return res;
    *r = rr;
    return res;
}

static int
read_uint16be(uint16_t *r)
{
    uint16_t rr;
    int res;
    res = read_bytes(2, &rr);
    if (res <= 0)   return res;
    *r = be16toh(rr);
    return res;
}

static int
read_uint32be(uint32_t *r)
{
    uint32_t rr;
    int res;
    res = read_bytes(4, &rr);
    if (res <= 0)   return res;
    *r = be32toh(rr);
    return res;
}

static uint8_t
get_uint8(void)
{
    uint8_t r;

    switch (read_uint8(&r)) {
    case 0:
        croakx(1, "read_uint8: unexpected end of file");
    case -1:
        croak(1, "read_uint8");
    }

    return r;
}

static uint16_t
get_uint16be(void)
{
    uint16_t r;

    switch (read_uint16be(&r)) {
    case 0:
        croakx(1, "read_uint16be: unexpected end of file");
    case -1:
        croak(1, "read_uint16be");
    }

    return r;
}

static uint32_t
get_uint32be(void)
{
    uint32_t r;

    switch (read_uint32be(&r)) {
    case 0:
        croakx(1, "read_uint32be: unexpected end of file");
    case -1:
        croak(1, "read_uint32be");
    }

    return r;
}

static char *
get_string_n(size_t n)
{
    char *r = getmem_temp(n+1);

    if (n > 0) {
        switch (read_bytes(n, r)) {
        case 0:
            croakx(1, "get_string_n(%d): unexpected end of file", n);
        case -1:
            croak(1, "get_string_n(%d)", n);
        }
    }

    r[n] = 0;
    return r;
}

static struct cidr
get_nlri(void)
{
    struct cidr nlri;
    int bytes;
    uint8_t buf[4];
    int i;
    in_addr_t mask = 0xffffffff;

    nlri.ip = 0;
    nlri.bits = get_uint8();
    bytes = (7 + nlri.bits) / 8;

    if (nlri.bits > 32)
        croakx(1, "get_nlri: prefix length too large: %u", nlri.bits);

    if (bytes > 0) {
        switch (read_bytes(bytes, buf)) {
        case 0:
            croakx(1, "get_nlri: unexpected end of file");
        case -1:
            croak(1, "get_nlri");
        }
    }

    for (i = 0; i < bytes; i++) {
        nlri.ip <<= 8;
        nlri.ip |= buf[i];
    }
    for (i = bytes; i < 4; i++) {
        nlri.ip <<= 8;
    }
    mask <<= 32 - nlri.bits;
    nlri.ip &= mask;
    nlri.ip = htonl(nlri.ip);

    return nlri;
}

struct mrt_peer_entry *
handle_peer_entry(int n, struct mrt_peer_entry *e)
{
    uint8_t flags = get_uint8();

    e->bgp_id     = htonl(get_uint32be());
fprintf(stderr, "%d: bgp id %s\n", n, ip2a(e->bgp_id));
    if (flags & 0x01) {
        e->is_ipv6 = 1;
        croakx(1, "handle_peer_entry: ipv6 not supported");
    } else {
        e->is_ipv6 = 0;
        e->peer_ipv4 = htonl(get_uint32be());
fprintf(stderr, "%d: ip %s\n", n, ip2a(e->peer_ipv4));
    }
    if (flags & 0x02) {
        e->peer_asn = get_uint32be();
    } else {
        e->peer_asn = get_uint16be();
    }
fprintf(stderr, "%d: asn %u\n", n, e->peer_asn);

    return e;
}

struct mrt_peer_index_table *
handle_peer_index_table(struct mrt_common_header *ch)
{
    struct mrt_peer_index_table *t = getmem_temp(sizeof(struct mrt_peer_index_table));
    int i;
    struct arvid_peer peer;

    t->ch         = ch;
    t->bgp_id     = htonl(get_uint32be());
    t->view_name  = get_string_n(get_uint16be());
    t->peer_count = get_uint16be();
    t->peers      = getmem_temp(t->peer_count * sizeof(struct mrt_peer_entry));

    printf("Peer index table %s \"%s\" %hu\n", ip2a(t->bgp_id), t->view_name, t->peer_count);
    current_arvid_peers = malloc(t->peer_count * sizeof(*current_arvid_peers));
    if (!current_arvid_peers)
        croak(1, "handle_peer_index_table: malloc(current_arvid_peers)");
    current_arvid_peers_length = t->peer_count;
    for (i = 0; i < t->peer_count; i++) {
        handle_peer_entry(i, &(t->peers[i]));
        memset(&peer, 0, sizeof(peer));
        peer.peer_ipv4 = t->peers[i].peer_ipv4;
        peer.bgp_id = t->peers[i].bgp_id;
        peer.peer_asn = t->peers[i].peer_asn;
        current_arvid_peers[i] = add_peer(&peer);
    }

    return t;
}

struct mrt_rib_entry *
handle_rib_entry(struct mrt_rib_ipv4_unicast *mrt_rib, struct mrt_rib_entry *e)
{
    struct arvid_opaque_attrs *attrs, **attrs_slot;
    struct arvid_peer *peer;
    struct prefix_info *pi;
    // struct bgp_attr_container *ba;

    e->peer_index      = get_uint16be();
    e->originated_time = get_uint32be();
    e->attr_len        = get_uint16be();
    e->attrs           = get_string_n(e->attr_len);

    // ba = parse_bgp_attrs(e->attr_len, e->attrs, 4);

    if (e->peer_index >= current_arvid_peers_length) {
        croakx(1, "handle_rib_entry: peer index %hu is out of bound (current arvid peers length is %hu)\n",
               e->peer_index, current_arvid_peers_length);
    }
    peer = current_arvid_peers[e->peer_index];

    attrs = add_attrs(e->attr_len, e->attrs);
    pi = rib_add(peer->rib, mrt_rib->nlri);
    peer->n_add_prefix++;

    /* XXX TODO if largest time has same attribute, do nothing I THINK */
    JLI(attrs_slot, pi->by_time, e->originated_time);
    if (attrs_slot == PJERR)
        croakx(1, "handle_rib_entry: JLI(time)");
    *attrs_slot = attrs;

    return e;
}

struct mrt_rib_ipv4_unicast *
handle_rib_ipv4_unicast(struct mrt_common_header *ch)
{
    struct mrt_rib_ipv4_unicast *t = getmem_temp(sizeof(struct mrt_rib_ipv4_unicast));

    t->ch              = ch;
    t->sequence_number = get_uint32be();
    t->nlri            = get_nlri();
    t->entry_count     = get_uint16be();
    t->entries         = getmem_temp(t->entry_count * sizeof(struct mrt_rib_entry));

    // printf("RIB IPv4 unicast %s/%d %hu\n", ip2a(t->nlri.ip), t->nlri.bits, t->entry_count);
    for (int i = 0; i < t->entry_count; i++) {
        handle_rib_entry(t, &(t->entries[i]));
    }

    return t;
}

void *
handle_table_dump_v2(struct mrt_common_header *ch)
{
    switch (ch->subtype) {
    case PEER_INDEX_TABLE:
        return handle_peer_index_table(ch);
    case RIB_IPV4_UNICAST:
        return handle_rib_ipv4_unicast(ch);
    default:
        croakx(1, "unrecognized or unsupported table dump v2 subtype %hu\n", ch->subtype);
    }

    return NULL;
}

int
read_mrt_record(void)
{
    uint32_t ts;
    struct mrt_common_header *ch;

    freeall_temp();

    switch (read_uint32be(&ts)) {
    case 0:
        return 0;
    case -1:
        croak(1, "read_uint32be");
    }

    ch = getmem_temp(sizeof(*ch));
    ch->ts      = ts;
    ch->type    = get_uint16be();
    ch->subtype = get_uint16be();
    ch->length  = get_uint32be();
    // printf("HDR ts:%u t:%hu st:%hu l:%u\n", ch->ts, ch->type, ch->subtype, ch->length);

    switch (ch->type) {
    case TABLE_DUMP_V2:
        handle_table_dump_v2(ch); // XXX what to do with the result
        return 1;
    default:
        croakx(1, "unrecognized or unsupported MRT record type %hu\n", ch->type);
    }

    return 0;
}

