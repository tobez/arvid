#include <string.h>
#include <netinet/in.h>
#include <stdio.h>

#include "mempool.h"
#include "carp.h"
#include "util.h"
#include "prefixes.h"
#include "bgp.h"

#define USING_AS_WIDTH \
    int as_width = 0; \
    if (input_as_width == 0) { \
        if (flags & BGP_FLAG_ARVID_2) \
            as_width = 2; \
        else if (flags & BGP_FLAG_ARVID_4) \
            as_width = 4; \
        else \
            croakx(2, "parse_bgp_attrs: internal: input_as_width is 0, but no arvid flag set"); \
     } else \
        as_width = input_as_width

struct bgp_attr_container*
parse_bgp_attrs(size_t len, void *attrs, int input_as_width)
{
    uint8_t *buf = (uint8_t *)attrs;
    uint8_t *input_buf = buf;
    size_t input_len = len;
    struct bgp_attr_container *type2attr[256];
    struct bgp_attr_container *r = NULL;
    char *debug;
    int has_32bit_as = 0;

    memset(type2attr, 0, 256 * sizeof(struct bgp_attr_container *));

    if (input_as_width != 2 && input_as_width != 4 && input_as_width != 0)
        croakx(2, "parse_bgp_attrs: internal: input_as_width must be 0 or 2 or 4");

    while (len > 0) {
        uint8_t flags = buf[0];
        uint8_t type;
        uint16_t alen;

        if (flags & BGP_FLAG_EXTENDED_LENGTH) {
            if (len < 4)
                croakx(2, "parse_bgp_attrs: attrs too short for an extended length attribute");
            alen = ntohs(*((uint16_t *)(buf + 2)));
            type = buf[1];

            buf += 4;
            len -= 4;
        } else {
            if (len < 3)
                croakx(2, "parse_bgp_attrs: attrs too short for a normal length attribute");
            alen = buf[2];
            type = buf[1];

            buf += 3;
            len -= 3;
        }

        if (len < alen) {
            debug = buf2hex(input_buf, input_len);
            croakx(2,
                   "parse_bgp_attrs: attrs too short for attribute %u data of length "
                   "%hu:\n%s\n",
                   type, alen, debug);
            free(debug);
        }

        if (type2attr[type])
            croakx(2,
                   "parse_bgp_attrs: multiple attributes of the same type (%u) "
                   "are not supported\n",
                   type);

        switch (type) {

        case BGP_ATTR_ORIGIN: {
            struct bgp_attr_origin *o = getmem_temp(sizeof(*o));
            o->h.flags = flags & (~BGP_FLAG_ARVID);
            o->h.type = type;
            o->origin = buf[0];

            if (alen != 1)
                croakx(2, "parse_bgp_attrs: ORIGIN attr len is not 1 but %u",
                       alen);

            type2attr[type] = getmem_temp(sizeof(struct bgp_attr_container));
            type2attr[type]->next = NULL;
            type2attr[type]->attr = (union bgp_attr *)o;
        } break;

        case BGP_ATTR_AS_PATH: {
            struct bgp_attr_as_path *p = getmem_temp(sizeof(*p));
            struct bgp_as_path_segment *last_seg = NULL;
            USING_AS_WIDTH;

            p->h.flags = flags & (~BGP_FLAG_ARVID);
            p->h.type = type;
            p->bytes16 = 2;  /* flags + type */
            p->bytes32 = 2;  /* flags + type */

            while (alen > 2) {
                uint8_t seg_type = buf[0];
                uint8_t seg_len =  buf[1];
                struct bgp_as_path_segment *seg = getmem_temp(sizeof(struct bgp_as_path_segment) + seg_len * 4);
                int i;

                alen -= 2;
                len -= 2;
                buf += 2;

                p->bytes16 += 2;  /* seg_type + seg_len */
                p->bytes32 += 2;  /* seg_type + seg_len */

                p->bytes16 += seg_len * 2;  /* seg_len 16-bit ASNs */
                p->bytes32 += seg_len * 4;  /* seg_len 32-bit ASNs */

                /* XXX assert seg_type BGP_AS_PATH_AS_SET or BGP_AS_PATH_AS_SEQUENCE */

                if (alen < seg_len * as_width)
                    croakx(2, "parse_bgp_attrs: attrs too short to fit AS SEGMENT of length %u",
                           seg_len);

                seg->seg_type = seg_type;
                seg->seg_len = seg_len;
                seg->next = NULL;

                if (last_seg)
                    last_seg->next = seg;
                else
                    p->seg = seg;
                last_seg = seg;

if (seg_type == BGP_AS_PATH_AS_SET)
    fprintf(stderr, "AS_SET: ");
else
    fprintf(stderr, "AS_SEQUENCE: ");

                if (as_width == 2) {
                    for (i = 0; i < seg_len; i++) {
                        seg->as[i] = ntohs(*((uint16_t *)buf));
                        alen -= 2;
                        len -= 2;
                        buf += 2;
fprintf(stderr, "%u ", seg->as[i]);
                    }
                } else {
                    for (i = 0; i < seg_len; i++) {
                        seg->as[i] = ntohl(*((uint32_t *)buf));
                        alen -= 4;
                        len -= 4;
                        buf += 4;
                        if (seg->as[i] > 65535)
                            has_32bit_as++;
fprintf(stderr, "%u ", seg->as[i]);
                    }
                }

fprintf(stderr, "\n");

                if (seg_type == BGP_AS_PATH_AS_SET) {
                    /* XXX sort AS_SET */
                }
            }

fprintf(stderr, "^^^ (%s-bit ASNs)\n", has_32bit_as ? "32" : "16");

            if (alen != 0)
                croakx(2, "parse_bgp_attrs: AS_PATH attr: %u extra bytes",
                       alen);

            type2attr[type] = getmem_temp(sizeof(struct bgp_attr_container));
            type2attr[type]->next = NULL;
            type2attr[type]->attr = (union bgp_attr *)p;

            p->h.flags |= (has_32bit_as ? BGP_FLAG_ARVID_4 : BGP_FLAG_ARVID_2);
        } break;

        case BGP_ATTR_NEXT_HOP: {
            struct bgp_attr_next_hop *n = getmem_temp(sizeof(*n));
            n->h.flags = flags & (~BGP_FLAG_ARVID);
            n->h.type = type;

            if (alen != 4)
                croakx(2, "parse_bgp_attrs: NEXT_HOP attr len is not 4 but %u",
                       alen);

            n->next_hop = *((in_addr_t *)buf);

fprintf(stderr, "NEXT_HOP %s\n", ip2a(n->next_hop));

            type2attr[type] = getmem_temp(sizeof(struct bgp_attr_container));
            type2attr[type]->next = NULL;
            type2attr[type]->attr = (union bgp_attr *)n;
        } break;

        case BGP_ATTR_MULTI_EXIT_DISC: {
            struct bgp_attr_multi_exit_disc *med = getmem_temp(sizeof(*med));
            med->h.flags = flags & (~BGP_FLAG_ARVID);
            med->h.type = type;

            if (alen != 4)
                croakx(2, "parse_bgp_attrs: MULTI_EXIT_DISC attr len is not 4 but %u",
                       alen);

            med->med = ntohl(*((uint32_t *)buf));

            type2attr[type] = getmem_temp(sizeof(struct bgp_attr_container));
            type2attr[type]->next = NULL;
            type2attr[type]->attr = (union bgp_attr *)med;
            med->h.flags |= (med->med > 65535 ? BGP_FLAG_ARVID_4 : BGP_FLAG_ARVID_2);
        } break;

        case BGP_ATTR_COMMUNITIES: {
            int i;
            struct bgp_attr_communities *c = getmem_temp(sizeof(*c) + sizeof(uint32_t)*(alen / 4));
            c->h.flags = flags & (~BGP_FLAG_ARVID);
            c->h.type = type;

            if (alen % 4 != 0)
                croakx(2, "parse_bgp_attrs: COMMUNITIES attribute size alignment problem");

fprintf(stderr, "COMMUNITIES: ");
            for (i = 0; i < alen / 4; i++) {
                c->communities[i] = ntohl(*((uint32_t *)(buf + i*4)));

fprintf(stderr, "%u:%u ", (c->communities[i] & 0xffff0000) >> 16, c->communities[i] & 0x0000ffff);
            }
fprintf(stderr, "\n");

            type2attr[type] = getmem_temp(sizeof(struct bgp_attr_container));
            type2attr[type]->next = NULL;
            type2attr[type]->attr = (union bgp_attr *)c;
        } break;

        case BGP_ATTR_ATOMIC_AGGREGATE: {
            struct bgp_attr_atomic_aggregate *aa = getmem_temp(sizeof(*aa));
            aa->h.flags = flags & (~BGP_FLAG_ARVID);
            aa->h.type = type;

            if (alen != 0)
                croakx(2, "parse_bgp_attrs: ATOMIC_AGGREGATE attr len is not 0 but %u",
                       alen);

            type2attr[type] = getmem_temp(sizeof(struct bgp_attr_container));
            type2attr[type]->next = NULL;
            type2attr[type]->attr = (union bgp_attr *)aa;
        } break;

		case BGP_ATTR_AGGREGATOR: {
            struct bgp_attr_aggregator *a = getmem_temp(sizeof(*a));
            a->h.flags = flags & (~BGP_FLAG_ARVID);
            a->h.type = type;

            if (alen == 6) {
				a->as = ntohs(*((uint16_t *)buf));
				alen -= 2;
				len -= 2;
				buf += 2;
			} else if (alen == 8) {
				a->as = ntohl(*((uint32_t *)buf));
				alen -= 4;
				len -= 4;
				buf += 4;
			} else
                croakx(2, "parse_bgp_attrs: AGGREGATOR attr len is %u",
                       alen);

            a->speaker = *((in_addr_t *)buf);

fprintf(stderr, "AGGREGATOR %u/%s\n", a->as, ip2a(a->speaker));

            type2attr[type] = getmem_temp(sizeof(struct bgp_attr_container));
            type2attr[type]->next = NULL;
            type2attr[type]->attr = (union bgp_attr *)a;
            a->h.flags |= (a->as > 65535 ? BGP_FLAG_ARVID_4 : BGP_FLAG_ARVID_2);
		} break;

        default:
            debug = buf2hex(input_buf, input_len);
            croakx(2,
                   "parse_bgp_attrs: attribute type %u "
                   "is not supported\n%s\n",
                   type, debug);
            free(debug);
        }

        buf += alen;
        len -= alen;
    }

    for (int i = 255; i >= 0; i--) {
        if (type2attr[i]) {
            type2attr[i]->next = r;
            r = type2attr[i];
        }
    }

    return r;
}

