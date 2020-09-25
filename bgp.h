#ifndef _BGP_H
#define _BGP_H 1

#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BGP_ATTR_ORIGIN 1
#define BGP_ATTR_AS_PATH 2
#define BGP_ATTR_NEXT_HOP 3
#define BGP_ATTR_MULTI_EXIT_DISC 4
#define BGP_ATTR_LOCAL_PREF 5
#define BGP_ATTR_ATOMIC_AGGREGATE 6
#define BGP_ATTR_AGGREGATOR 7
#define BGP_ATTR_COMMUNITIES 8

#define BGP_FLAG_OPTIONAL 0x80
#define BGP_FLAG_TRANSITIVE 0x40
#define BGP_FLAG_PARTIAL 0x20
#define BGP_FLAG_EXTENDED_LENGTH 0x10

/* Our own attr flags */
#define BGP_FLAG_ARVID_2 0x02
#define BGP_FLAG_ARVID_4 0x04
#define BGP_FLAG_ARVID   (BGP_FLAG_ARVID_2 | BGP_FLAG_ARVID_4)

#define BGP_AS_PATH_AS_SET 1
#define BGP_AS_PATH_AS_SEQUENCE 2

struct bgp_attr_container;
union bgp_attr;
struct bgp_attr_container
{
    union bgp_attr *attr;
    struct bgp_attr_container *next;
};

struct bgp_attr_header
{
    uint8_t flags;
    uint8_t type;
};

struct bgp_attr_origin
{
    struct bgp_attr_header h;
    uint8_t origin;
};

struct bgp_as_path_segment;

struct bgp_as_path_segment
{
    uint8_t seg_type;
    uint8_t seg_len;
    struct bgp_as_path_segment *next;
    uint32_t as[0];
};

struct bgp_attr_as_path
{
    struct bgp_attr_header h;
    struct bgp_as_path_segment *seg;
    uint16_t bytes16;  /* binary size if coded with 16 bits */
    uint16_t bytes32;  /* binary size if coded with 32 bits */
};

struct bgp_attr_next_hop
{
    struct bgp_attr_header h;
    in_addr_t next_hop;
};

struct bgp_attr_multi_exit_disc
{
    struct bgp_attr_header h;
    uint32_t med;
};

struct bgp_attr_communities
{
    struct bgp_attr_header h;
    uint32_t communities[0];
};

struct bgp_attr_atomic_aggregate
{
    struct bgp_attr_header h;
};

struct bgp_attr_aggregator
{
    struct bgp_attr_header h;
	uint32_t as;
	in_addr_t speaker;
};

union bgp_attr
{
    struct bgp_attr_header header;
    struct bgp_attr_origin origin;
    struct bgp_attr_next_hop next_hop;
    struct bgp_attr_multi_exit_disc med;
    struct bgp_attr_communities communities;
    struct bgp_attr_atomic_aggregate atomic_aggregate;
};

struct bgp_attr_container*
parse_bgp_attrs(size_t len, void *attrs, int as_width);

void *
canonicalize_bgp_attrs(struct bgp_attr_container *attr, size_t *out_len);

#endif
