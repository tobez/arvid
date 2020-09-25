#ifndef _PEERS_H
#define _PEERS_H 1

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <Judy.h>

#include "rib.h"

struct arvid_peer
{
    in_addr_t peer_ipv4;
    in_addr_t bgp_id;
    uint32_t peer_asn;
    struct rib *rib;
    struct rib_stats rib_stats;
    unsigned n_add_prefix;
};

struct arvid_peer_container;

struct arvid_peer_container {
    struct arvid_peer *peer;
    uint32_t id;  /* for disk storage */
    struct arvid_peer_container *next;
};

/* getting peer by peer index while parsing a particular MRT */
extern struct arvid_peer **current_arvid_peers;
extern int current_arvid_peers_length;

/* all peers, hashed */
extern void *arvid_peer_container_hash;

/* all peers, linked */
extern struct arvid_peer_container *arvid_peer_container_list;

/* After add_peer() is called, use the returned struct for everything;
 * the passed struct can be freed */
struct arvid_peer *
add_peer(struct arvid_peer *peer);

/* XXX debug printing, saving, loading */

void
peers_debug_print(void);

#endif
