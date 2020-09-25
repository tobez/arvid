#include <stdlib.h>
#include <string.h>

#include <Judy.h>

#include "carp.h"
#include "peers.h"
#include "rib.h"
#include "prefixes.h"

struct arvid_peer **current_arvid_peers = NULL;
int current_arvid_peers_length = 0;
void *arvid_peer_container_hash = NULL;
struct arvid_peer_container *arvid_peer_container_list = NULL;

struct arvid_peer *
add_peer(struct arvid_peer *op)
{
    struct arvid_peer_container **peer_container_slot;
    struct arvid_peer_container *container;
    struct arvid_peer *peer;

    JHSI(peer_container_slot, arvid_peer_container_hash, op, sizeof(*op));
    if (peer_container_slot == PJERR)
        croak(16, "add_peer: JHSI failed");
    if (*peer_container_slot)
        return (*peer_container_slot)->peer;

    container = malloc(sizeof(*container));
    if (!container)
        croak(16, "add_peer: malloc(container)");

    peer = malloc(sizeof(*peer));
    if (!peer)
        croak(16, "add_peer: malloc(peer)");
    memset(peer, 0, sizeof(*peer));

    *peer = *op;
    container->peer = peer;
    container->next = arvid_peer_container_list;
    arvid_peer_container_list = container;
    if (container->next)
        container->id = container->next->id + 1;
    else
        container->id = 0;

    *peer_container_slot = container;

    peer->rib = rib_new(&peer->rib_stats);

    return peer;
}

void
peers_debug_print(void)
{
    struct arvid_peer_container *p = arvid_peer_container_list;
    fprintf(stderr, "Arvid peers\n");
    while (p) {
        fprintf(stderr, "{ \"id\":%u", p->id);
        fprintf(stderr, ", \"peer\":{\"peer_id\":\"%s\"", ip2a(p->peer->peer_ipv4));
        fprintf(stderr, ", \"bgp_id\":\"%s\"", ip2a(p->peer->bgp_id));
        fprintf(stderr, ", \"peer_asn\":%u", p->peer->peer_asn);
        fprintf(stderr, ", \"n_add_prefix\":%u", p->peer->n_add_prefix);
        fprintf(stderr, " }}\n");

        rib_debug_print(p->peer->rib);

        p = p->next;
    }
    fprintf(stderr, "\n");
}

