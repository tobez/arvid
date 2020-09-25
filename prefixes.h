#ifndef _PREFIXES_H
#define _PREFIXES_H 1

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "attrs.h"

#define ip2a(x) inet_ntoa(*((struct in_addr *)(&x)))

struct cidr
{
    in_addr_t ip;
    uint8_t bits;
};

struct prefix_info
{
    void *by_time;
};

#endif
