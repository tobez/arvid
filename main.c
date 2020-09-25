#include <stdio.h>

#include "carp.h"
#include "mrt.h"
#include "peers.h"
#include "attrs.h"

int
main(int argc, char **argv)
{
    if (argc != 2)  croakx(1, "expect MRT file name");
    open_mrt(argv[1]);
    while (read_mrt_record()) ;
    peers_debug_print();
    fprintf(stderr, "{ \"arvid_attrs_count\": %d", arvid_attrs_count);
    fprintf(stderr, ", \"arvid_attrs_bytes\": %d }\n", arvid_attrs_bytes);
    fprintf(stderr, "Press <ENTER>\n");
    getchar();
    return 0;
}
