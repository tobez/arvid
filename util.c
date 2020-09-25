#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "carp.h"
#include "util.h"

size_t
my_strlcat(char *dst, const char *src, size_t siz)
{
	char *d = dst;
	const char *s = src;
	size_t n = siz;
	size_t dlen;

	/* Find the end of dst and adjust bytes left but don't go past end */
	while (n-- != 0 && *d != '\0')
		d++;
	dlen = d - dst;
	n = siz - dlen;

	if (n == 0)
		return(dlen + strlen(s));
	while (*s != '\0') {
		if (n != 1) {
			*d++ = *s;
			n--;
		}
		s++;
	}
	*d = '\0';

	return(dlen + (s - src));       /* count does not include NUL */
}

char *
buf2hex(void *mem, int mem_len)
{
	unsigned char *s = mem;
	int i;
	char o[69];
	int pos[] = { 0,3,6,9,12,15,18,21,25,28,31,34,37,40,43,46 };
	char hex[] = "0123456789abcdef";
	size_t out_len = (mem_len + 15)/16*70;
	char *out = malloc(out_len);

	if (!out)
		croakx(21, "buf2hex: malloc(%zu)", out_len);

	out[0] = 0;
	while (mem_len) {
		memset(o, ' ', 67);
		o[67] = '\n';
		o[68] = 0;
		for (i = 0; i < 16 && mem_len > 0; i++, mem_len--, s++) {
			o[pos[i]] = hex[*s >> 4];
			o[pos[i]+1] = hex[*s & 0x0f];
			o[51+i] = isprint(*s) ? *s : '.';
		}
		my_strlcat(out, o, out_len);
	}

	return out;
}
