#ifndef _CARP_H
#define _CARP_H 1

const char *thisprogname(void);

void croak(int exit_code, const char *fmt, ...);
void croakx(int exit_code, const char *fmt, ...);

#endif
