#define _GNU_SOURCE

#include <x86intrin.h>

// Definition of rdtsc() as in mozilla rr's src/record_signal.cc
// e.g. see that file as of rr git revision abd344288878c9b4046e0b8664927992947a46eb
// NOTE: static and  __inline__ annotations removed though
unsigned long long rdtsc(void) { return __rdtsc(); }


