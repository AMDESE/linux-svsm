/* SPDX-License-Identifier: MIT */

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

static uint64_t seed;

void srand(unsigned s)
{
	seed = s - 1;
}

/* return 0 on success */
static inline int rdrand64(uint64_t *rnd)
{
    unsigned char ok;

    __asm__ volatile("rdrand %0; setc %1":"=r"(*rnd), "=qm"(ok));

    return (ok) ? 0 : -1;
}

int rand(void)
{
  uint64_t r = 0;

  if (rdrand64(&r)) {
    printf("%s, RDRAND failed\n", __func__);
  }

  return r;
}
